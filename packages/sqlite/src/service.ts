import * as fs from "node:fs";
import * as path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import type { KeyObject } from "node:crypto";
import {
  D,
  H,
  J,
  VLError,
  ZERO,
  buildBundle,
  computePath,
  genId,
  isId,
  normalize,
  reduce,
  verify as coreVerify,
  type Audit,
  type AuditData,
  type Bundle,
  type CommitResult,
  type ExternalHead,
  type ImportState,
  type Origin,
  type PathRequest,
  type Source,
  type StageRequest,
  type StageResult,
  signMessage,
  signPayload,
  spanOf,
  type Step,
  type StepBody,
  type Trace,
  type TrustPackage,
  type Verification,
} from "@latticeag/vislineage-core";
import { schema as sch } from "@latticeag/vislineage-core";
import { randomBytes } from "node:crypto";
import {
  acquireWriterLock,
  auditHead,
  checkMeta,
  initDb,
  openDb,
  reconcilePin,
  setMeta,
  storagePressure,
  withTx,
  writeArtifactFile,
} from "./store.js";

export type Role = "read" | "write" | "admin";
export interface Credential {
  roles: Set<Role>;
  workspace: string;
}

export interface ServiceLimits {
  stage_rows: number;
  request_bytes: number;
  path_nodes: number;
  bundle_bytes: number;
}
export interface ServiceRetention {
  stage_ttl_seconds: number;
  history_revisions: number;
  artifacts_days: number;
}

export interface ServiceOptions {
  dbPath: string;
  stateDir: string;
  artifactsDir: string;
  workspace: string;
  auditKeyId: string;
  auditKey: KeyObject | null; // null → no mutations possible (verify/read-only use)
  limits: ServiceLimits;
  retention: ServiceRetention;
  recoveryPinPath: string | null;
  now?: () => number; // seconds; defaults to Date.now()/1000
  log?: (level: string, event: string, request: string | null, code: string | null, durationMs: number) => void;
  /** Test-only crash injection at named commit boundaries. */
  fault?: (point: "afterSign" | "afterCommit") => void;
}

export type ServiceState = "RECOVERING" | "READY" | "READ_ONLY" | "DRAINING" | "STOPPED";

export interface RpcSuccess<T = unknown> {
  id: string;
  ok: true;
  result: T;
}
export interface RpcFailureObj {
  id: string | null;
  ok: false;
  error: { code: string; retryable: boolean; details: { field: string | null } };
}

const METHODS = new Set([
  "source.register",
  "source.list",
  "trace.create",
  "trace.get",
  "import.stage",
  "import.get",
  "import.commit",
  "import.cancel",
  "path.get",
  "bundle.export",
  "bundle.verify",
]);

const ROLE_REQUIRED: Record<string, Role> = {
  "source.register": "admin",
  "source.list": "read",
  "trace.create": "admin",
  "trace.get": "read",
  "import.stage": "write",
  "import.get": "read",
  "import.commit": "write",
  "import.cancel": "write",
  "path.get": "read",
  "bundle.export": "read",
  "bundle.verify": "read",
};

const MUTATING = new Set([
  "source.register",
  "trace.create",
  "import.stage",
  "import.commit",
  "import.cancel",
]);

const GENERIC_CAP = 64 * 1024 * 1024; // 64 MiB serialized-response cap

/** Closed params object: unknown members are SCHEMA_INVALID. */
function onlyKeys(params: Record<string, unknown>, allowed: string[]): void {
  for (const k of Object.keys(params)) {
    if (!allowed.includes(k)) throw new VLError("SCHEMA_INVALID", `/params/${k}`, "unknown member");
  }
}

function hasRole(cred: Credential, role: Role): boolean {
  if (cred.roles.has("admin")) return true;
  if (role === "admin") return false;
  return cred.roles.has(role);
}

interface ImportRow {
  id: string;
  trace: string;
  state: "STAGED" | "COMMITTED" | "CANCELLED";
  batch: string;
  staged: Buffer | null;
  stage_result: Buffer;
  expires_at: number | bigint;
  result: Buffer | null;
}

export class WorkspaceService {
  readonly db: DatabaseSync;
  readonly opts: ServiceOptions;
  state: ServiceState = "RECOVERING";
  readOnlyReason: string | null = null;
  private releaseLock: () => void;
  private now(): number {
    return this.opts.now ? this.opts.now() : Date.now() / 1000;
  }
  private emit(level: string, event: string, request: string | null, code: string | null, durationMs: number): void {
    this.opts.log?.(level, event, request, code, durationMs);
  }

  constructor(opts: ServiceOptions) {
    this.opts = opts;
    this.releaseLock = acquireWriterLock(opts.stateDir);
    try {
      this.db = openDb(opts.dbPath, opts.workspace);
      checkMeta(this.db, opts.workspace);
      fs.mkdirSync(opts.artifactsDir, { recursive: true, mode: 0o700 });
      try {
        fs.chmodSync(opts.artifactsDir, 0o700);
      } catch {
        /* best effort */
      }
      const rec = opts.recoveryPinPath
        ? reconcilePin(this.db, opts.recoveryPinPath)
        : { state: "READY" as const, reason: null };
      if (storagePressure(opts.stateDir) >= 0.95) {
        this.state = "READ_ONLY";
        this.readOnlyReason = "STORAGE_FULL";
      } else {
        this.state = rec.state;
        this.readOnlyReason = rec.reason;
      }
      this.emit("info", "service_state", null, this.state, 0);
    } catch (e) {
      this.releaseLock();
      throw e;
    }
  }

  static create(opts: ServiceOptions & { configHash: string; requestId: string }): WorkspaceService {
    const db = initDb(opts.dbPath, opts.workspace);
    db.close();
    const svc = new WorkspaceService({ ...opts, recoveryPinPath: null });
    // genesis audit entry — before reconcile, so create it directly
    svc.appendAudit(
      { kind: "WorkspaceCreated", config: opts.configHash },
      opts.requestId,
    );
    return svc;
  }

  close(): void {
    try {
      this.db.close();
    } finally {
      this.releaseLock();
      this.state = "STOPPED";
    }
  }

  /** Lazily expire staged imports (service clock only for storage cleanup). */
  private sweepExpiredStages(): void {
    if (this.state !== "READY") return;
    const now = this.now();
    const rows = this.db
      .prepare("SELECT id FROM imports WHERE state='STAGED' AND expires_at < ?")
      .all(now) as { id: string }[];
    if (!rows.length) return;
    withTx(this.db, () => {
      for (const r of rows) {
        this.db
          .prepare("UPDATE imports SET state='CANCELLED', staged=NULL, result=? WHERE id=? AND state='STAGED'")
          .run(Buffer.from(J({ import: r.id, state: "CANCELLED" })), r.id);
        this.appendAudit({ kind: "ImportCancelled", import: r.id, reason: "EXPIRED" }, genId("request"));
      }
    });
  }

  /** Public so offline maintenance (prune/rotate) can append under the writer lock. */
  appendAuditInternal(data: AuditData, requestId: string): Audit {
    return this.appendAudit(data, requestId);
  }

  private appendAudit(data: AuditData, requestId: string): Audit {
    const head = auditHead(this.db);
    const seq = head ? head.seq + 1n : 1n;
    const prev = head ? head.hash : ZERO;
    const body = {
      v: 1 as const,
      workspace: this.opts.workspace,
      seq: String(seq),
      prev,
      request: requestId,
      key: this.opts.auditKeyId,
      data,
    };
    const hash = D("VL-AUDIT/1", body);
    if (!this.opts.auditKey) throw new VLError("READ_ONLY", null, "no audit key configured");
    const signature = signPayloadAudit(this.opts.auditKey, hash);
    const env: Audit = { body, hash, signature };
    this.db.prepare("INSERT INTO audit(seq,hash,envelope) VALUES(?,?,?)").run(Number(seq), hash, J(env));
    return env;
  }

  /**
   * dispatch(request, cred) — full §9.1 processing order.
   * cred === null → unauthenticated. Returns logical success/failure object.
   */
  dispatch(request: unknown, cred: Credential | null): RpcSuccess | RpcFailureObj {
    const started = Date.now();
    const done = <R extends RpcSuccess | RpcFailureObj>(r: R, code: string | null): R => {
      this.emit(
        r.ok ? "info" : "error",
        r.ok ? "rpc_completed" : "rpc_failed",
        r.id,
        code,
        Date.now() - started,
      );
      return r;
    };
    const fail = (e: VLError | { code: string; field?: string | null }, idEcho: string | null): RpcFailureObj => {
      const vl = e instanceof VLError ? e : new VLError(e.code, e.field ?? null);
      return done(
        { id: idEcho, ok: false, error: { code: vl.code, retryable: vl.retryable, details: vl.details } },
        vl.code,
      );
    };

    // 1. envelope shape
    const idEcho =
      typeof (request as { id?: unknown })?.id === "string" && isId("request", (request as { id: string }).id)
        ? (request as { id: string }).id
        : null;
    if (
      typeof request !== "object" ||
      request === null ||
      Array.isArray(request) ||
      !isId("request", (request as Record<string, unknown>).id) ||
      typeof (request as Record<string, unknown>).method !== "string" ||
      typeof (request as Record<string, unknown>).params !== "object" ||
      (request as Record<string, unknown>).params === null ||
      Array.isArray((request as Record<string, unknown>).params)
    ) {
      return fail(new VLError("JSON_INVALID", null, "bad RPC envelope"), idEcho);
    }
    const req = request as { id: string; method: string; params: Record<string, unknown> };

    // 2. authentication
    if (cred === null) return fail(new VLError("UNAUTHENTICATED"), req.id);
    if (cred.workspace !== this.opts.workspace) return fail(new VLError("FORBIDDEN"), req.id);

    // 3. method resolution
    if (!METHODS.has(req.method)) {
      return fail(new VLError("METHOD_UNKNOWN", "/method"), req.id);
    }

    // 4. role authorization (before resource lookup)
    const need = ROLE_REQUIRED[req.method]!;
    if (!hasRole(cred, need)) return fail(new VLError("FORBIDDEN"), req.id);

    // 5. service-state admission
    if (this.state === "RECOVERING" || this.state === "DRAINING") {
      return fail(new VLError("BUSY"), req.id);
    }
    if (this.state === "READ_ONLY" && MUTATING.has(req.method)) {
      return fail(new VLError("READ_ONLY"), req.id);
    }

    // retention sweep (only when writable)
    this.sweepExpiredStages();

    try {
      const result = this.runMethod(req, cred);
      const payload = J({ id: req.id, ok: true, result });
      if (payload.length > GENERIC_CAP) return fail(new VLError("BUNDLE_LIMIT"), req.id);
      return done({ id: req.id, ok: true, result }, null);
    } catch (e) {
      if (e instanceof VLError) return fail(e, req.id);
      throw e;
    }
  }

  /** Idempotency: returns stored response or runs the mutation. */
  private idempotent<T>(
    req: { id: string; method?: string; params: unknown },
    exec: () => { result: T; auditSeq: number },
  ): T {
    const requestHash = D("VL-REQUEST/1", { method: req.method, params: req.params });
    const prior = this.db.prepare("SELECT request_hash, response FROM idempotency WHERE id=?").get(req.id) as
      | { request_hash: string; response: Buffer }
      | undefined;
    if (prior) {
      if (prior.request_hash !== requestHash) throw new VLError("IDEMPOTENCY_CONFLICT");
      return JSON.parse(Buffer.from(prior.response).toString("utf8")) as T;
    }
    const { result, auditSeq } = exec();
    this.db
      .prepare("INSERT INTO idempotency(id,request_hash,response,audit_seq) VALUES(?,?,?,?)")
      .run(req.id, requestHash, J(result), auditSeq);
    return result;
  }

  private runMethod(req: { id: string; method: string; params: Record<string, unknown> }, cred: Credential): unknown {
    switch (req.method) {
      case "source.register":
        return this.mSourceRegister(req);
      case "source.list":
        return this.mSourceList(req);
      case "trace.create":
        return this.mTraceCreate(req);
      case "trace.get":
        return this.mTraceGet(req);
      case "import.stage":
        return this.mImportStage(req);
      case "import.get":
        return this.mImportGet(req);
      case "import.commit":
        return this.mImportCommit(req);
      case "import.cancel":
        return this.mImportCancel(req);
      case "path.get":
        return this.mPathGet(req);
      case "bundle.export":
        return this.mBundleExport(req);
      case "bundle.verify":
        return this.mBundleVerify(req);
      default:
        throw new VLError("METHOD_UNKNOWN", "/method");
    }
    void cred;
  }

  // ---------- sources -------------------------------------------------------

  private sourceById(id: string): Source | null {
    const row = this.db.prepare("SELECT body FROM sources WHERE id=?").get(id) as { body: Buffer } | undefined;
    return row ? (JSON.parse(Buffer.from(row.body).toString("utf8")) as Source) : null;
  }

  /** audit seq of the SourceRegistered entry for a source (immutable history). */
  private sourceAuditSeq(id: string): number {
    const rows = this.db.prepare("SELECT seq,envelope FROM audit ORDER BY seq").all() as {
      seq: number | bigint;
      envelope: Buffer;
    }[];
    for (const r of rows) {
      const a = JSON.parse(Buffer.from(r.envelope).toString("utf8")) as Audit;
      if (a.body.data.kind === "SourceRegistered" && a.body.data.source.id === id) return Number(r.seq);
    }
    throw new VLError("STORAGE_UNAVAILABLE", null, "missing source audit entry");
  }

  private mSourceRegister(req: { id: string; params: Record<string, unknown> }): Source {
    const s = sch.source(req.params, "/params");
    return withTx(this.db, () =>
      this.idempotent(req, () => {
        const existing = this.sourceById(s.id);
        if (existing) {
          if (Buffer.compare(J(existing), J(s)) === 0) {
            return { result: existing, auditSeq: this.sourceAuditSeq(s.id) };
          }
          throw new VLError("SOURCE_CONFLICT", null, "source id already registered differently");
        }
        const count = (this.db.prepare("SELECT COUNT(*) c FROM sources").get() as { c: number }).c;
        if (count >= 256) throw new VLError("TRACE_LIMIT", null, "source cap");
        this.db.prepare("INSERT INTO sources(id,body) VALUES(?,?)").run(s.id, J(s));
        const a = this.appendAudit({ kind: "SourceRegistered", source: s }, req.id);
        const seq = Number(BigInt(a.body.seq));
        return { result: s, auditSeq: seq };
      }),
    );
  }

  private mSourceList(req: { params: Record<string, unknown> }): { sources: Source[] } {
    onlyKeys(req.params, []);
    const rows = this.db.prepare("SELECT body FROM sources ORDER BY id").all() as { body: Buffer }[];
    return { sources: rows.map((r) => JSON.parse(Buffer.from(r.body).toString("utf8")) as Source) };
  }

  // ---------- traces --------------------------------------------------------

  private emptyGraphHash(trace: string): string {
    return D("VL-GRAPH/1", {
      v: 1,
      workspace: this.opts.workspace,
      trace,
      steps: [],
      origins: [],
      edges: [],
      gaps: [],
    });
  }

  private traceById(id: string): Trace | null {
    const row = this.db.prepare("SELECT id,revision,graph FROM traces WHERE id=?").get(id) as
      | { id: string; revision: number | bigint; graph: string }
      | undefined;
    return row ? { id: row.id, revision: String(row.revision), graph: row.graph } : null;
  }

  private traceAuditSeq(id: string): number {
    const rows = this.db.prepare("SELECT seq,envelope FROM audit ORDER BY seq").all() as {
      seq: number | bigint;
      envelope: Buffer;
    }[];
    for (const r of rows) {
      const a = JSON.parse(Buffer.from(r.envelope).toString("utf8")) as Audit;
      if (a.body.data.kind === "TraceCreated" && a.body.data.trace === id) return Number(r.seq);
    }
    throw new VLError("STORAGE_UNAVAILABLE", null, "missing trace audit entry");
  }

  private mTraceCreate(req: { id: string; params: Record<string, unknown> }): Trace {
    if (typeof req.params !== "object" || req.params === null) throw new VLError("SCHEMA_INVALID", "/params");
    sch.typedId(req.params.trace, "trace", "/params/trace");
    const extra = Object.keys(req.params).filter((k) => k !== "trace");
    if (extra.length) throw new VLError("SCHEMA_INVALID", `/params/${extra[0]}`, "unknown member");
    const id = req.params.trace as string;
    return withTx(this.db, () =>
      this.idempotent(req, () => {
        const existing = this.traceById(id);
        if (existing) {
          return {
            result: { id, revision: "0", graph: this.emptyGraphHash(id) } satisfies Trace,
            auditSeq: this.traceAuditSeq(id),
          };
        }
        const g0 = this.emptyGraphHash(id);
        this.db.prepare("INSERT INTO traces(id,revision,graph) VALUES(?,0,?)").run(id, g0);
        const a = this.appendAudit({ kind: "TraceCreated", trace: id, graph: g0 }, req.id);
        const seq = Number(BigInt(a.body.seq));
        this.db
          .prepare("INSERT INTO revisions(trace,revision,graph,manifest,audit_seq,pruned) VALUES(?,0,?,?,?,0)")
          .run(id, g0, J({ v: 1, workspace: this.opts.workspace, trace: id, steps: [], origins: [], edges: [], gaps: [] }), seq);
        return { result: { id, revision: "0", graph: g0 } satisfies Trace, auditSeq: seq };
      }),
    );
  }

  private mTraceGet(req: { params: Record<string, unknown> }): Trace {
    onlyKeys(req.params, ["trace"]);
    sch.typedId(req.params.trace, "trace", "/params/trace");
    const t = this.traceById(req.params.trace as string);
    if (!t) throw new VLError("NOT_FOUND");
    return t;
  }

  // ---------- imports -------------------------------------------------------

  private importById(id: string): ImportRow | null {
    const row = this.db.prepare("SELECT * FROM imports WHERE id=?").get(id) as ImportRow | undefined;
    return row ?? null;
  }

  private mImportStage(req: { id: string; params: Record<string, unknown> }): StageResult {
    const p = req.params;
    onlyKeys(p, ["import", "trace", "source", "rows", "origins", "artifacts"]);
    sch.typedId(p.import, "import", "/params/import");
    sch.typedId(p.trace, "trace", "/params/trace");
    sch.typedId(p.source, "source", "/params/source");
    if (!Array.isArray(p.rows)) throw new VLError("SCHEMA_INVALID", "/params/rows");
    if (p.rows.length === 0) throw new VLError("SCHEMA_INVALID", "/params/rows", "empty stage");
    if (p.rows.length > this.opts.limits.stage_rows) throw new VLError("ROW_LIMIT", "/params/rows");
    if (!Array.isArray(p.origins)) throw new VLError("SCHEMA_INVALID", "/params/origins");
    if (p.origins.length > 4096) throw new VLError("ROW_LIMIT", "/params/origins");
    if (!Array.isArray(p.artifacts)) throw new VLError("SCHEMA_INVALID", "/params/artifacts");
    if (p.artifacts.length > 64) throw new VLError("ROW_LIMIT", "/params/artifacts");
    for (const [i, r] of p.rows.entries()) {
      const span = rawSpan(r);
      if (span !== undefined && span > 1024 * 1024) throw new VLError("ROW_LIMIT", `/params/rows/${i}`);
      if (span === undefined && J(r).length > 1024 * 1024) throw new VLError("ROW_LIMIT", `/params/rows/${i}`);
    }
    const origins = p.origins.map((o, i) => sch.origin(o, `/params/origins/${i}`));
    const artifacts = p.artifacts.map((a, i) => sch.artifact(a, `/params/artifacts/${i}`));
    for (const [i, a] of artifacts.entries()) {
      const raw = sch.artifactBytes(a, `/params/artifacts/${i}`);
      if (raw.length > 1024 * 1024) throw new VLError("ROW_LIMIT", `/params/artifacts/${i}`);
      if (H(raw) !== a.digest) throw new VLError("HASH_MISMATCH", `/params/artifacts/${i}/digest`);
    }

    const source = this.sourceById(p.source as string);
    if (!source) throw new VLError("NOT_FOUND");
    const trace = this.traceById(p.trace as string);
    if (!trace) throw new VLError("NOT_FOUND");

    if (storagePressure(this.opts.stateDir) >= 0.9) {
      throw new VLError("STORAGE_UNAVAILABLE", null, "storage pressure");
    }

    // normalize all rows (atomic)
    const ctx = { workspace: this.opts.workspace, trace: p.trace as string, source };
    const steps: Step[] = [];
    const warnings = new Set<string>();
    let sawDup = false;
    const seenHashes = new Set<string>();
    const nativeTraces = new Set<string>();
    for (const [i, r] of p.rows.entries()) {
      const { step, warnings: w } = normalize(source.profile, r, ctx, `/params/rows/${i}`);
      for (const x of w) warnings.add(x);
      nativeTraces.add(step.body.native_trace);
      if (seenHashes.has(step.hash)) {
        sawDup = true;
        continue;
      }
      seenHashes.add(step.hash);
      steps.push(step);
    }
    if (nativeTraces.size > 1) {
      throw new VLError("SCHEMA_INVALID", "/params/rows", "multiple native traces in one stage");
    }
    if (sawDup) warnings.add("DUPLICATE_ROW");

    // origin body-hash integrity + reference rule
    const stepSet = new Set(steps.map((s) => s.hash));
    const storedTraceSteps = new Set(
      (this.db.prepare("SELECT hash FROM steps WHERE trace=?").all(p.trace as string) as { hash: string }[]).map(
        (r) => r.hash,
      ),
    );
    const storedOrigins = this.db
      .prepare("SELECT source,stream,seq,step FROM origins")
      .all() as { source: string; stream: string; seq: number | bigint; step: string }[];
    const attesting = (o: Origin): boolean => stepSet.has(o.body.step) || storedTraceSteps.has(o.body.step);
    const originOk = (o: Origin): boolean => {
      if (attesting(o)) return true;
      // predecessor: some attesting origin in same stream with seq >= o.seq
      const seq = BigInt(o.body.seq);
      for (const cand of origins) {
        if (
          cand.body.source === o.body.source &&
          cand.body.stream === o.body.stream &&
          attesting(cand) &&
          BigInt(cand.body.seq) >= seq
        )
          return true;
      }
      for (const cand of storedOrigins) {
        if (
          cand.source === o.body.source &&
          cand.stream === o.body.stream &&
          storedTraceSteps.has(cand.step) &&
          BigInt(cand.seq) >= seq
        )
          return true;
      }
      return false;
    };
    for (const [i, o] of origins.entries()) {
      if (o.body.workspace !== this.opts.workspace) {
        throw new VLError("SCHEMA_INVALID", `/params/origins/${i}/body/workspace`);
      }
      if (!this.sourceById(o.body.source)) throw new VLError("NOT_FOUND");
      if (o.hash !== D("VL-ORIGIN/1", o.body)) {
        throw new VLError("HASH_MISMATCH", `/params/origins/${i}/hash`);
      }
      if (!originOk(o)) throw new VLError("ORIGIN_UNREFERENCED", `/params/origins/${i}`);
    }

    // artifact reference rule
    const refByDigest = new Map<string, { format: string; bytes: string }>();
    const collectRefs = (attachments: { digest: string; format: string; bytes: string }[]) => {
      for (const r of attachments) refByDigest.set(r.digest, r);
    };
    for (const s of steps) collectRefs(s.body.attachments);
    for (const h of storedTraceSteps) {
      const row = this.db.prepare("SELECT body FROM steps WHERE hash=?").get(h) as { body: Buffer };
      collectRefs((JSON.parse(Buffer.from(row.body).toString("utf8")) as StepBody).attachments);
    }
    for (const [i, a] of artifacts.entries()) {
      const ref = refByDigest.get(a.digest);
      if (!ref) throw new VLError("ARTIFACT_UNREFERENCED", `/params/artifacts/${i}`);
      const raw = sch.artifactBytes(a, `/params/artifacts/${i}`);
      if (H(raw) !== a.digest || BigInt(ref.bytes) !== BigInt(raw.length) || ref.format !== a.format) {
        throw new VLError("HASH_MISMATCH", `/params/artifacts/${i}`);
      }
      const existing = this.db.prepare("SELECT format FROM artifacts WHERE digest=?").get(a.digest) as
        | { format: string }
        | undefined;
      if (existing && existing.format !== a.format) {
        throw new VLError("ARTIFACT_FORMAT_CONFLICT", `/params/artifacts/${i}`);
      }
    }

    const sortEnv = <T>(xs: T[]): T[] => [...xs].sort((a, b) => Buffer.compare(J(a), J(b)));
    const batch = D("VL-BATCH/1", {
      trace: p.trace,
      source: p.source,
      steps: sortEnv(steps),
      origins: sortEnv(origins),
      artifacts: sortEnv(artifacts),
    });

    const stagedPayload = { source: p.source, steps, origins, artifacts };
    const stageResult: StageResult = {
      import: p.import as string,
      state: "STAGED",
      batch,
      rows: steps.length,
      warnings: [...warnings].sort(),
    };

    return withTx(this.db, () =>
      this.idempotent(req, () => {
        // import-id reuse: identical batch returns the stored stage result
        const existingImport = this.importById(p.import as string);
        if (existingImport) {
          if (existingImport.batch === batch) {
            return {
              result: JSON.parse(Buffer.from(existingImport.stage_result).toString("utf8")) as StageResult,
              auditSeq: this.auditSeqForKind("ImportStaged", p.import as string),
            };
          }
          throw new VLError("IMPORT_CONFLICT", null, "import id reused with different batch");
        }
        const expires = Math.floor(this.now()) + this.opts.retention.stage_ttl_seconds;
        this.db
          .prepare(
            "INSERT INTO imports(id,trace,state,batch,staged,stage_result,expires_at,result) VALUES(?,?,?,?,?,?,?,NULL)",
          )
          .run(
            p.import as string,
            p.trace as string,
            "STAGED",
            batch,
            J(stagedPayload),
            J(stageResult),
            expires,
          );
        const a = this.appendAudit(
          { kind: "ImportStaged", import: p.import as string, trace: p.trace as string, batch, rows: steps.length },
          req.id,
        );
        return { result: stageResult, auditSeq: Number(BigInt(a.body.seq)) };
      }),
    );
  }

  private mImportGet(req: { params: Record<string, unknown> }): ImportState {
    onlyKeys(req.params, ["import"]);
    sch.typedId(req.params.import, "import", "/params/import");
    const im = this.importById(req.params.import as string);
    if (!im) throw new VLError("NOT_FOUND");
    const base = { import: im.id, state: im.state, batch: im.batch };
    if (im.state === "COMMITTED" && im.result) {
      return { ...base, commit: JSON.parse(Buffer.from(im.result).toString("utf8")) as CommitResult, reason: null };
    }
    if (im.state === "CANCELLED") {
      const reason = im.result
        ? ((JSON.parse(Buffer.from(im.result).toString("utf8")) as { reason?: "USER" | "EXPIRED" }).reason ?? "USER")
        : "USER";
      return { ...base, commit: null, reason };
    }
    return { ...base, commit: null, reason: null };
  }

  private mImportCommit(req: { id: string; params: Record<string, unknown> }): CommitResult {
    onlyKeys(req.params, ["import", "expected_revision"]);
    sch.typedId(req.params.import, "import", "/params/import");
    sch.counter(req.params.expected_revision, "/params/expected_revision");
    const importId = req.params.import as string;
    const expected = BigInt(req.params.expected_revision as string);

    type Outcome = { kind: "ok"; result: CommitResult } | { kind: "expired" };
    const outcome = withTx(this.db, (): Outcome => {
      const im = this.importById(importId);
      if (!im) throw new VLError("NOT_FOUND");
      if (im.state === "CANCELLED") throw new VLError("IMPORT_STATE");
      // STAGED past TTL → cancel inside this transaction; call fails IMPORT_STATE
      if (im.state === "STAGED" && BigInt(im.expires_at) < BigInt(Math.floor(this.now()))) {
        this.db
          .prepare("UPDATE imports SET state='CANCELLED', staged=NULL, result=? WHERE id=?")
          .run(J({ import: importId, state: "CANCELLED", reason: "EXPIRED" }), importId);
        this.appendAudit({ kind: "ImportCancelled", import: importId, reason: "EXPIRED" }, req.id);
        return { kind: "expired" };
      }
      return { kind: "ok", result: this.idempotent(req, () => this.execCommit(req, im as ImportRow, expected)) };
    });
    if (outcome.kind === "expired") throw new VLError("IMPORT_STATE", null, "stage expired");
    this.opts.fault?.("afterCommit");
    return outcome.result;
  }

  private execCommit(
    req: { id: string },
    im: ImportRow,
    expected: bigint,
  ): { result: CommitResult; auditSeq: number } {
    const importId = im.id;
    if (im.state === "COMMITTED") {
      const stored = JSON.parse(Buffer.from(im.result!).toString("utf8")) as CommitResult;
      return { result: stored, auditSeq: this.auditSeqForCommit(importId) };
    }
    const t = this.traceById(im.trace)!;
    if (BigInt(t.revision) !== expected) throw new VLError("REVISION_CONFLICT");

    const staged = JSON.parse(Buffer.from(im.staged!).toString("utf8")) as {
      source: string;
      steps: Step[];
      origins: Origin[];
      artifacts: { digest: string; format: string; bytes: string; content: string }[];
    };

    // native-trace + record bindings (all-or-nothing before mutation)
    const bind = this.db.prepare("SELECT trace FROM native_traces WHERE source=? AND native=?");
    const insBind = this.db.prepare("INSERT INTO native_traces(source,native,trace) VALUES(?,?,?)");
    const recordBind = this.db.prepare("SELECT DISTINCT trace FROM steps WHERE source=? AND record=?");
    for (const s of staged.steps) {
      const b = bind.get(s.body.source, s.body.native_trace) as { trace: string } | undefined;
      if (b && b.trace !== im.trace) throw new VLError("TRACE_MISMATCH");
      for (const r of recordBind.all(s.body.source, s.body.record) as { trace: string }[]) {
        if (r.trace !== im.trace) throw new VLError("TRACE_MISMATCH");
      }
    }

    // insert steps
    const insStep = this.db.prepare(
      "INSERT INTO steps(hash,source,record,trace,native_trace,native_span,body) VALUES(?,?,?,?,?,?,?)",
    );
    let added = 0;
    let duplicates = 0;
    let conflicts = 0;
    for (const s of staged.steps) {
      const have = this.db.prepare("SELECT hash FROM steps WHERE hash=?").get(s.hash);
      if (have) {
        duplicates++;
        continue;
      }
      const prior = this.db
        .prepare("SELECT COUNT(*) c FROM steps WHERE source=? AND record=?")
        .get(s.body.source, s.body.record) as { c: number };
      insStep.run(s.hash, s.body.source, s.body.record, s.body.trace, s.body.native_trace, s.body.native_span, J(s.body));
      added++;
      if (prior.c > 0) conflicts++;
    }
    // binding rows for every staged native trace (even if all steps were duplicates)
    for (const s of staged.steps) {
      const b = bind.get(s.body.source, s.body.native_trace) as { trace: string } | undefined;
      if (!b) insBind.run(s.body.source, s.body.native_trace, im.trace);
    }

    // insert origins (dedupe by envelope digest)
    const insOrigin = this.db.prepare(
      "INSERT INTO origins(digest,hash,source,stream,seq,step,envelope) VALUES(?,?,?,?,?,?,?)",
    );
    for (const o of staged.origins) {
      const digest = H(J(o));
      const have = this.db.prepare("SELECT digest FROM origins WHERE digest=?").get(digest);
      if (!have) insOrigin.run(digest, o.hash, o.body.source, o.body.stream, Number(BigInt(o.body.seq)), o.body.step, J(o));
    }

    // artifacts: write bytes then reference
    const insArt = this.db.prepare(
      "INSERT INTO artifacts(digest,format,bytes,state,relative_path,created_at) VALUES(?,?,?,?,?,?)",
    );
    for (const a of staged.artifacts) {
      const have = this.db.prepare("SELECT digest FROM artifacts WHERE digest=?").get(a.digest);
      if (have) continue;
      const raw = sch.artifactBytes(a, "/staged/artifacts");
      const rel = writeArtifactFile(this.opts.artifactsDir, a.digest, raw);
      insArt.run(a.digest, a.format, raw.length, "AVAILABLE", rel, Math.floor(this.now()));
    }

    // revision content: all steps bound to the trace (steps.body stores the
    // canonical StepBody; the envelope hash is the row key)
    const allSteps = (this.db.prepare("SELECT hash,body FROM steps WHERE trace=?").all(im.trace) as {
      hash: string;
      body: Buffer;
    }[]).map((r) => ({ body: JSON.parse(Buffer.from(r.body).toString("utf8")) as StepBody, hash: r.hash }));
    const stepSet = new Set(allSteps.map((s) => s.hash));
    // pinned origin set: every stored origin capped by an attesting origin in
    // the same stream whose step belongs to the new revision's step set
    const allOrigins = (this.db.prepare("SELECT envelope FROM origins").all() as { envelope: Buffer }[]).map(
      (r) => JSON.parse(Buffer.from(r.envelope).toString("utf8")) as Origin,
    );
    const pinned = allOrigins.filter((o) =>
      allOrigins.some(
        (p) =>
          p.body.source === o.body.source &&
          p.body.stream === o.body.stream &&
          stepSet.has(p.body.step) &&
          BigInt(p.body.seq) >= BigInt(o.body.seq),
      ),
    );

    const red = reduce(allSteps, pinned, this.opts.workspace, im.trace);
    const graph = D("VL-GRAPH/1", red.manifest);
    const newRev = BigInt(t.revision) + 1n;
    const auditEnv = this.appendAudit(
      {
        kind: "ImportCommitted",
        import: importId,
        trace: im.trace,
        revision: String(newRev),
        graph,
        batch: im.batch,
      },
      req.id,
    );
    const auditSeq = Number(BigInt(auditEnv.body.seq));
    this.opts.fault?.("afterSign");
    this.db
      .prepare("INSERT INTO revisions(trace,revision,graph,manifest,audit_seq,pruned) VALUES(?,?,?,?,?,0)")
      .run(im.trace, Number(newRev), graph, J(red.manifest), auditSeq);
    const insRS = this.db.prepare("INSERT INTO revision_steps(trace,revision,hash) VALUES(?,?,?)");
    for (const s of allSteps) insRS.run(im.trace, Number(newRev), s.hash);
    const insRO = this.db.prepare("INSERT INTO revision_origins(trace,revision,digest) VALUES(?,?,?)");
    for (const o of pinned) insRO.run(im.trace, Number(newRev), H(J(o)));
    const insE = this.db.prepare(
      "INSERT INTO edges(trace,revision,hash,parent,child,body) VALUES(?,?,?,?,?,?)",
    );
    for (const e of red.edges) insE.run(im.trace, Number(newRev), e.hash, e.body.parent, e.body.child, J(e));
    this.db.prepare("UPDATE traces SET revision=?, graph=? WHERE id=?").run(Number(newRev), graph, im.trace);

    const result: CommitResult = {
      import: importId,
      state: "COMMITTED",
      trace: im.trace,
      revision: String(newRev),
      graph,
      added,
      duplicates,
      conflicts,
      audit: auditEnv.hash,
    };
    this.db
      .prepare("UPDATE imports SET state='COMMITTED', staged=NULL, result=? WHERE id=?")
      .run(J(result), importId);
    return { result, auditSeq };
  }

  /** audit seq of the (first) entry of `kind` naming `id` — for idempotent replay rows. */
  private auditSeqForKind(kind: AuditData["kind"], id: string): number {
    const rows = this.db.prepare("SELECT seq,envelope FROM audit ORDER BY seq").all() as {
      seq: number | bigint;
      envelope: Buffer;
    }[];
    for (const r of rows) {
      const a = JSON.parse(Buffer.from(r.envelope).toString("utf8")) as Audit;
      const d = a.body.data;
      const named =
        ("import" in d && d.import === id) ||
        ("source" in d && d.source.id === id) ||
        ("trace" in d && d.trace === id);
      if (d.kind === kind && named) return Number(r.seq);
    }
    throw new VLError("STORAGE_UNAVAILABLE");
  }

  private auditSeqForCommit(importId: string): number {
    return this.auditSeqForKind("ImportCommitted", importId);
  }

  private mImportCancel(req: { id: string; params: Record<string, unknown> }): { import: string; state: "CANCELLED" } {
    onlyKeys(req.params, ["import"]);
    sch.typedId(req.params.import, "import", "/params/import");
    const importId = req.params.import as string;
    return withTx(this.db, () =>
      this.idempotent(req, () => {
        const im = this.importById(importId);
        if (!im) throw new VLError("NOT_FOUND");
        if (im.state === "CANCELLED") {
          const stored = im.result ? (JSON.parse(Buffer.from(im.result).toString("utf8")) as { import: string; state: "CANCELLED" }) : { import: importId, state: "CANCELLED" as const };
          return { result: { import: stored.import, state: "CANCELLED" as const }, auditSeq: this.auditSeqForKind("ImportCancelled", importId) };
        }
        if (im.state === "COMMITTED") throw new VLError("IMPORT_STATE");
        const a = this.appendAudit({ kind: "ImportCancelled", import: importId, reason: "USER" }, req.id);
        this.db
          .prepare("UPDATE imports SET state='CANCELLED', staged=NULL, result=? WHERE id=?")
          .run(J({ import: importId, state: "CANCELLED", reason: "USER" }), importId);
        return { result: { import: importId, state: "CANCELLED" as const }, auditSeq: Number(BigInt(a.body.seq)) };
      }),
    );
  }

  // ---------- path / bundle -------------------------------------------------

  private revisionProjection(trace: string, revision: bigint): {
    graph: string;
    manifest: import("@latticeag/vislineage-core").GraphManifest;
    steps: Step[];
    origins: Origin[];
    edges: import("@latticeag/vislineage-core").Edge[];
  } {
    const rev = this.db
      .prepare("SELECT graph,manifest,pruned FROM revisions WHERE trace=? AND revision=?")
      .get(trace, Number(revision)) as { graph: string; manifest: Buffer | null; pruned: number } | undefined;
    if (!rev) throw new VLError("NOT_FOUND");
    if (rev.pruned || !rev.manifest) throw new VLError("REVISION_PRUNED");
    const manifest = JSON.parse(Buffer.from(rev.manifest).toString("utf8")) as import("@latticeag/vislineage-core").GraphManifest;
    const steps = (
      this.db
        .prepare("SELECT s.hash,s.body FROM revision_steps rs JOIN steps s ON s.hash=rs.hash WHERE rs.trace=? AND rs.revision=?")
        .all(trace, Number(revision)) as { hash: string; body: Buffer }[]
    ).map((r) => ({ body: JSON.parse(Buffer.from(r.body).toString("utf8")) as StepBody, hash: r.hash }));
    const origins = (
      this.db
        .prepare("SELECT o.envelope FROM revision_origins ro JOIN origins o ON o.digest=ro.digest WHERE ro.trace=? AND ro.revision=?")
        .all(trace, Number(revision)) as { envelope: Buffer }[]
    ).map((r) => JSON.parse(Buffer.from(r.envelope).toString("utf8")) as Origin);
    const edges = (
      this.db
        .prepare("SELECT body FROM edges WHERE trace=? AND revision=?")
        .all(trace, Number(revision)) as { body: Buffer }[]
    ).map((r) => JSON.parse(Buffer.from(r.body).toString("utf8")) as import("@latticeag/vislineage-core").Edge);
    return { graph: rev.graph, manifest, steps, origins, edges };
  }

  private mPathGet(req: { params: Record<string, unknown> }): import("@latticeag/vislineage-core").PathResult {
    const pr = sch.pathRequest(req.params, "/params", this.opts.limits.path_nodes, 256);
    const t = this.traceById(pr.trace);
    if (!t) throw new VLError("NOT_FOUND");
    if (BigInt(pr.revision) > BigInt(t.revision)) throw new VLError("NOT_FOUND");
    const proj = this.revisionProjection(pr.trace, BigInt(pr.revision));
    this.acquireLease(pr.trace, BigInt(pr.revision));
    try {
      return computePath(
        { steps: proj.steps, edges: proj.edges, origins: proj.origins, gaps: proj.manifest.gaps, graph: proj.graph },
        pr,
      );
    } finally {
      this.releaseLeases();
    }
  }

  private leaseId: string | null = null;
  private acquireLease(trace: string, revision: bigint): void {
    this.leaseId = `lease_${randomBytes(12).toString("base64url")}`;
    this.db.prepare("INSERT INTO leases(id,trace,revision,expires_at) VALUES(?,?,?,?)").run(
      this.leaseId,
      trace,
      Number(revision),
      Math.floor(this.now()) + 60,
    );
  }
  private releaseLeases(): void {
    if (this.leaseId) {
      this.db.prepare("DELETE FROM leases WHERE id=?").run(this.leaseId);
      this.leaseId = null;
    }
  }

  private mBundleExport(req: { params: Record<string, unknown> }): { bundle: Bundle; sunlight: unknown } {
    if (typeof req.params !== "object" || req.params === null) throw new VLError("SCHEMA_INVALID", "/params");
    const allowed = new Set(["path", "attachments"]);
    for (const k of Object.keys(req.params)) {
      if (!allowed.has(k)) throw new VLError("SCHEMA_INVALID", `/params/${k}`);
    }
    const pr = sch.pathRequest(req.params.path, "/params/path", this.opts.limits.path_nodes, 256);
    if (req.params.attachments !== "INCLUDE" && req.params.attachments !== "OMIT") {
      throw new VLError("SCHEMA_INVALID", "/params/attachments");
    }
    const policy = req.params.attachments;
    const t = this.traceById(pr.trace);
    if (!t) throw new VLError("NOT_FOUND");
    if (BigInt(pr.revision) > BigInt(t.revision)) throw new VLError("NOT_FOUND");
    this.acquireLease(pr.trace, BigInt(pr.revision));
    try {
      return this.execBundleExport(pr, policy);
    } finally {
      this.releaseLeases();
    }
  }

  private execBundleExport(
    pr: PathRequest,
    policy: "INCLUDE" | "OMIT",
  ): { bundle: Bundle; sunlight: unknown } {
    const proj = this.revisionProjection(pr.trace, BigInt(pr.revision));
    const graphHash = proj.graph;
    const pathRes = computePath(
      { steps: proj.steps, edges: proj.edges, origins: proj.origins, gaps: proj.manifest.gaps, graph: graphHash },
      pr,
    );

    // audit prefix through the entry binding this revision+graph
    const auditRows = this.db.prepare("SELECT seq,envelope FROM audit ORDER BY seq").all() as {
      seq: number | bigint;
      envelope: Buffer;
    }[];
    let bindSeq = -1;
    const audits: Audit[] = [];
    for (const r of auditRows) {
      const a = JSON.parse(Buffer.from(r.envelope).toString("utf8")) as Audit;
      audits.push(a);
      const d = a.body.data;
      if (
        (BigInt(pr.revision) === 0n && d.kind === "TraceCreated" && d.trace === pr.trace && d.graph === graphHash) ||
        (d.kind === "ImportCommitted" && d.trace === pr.trace && d.revision === pr.revision && d.graph === graphHash)
      ) {
        bindSeq = Number(r.seq);
        break;
      }
    }
    if (bindSeq < 0) throw new VLError("STORAGE_UNAVAILABLE", null, "no binding audit entry");

    // attachment refs across all bundled steps
    const refMap = new Map<string, { digest: string; format: string; bytes: string }>();
    for (const s of proj.steps) for (const r of s.body.attachments) refMap.set(r.digest, r);
    const refs = [...refMap.values()].sort((a, b) => (a.digest < b.digest ? -1 : 1));
    const artifacts: { digest: string; format: string; bytes: string; content: string }[] = [];
    if (policy === "INCLUDE") {
      for (const r of refs) {
        const row = this.db.prepare("SELECT state,relative_path,bytes FROM artifacts WHERE digest=?").get(r.digest) as
          | { state: string; relative_path: string | null; bytes: number | bigint }
          | undefined;
        if (!row || row.state !== "AVAILABLE" || !row.relative_path) {
          throw new VLError("ARTIFACT_UNAVAILABLE", null, `attachment ${r.digest}`);
        }
        const abs = path.join(this.opts.artifactsDir, row.relative_path);
        let raw: Buffer;
        try {
          raw = fs.readFileSync(abs);
        } catch {
          throw new VLError("ARTIFACT_UNAVAILABLE", null, `attachment ${r.digest}`);
        }
        if (H(raw) !== r.digest || BigInt(raw.length) !== BigInt(r.bytes)) {
          throw new VLError("ARTIFACT_UNAVAILABLE", null, `attachment ${r.digest} corrupt`);
        }
        artifacts.push({ digest: r.digest, format: r.format, bytes: r.bytes, content: raw.toString("base64url") });
      }
    }

    return buildBundle({
      workspace: this.opts.workspace,
      trace: pr.trace,
      revision: pr.revision,
      graph: proj.manifest,
      pathRequest: pr,
      path: pathRes,
      steps: proj.steps,
      origins: proj.origins,
      audit: audits.slice(0, bindSeq),
      artifacts,
      attachmentRefs: refs,
      attachmentPolicy: policy,
      bundleBytes: Math.min(this.opts.limits.bundle_bytes, GENERIC_CAP),
    });
  }

  private mBundleVerify(req: { params: Record<string, unknown> }): Verification {
    if (typeof req.params !== "object" || req.params === null) throw new VLError("SCHEMA_INVALID", "/params");
    const allowed = new Set(["bundle", "trust"]);
    for (const k of Object.keys(req.params)) {
      if (!allowed.has(k)) throw new VLError("SCHEMA_INVALID", `/params/${k}`);
    }
    const out = coreVerify(req.params.bundle, req.params.trust as TrustPackage);
    if ("ok" in out && out.ok === false) {
      const e = out.error;
      throw new VLError(e.code, e.details.field);
    }
    return out as Verification;
  }
}

function rawSpan(v: unknown): number | undefined {
  const s = spanOf(v);
  return s ? s[1] - s[0] : undefined;
}

function signPayloadAudit(key: KeyObject, hash: string): string {
  return signMessage(key, signPayload("VL-AUDIT-SIGN/1", hash));
}

export function writePinFile(pinPath: string, head: { seq: bigint; hash: string }, workspace: string): void {
  const pin: ExternalHead = { v: 1, workspace, seq: String(head.seq), hash: head.hash };
  fs.mkdirSync(path.dirname(pinPath), { recursive: true, mode: 0o700 });
  const tmp = `${pinPath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  const fd = fs.openSync(tmp, "wx", 0o600);
  try {
    fs.writeSync(fd, JSON.stringify(pin));
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, pinPath);
}
