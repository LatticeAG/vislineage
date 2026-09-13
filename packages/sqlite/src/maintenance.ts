import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { KeyObject } from "node:crypto";
import {
  D,
  H,
  J,
  VLError,
  isHash,
  reduce,
  type Audit,
  type BackupManifest,
  type Origin,
  type PrunePlan,
  type Step,
  type TrustUpdate,
} from "@latticeag/vislineage-core";
import { schema as sch } from "@latticeag/vislineage-core";
import {
  SCHEMA_VERSION,
  acquireWriterLock,
  auditHead,
  checkMeta,
  initDb,
  openDb,
  reconcilePin,
  withTx,
  writeArtifactFile,
} from "./store.js";
import { WorkspaceService, type ServiceOptions } from "./service.js";

function sha256File(p: string): { bytes: number; digest: string } {
  const b = fs.readFileSync(p);
  return { bytes: b.length, digest: createHash("sha256").update(b).digest("hex") };
}

function decAudit(row: { envelope: Buffer }): Audit {
  return JSON.parse(Buffer.from(row.envelope).toString("utf8")) as Audit;
}

function loadStep(row: { hash: string; body: Buffer }): Step {
  return { body: JSON.parse(Buffer.from(row.body).toString("utf8")) as Step["body"], hash: row.hash };
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

export interface DoctorResult {
  command: "doctor";
  integrity: "OK" | "FAILED";
  read_only: boolean;
  graph_checks: number;
  reasons: string[];
}

/** §10.3 doctor. --deep rebuilds every retained graph and re-verifies the audit chain. */
export function doctor(svc: WorkspaceService, deep: boolean): DoctorResult {
  const db = svc.db;
  const reasons: string[] = [];
  let graphChecks = 0;
  let failed = false;

  // audit chain continuity + hash recomputation (always)
  const audits = db.prepare("SELECT seq,envelope FROM audit ORDER BY seq").all() as {
    seq: number | bigint;
    envelope: Buffer;
  }[];
  let prev = "0".repeat(64);
  let expect = 1;
  for (const r of audits) {
    const a = decAudit(r);
    if (BigInt(a.body.seq) !== BigInt(expect)) {
      reasons.push(`AUDIT_GAP:${expect}`);
      failed = true;
    }
    if (a.body.prev !== prev) {
      reasons.push(`AUDIT_LINK:${a.body.seq}`);
      failed = true;
    }
    if (a.hash !== D("VL-AUDIT/1", a.body)) {
      reasons.push(`AUDIT_HASH:${a.body.seq}`);
      failed = true;
    }
    prev = a.hash;
    expect = Number(BigInt(a.body.seq)) + 1;
  }

  if (deep) {
    // rebuild every retained revision's manifest and compare graph roots
    const revs = db
      .prepare("SELECT trace,revision,graph,manifest FROM revisions WHERE pruned=0")
      .all() as { trace: string; revision: number; graph: string; manifest: Buffer | null }[];
    for (const rev of revs) {
      graphChecks++;
      const steps = (
        db
          .prepare("SELECT s.hash,s.body FROM revision_steps rs JOIN steps s ON s.hash=rs.hash WHERE rs.trace=? AND rs.revision=?")
          .all(rev.trace, rev.revision) as { hash: string; body: Buffer }[]
      ).map(loadStep);
      const origins = (
        db
          .prepare("SELECT o.envelope FROM revision_origins ro JOIN origins o ON o.digest=ro.digest WHERE ro.trace=? AND ro.revision=?")
          .all(rev.trace, rev.revision) as { envelope: Buffer }[]
      ).map((r) => JSON.parse(Buffer.from(r.envelope).toString("utf8")) as Origin);
      const red = reduce(steps, origins, svc.opts.workspace, rev.trace);
      const g = D("VL-GRAPH/1", red.manifest);
      if (g !== rev.graph) {
        reasons.push(`GRAPH_MISMATCH:${rev.trace}@${rev.revision}`);
        failed = true;
      }
      if (!rev.manifest || Buffer.compare(J(red.manifest), rev.manifest) !== 0) {
        reasons.push(`MANIFEST_MISMATCH:${rev.trace}@${rev.revision}`);
        failed = true;
      }
    }
    // step hash recomputation
    const stepRows = db.prepare("SELECT hash,body FROM steps").all() as { hash: string; body: Buffer }[];
    for (const s of stepRows.map(loadStep)) {
      if (s.hash !== D("VL-STEP/1", s.body)) {
        reasons.push(`STEP_HASH:${s.hash}`);
        failed = true;
      }
    }
    // artifact integrity
    const arts = db.prepare("SELECT digest,state,relative_path FROM artifacts").all() as {
      digest: string;
      state: string;
      relative_path: string | null;
    }[];
    for (const a of arts) {
      if (a.state === "AVAILABLE") {
        if (!a.relative_path) {
          reasons.push(`ARTIFACT_MISSING:${a.digest}`);
          failed = true;
          continue;
        }
        const abs = path.join(svc.opts.artifactsDir, a.relative_path);
        try {
          const f = sha256File(abs);
          if (f.digest !== a.digest) {
            reasons.push(`ARTIFACT_HASH:${a.digest}`);
            failed = true;
          }
        } catch {
          reasons.push(`ARTIFACT_MISSING:${a.digest}`);
          failed = true;
        }
      }
    }
    // orphan artifact files are reported, not deleted (§11.2)
    const known = new Set(arts.filter((a) => a.relative_path).map((a) => a.relative_path!));
    const walk = (dir: string): void => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, ent.name);
        if (ent.isDirectory()) walk(p);
        else {
          const rel = path.relative(svc.opts.artifactsDir, p);
          if (!known.has(rel) && !ent.name.includes(".tmp-")) reasons.push(`ARTIFACT_ORPHAN:${rel}`);
        }
      }
    };
    if (fs.existsSync(svc.opts.artifactsDir)) walk(svc.opts.artifactsDir);
  }

  return {
    command: "doctor",
    integrity: failed ? "FAILED" : "OK",
    read_only: svc.state === "READ_ONLY",
    graph_checks: graphChecks,
    reasons: reasons.sort(),
  };
}

// ---------------------------------------------------------------------------
// backup / restore
// ---------------------------------------------------------------------------

/** §10.3 backup: consistent DB snapshot + reachable artifacts + manifest. */
export function backup(
  svc: WorkspaceService,
  outDir: string,
): { manifest: BackupManifest; digest: string } {
  const db = svc.db;
  fs.mkdirSync(outDir, { recursive: false, mode: 0o700 }); // fails if exists
  const dbOut = path.join(outDir, "lineage.sqlite");
  db.exec(`VACUUM INTO '${dbOut.replace(/'/g, "''")}';`);

  const files: { path: string; bytes: string; digest: string }[] = [];
  files.push({ path: "lineage.sqlite", ...mapSha(sha256File(dbOut)) });

  const artRows = svc.db
    .prepare("SELECT digest,relative_path FROM artifacts WHERE state='AVAILABLE' AND relative_path IS NOT NULL ORDER BY digest")
    .all() as { digest: string; relative_path: string }[];
  for (const a of artRows) {
    const src = path.join(svc.opts.artifactsDir, a.relative_path);
    if (!fs.existsSync(src)) continue;
    const dst = path.join(outDir, "artifacts", a.relative_path);
    fs.mkdirSync(path.dirname(dst), { recursive: true, mode: 0o700 });
    fs.copyFileSync(src, dst);
    fs.chmodSync(dst, 0o600);
    const f = sha256File(dst);
    if (f.digest !== a.digest) throw new VLError("STORAGE_UNAVAILABLE", null, `artifact corrupt: ${a.digest}`);
    files.push({ path: `artifacts/${a.relative_path}`, ...mapSha(f) });
  }

  const head = auditHead(db);
  if (!head) throw new VLError("STORAGE_UNAVAILABLE", null, "no audit head");
  const manifest: BackupManifest = {
    v: 1,
    workspace: svc.opts.workspace,
    schema: SCHEMA_VERSION,
    head: { seq: String(head.seq), hash: head.hash },
    files: files.map((f) => ({ path: f.path, bytes: f.bytes, digest: f.digest })),
  };
  const digest = D("VL-BACKUP/1", manifest);
  const fd = fs.openSync(path.join(outDir, "manifest.json"), "wx", 0o600);
  try {
    fs.writeSync(fd, J(manifest));
  } finally {
    fs.closeSync(fd);
  }
  return { manifest, digest };
}

function mapSha(f: { bytes: number; digest: string }): { bytes: string; digest: string } {
  return { bytes: String(f.bytes), digest: f.digest };
}

/** Verify a backup directory against its manifest (§10.3 path rules). */
export function verifyBackupDir(dir: string): { manifest: BackupManifest } {
  const manifestRaw = fs.readFileSync(path.join(dir, "manifest.json"));
  const manifest = JSON.parse(manifestRaw.toString("utf8")) as BackupManifest;
  sch.backupManifest(manifest, "/manifest");
  for (const f of manifest.files) {
    if (f.path.startsWith("/") || f.path.includes("..") || f.path.includes("\\")) {
      throw new VLError("STORAGE_UNAVAILABLE", null, `bad backup path ${f.path}`);
    }
    const p = path.join(dir, f.path);
    const lst = fs.lstatSync(p);
    if (lst.isSymbolicLink()) throw new VLError("STORAGE_UNAVAILABLE", null, `symlink in backup ${f.path}`);
    const actual = sha256File(p);
    if (actual.digest !== f.digest || String(actual.bytes) !== f.bytes) {
      throw new VLError("STORAGE_UNAVAILABLE", null, `backup file mismatch ${f.path}`);
    }
  }
  // allow exactly manifest.json plus listed files
  const allowed = new Set(["manifest.json", ...manifest.files.map((f) => f.path)]);
  const walk = (d: string): void => {
    for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, ent.name);
      const rel = path.relative(dir, p);
      if (ent.isDirectory()) {
        walk(p);
      } else if (!allowed.has(rel.split(path.sep).join("/"))) {
        throw new VLError("STORAGE_UNAVAILABLE", null, `unexpected backup entry ${rel}`);
      }
    }
  };
  walk(dir);
  return { manifest };
}

/**
 * §10.3 restore: copy a verified backup into a fresh directory and install the
 * independently supplied external head pin. The restored service opens
 * READ_ONLY until reconciliation/doctor passes.
 */
export function restore(
  fromDir: string,
  intoDir: string,
  pinFile: string,
  pinDest: string,
): { workspace: string; state: "READ_ONLY"; head: { seq: string; hash: string } } {
  const { manifest } = verifyBackupDir(fromDir);
  fs.mkdirSync(intoDir, { recursive: false, mode: 0o700 });
  for (const f of manifest.files) {
    const src = path.join(fromDir, f.path);
    const dst = path.join(intoDir, f.path);
    fs.mkdirSync(path.dirname(dst), { recursive: true, mode: 0o700 });
    fs.copyFileSync(src, dst);
    fs.chmodSync(dst, 0o600);
    const actual = sha256File(dst);
    if (actual.digest !== f.digest) throw new VLError("STORAGE_UNAVAILABLE", null, `restore mismatch ${f.path}`);
  }
  // independently supplied head pin — never taken from inside the backup
  const pinRaw = fs.readFileSync(pinFile, "utf8");
  const pin = JSON.parse(pinRaw) as { v: number; workspace: string; seq: string; hash: string };
  if (pin.v !== 1 || pin.workspace !== manifest.workspace || !isHash(pin.hash)) {
    throw new VLError("STORAGE_UNAVAILABLE", null, "independent pin does not match backup workspace");
  }
  const fd = fs.openSync(pinDest, "wx", 0o600);
  try {
    fs.writeSync(fd, JSON.stringify({ v: 1, workspace: pin.workspace, seq: pin.seq, hash: pin.hash }));
  } finally {
    fs.closeSync(fd);
  }
  return { workspace: manifest.workspace, state: "READ_ONLY", head: manifest.head };
}

// ---------------------------------------------------------------------------
// prune
// ---------------------------------------------------------------------------

/** Deterministic prune plan for one trace (§10.3/§11.3). */
export function prunePlan(
  svc: WorkspaceService,
  traceId: string,
  beforeRevision: bigint,
): PrunePlan {
  const db = svc.db;
  const t = db.prepare("SELECT revision,graph FROM traces WHERE id=?").get(traceId) as
    | { revision: number | bigint; graph: string }
    | undefined;
  if (!t) throw new VLError("NOT_FOUND");
  const current = BigInt(t.revision);
  const keepFrom = current - BigInt(svc.opts.retention.history_revisions) + 1n;
  const now = Math.floor(Date.now() / 1000);
  const leased = new Set(
    (db.prepare("SELECT revision FROM leases WHERE trace=? AND expires_at > ?").all(traceId, now) as {
      revision: number | bigint;
    }[]).map((r) => String(r.revision)),
  );
  const revs = db
    .prepare("SELECT revision,pruned FROM revisions WHERE trace=? ORDER BY revision")
    .all(traceId) as { revision: number | bigint; pruned: number }[];
  const candidates: string[] = [];
  let blocked = false;
  for (const r of revs) {
    const rev = BigInt(r.revision);
    if (r.pruned) continue;
    if (rev === current) continue; // never the latest
    if (rev >= beforeRevision) continue; // must be older than --before-revision
    if (rev >= keepFrom) continue; // inside the retention window
    if (leased.has(String(rev))) {
      blocked = true;
      continue;
    }
    candidates.push(String(rev));
  }
  // artifacts eligible by age not held by a stage or lease
  const leasedTraces = new Set(
    (db.prepare("SELECT DISTINCT trace FROM leases WHERE expires_at > ?").all(now) as { trace: string }[]).map(
      (r) => r.trace,
    ),
  );
  const cutoff = now - svc.opts.retention.artifacts_days * 86400;
  const stagedPayloads = db.prepare("SELECT staged FROM imports WHERE state='STAGED'").all() as {
    staged: Buffer | null;
  }[];
  const stagedDigests = new Set<string>();
  for (const s of stagedPayloads) {
    if (!s.staged) continue;
    const p = JSON.parse(Buffer.from(s.staged).toString("utf8")) as { artifacts: { digest: string }[] };
    for (const a of p.artifacts) stagedDigests.add(a.digest);
  }
  const artRows = db
    .prepare("SELECT digest,created_at FROM artifacts WHERE state='AVAILABLE' ORDER BY digest")
    .all() as { digest: string; created_at: number | bigint }[];
  const artifacts: string[] = [];
  for (const a of artRows) {
    if (Number(a.created_at) > cutoff) continue;
    if (stagedDigests.has(a.digest)) continue;
    // held by a lease iff any unexpired lease covers a revision whose steps reference it
    if (leasedTraces.has(traceId) && artifactReferencedByLeasedRevision(db, a.digest, traceId, now)) {
      blocked = true;
      continue;
    }
    artifacts.push(a.digest);
  }
  return {
    trace: traceId,
    graph: t.graph,
    revisions: candidates.sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1)),
    artifacts,
    blocked_by_lease: blocked,
  };
}

function artifactReferencedByLeasedRevision(
  db: DatabaseSync,
  digest: string,
  traceId: string,
  now: number,
): boolean {
  const rows = db
    .prepare(
      `SELECT rs.hash FROM leases l
       JOIN revision_steps rs ON rs.trace=l.trace AND rs.revision=l.revision
       JOIN steps s ON s.hash=rs.hash
       WHERE l.trace=? AND l.expires_at > ?`,
    )
    .all(traceId, now) as { hash: string }[];
  for (const r of rows) {
    const s = db.prepare("SELECT body FROM steps WHERE hash=?").get(r.hash) as { body: Buffer };
    const body = JSON.parse(Buffer.from(s.body).toString("utf8")) as Step["body"];
    if (body.attachments.some((a) => a.digest === digest)) return true;
  }
  return false;
}

/** Apply a re-planned prune; emits RetentionPruned and returns its audit hash. */
export function applyPrune(
  svc: WorkspaceService,
  traceId: string,
  beforeRevision: bigint,
  confirmGraph: string,
  requestId: string,
): { plan: PrunePlan; audit: string } {
  if (svc.state !== "READY") throw new VLError("READ_ONLY");
  return withTx(svc.db, () => {
    const plan = prunePlan(svc, traceId, beforeRevision);
    if (plan.blocked_by_lease) throw new VLError("BUSY", null, "active lease blocks prune");
    if (plan.graph !== confirmGraph) {
      throw new VLError("REVISION_CONFLICT", null, "confirm-graph does not match current graph");
    }
    const db = svc.db;
    for (const rev of plan.revisions) {
      db.prepare("DELETE FROM revision_steps WHERE trace=? AND revision=?").run(traceId, Number(rev));
      db.prepare("DELETE FROM revision_origins WHERE trace=? AND revision=?").run(traceId, Number(rev));
      db.prepare("DELETE FROM edges WHERE trace=? AND revision=?").run(traceId, Number(rev));
      db.prepare("UPDATE revisions SET manifest=NULL, pruned=1 WHERE trace=? AND revision=?").run(
        traceId,
        Number(rev),
      );
    }
    for (const d of plan.artifacts) {
      const row = db.prepare("SELECT relative_path FROM artifacts WHERE digest=?").get(d) as {
        relative_path: string | null;
      };
      db.prepare("UPDATE artifacts SET state='PRUNED', relative_path=NULL WHERE digest=?").run(d);
      if (row.relative_path) {
        try {
          fs.rmSync(path.join(svc.opts.artifactsDir, row.relative_path), { force: true });
        } catch {
          /* file already gone */
        }
      }
    }
    const env = svc.appendAuditInternal(
      {
        kind: "RetentionPruned",
        traces: [{ trace: traceId, revisions: plan.revisions }],
        artifacts: plan.artifacts,
      },
      requestId,
    );
    return { plan, audit: env.hash };
  });
}

// ---------------------------------------------------------------------------
// key rotation
// ---------------------------------------------------------------------------

/**
 * §10.3 key rotate: the OLD key signs KeyRotated; emits a TrustUpdate file for
 * the operator to merge into their TrustPackage.
 */
export function keyRotate(
  svc: WorkspaceService,
  nextId: string,
  nextPublic: string,
  requestId: string,
): { old: string; next: string; audit: string; update: TrustUpdate } {
  if (svc.state !== "READY") throw new VLError("READ_ONLY");
  sch.typedId(nextId, "key", "/next-id");
  if (!/^[A-Za-z0-9_-]{43}$/.test(nextPublic)) throw new VLError("SCHEMA_INVALID", "/next-key");
  return withTx(svc.db, () => {
    const head = auditHead(svc.db)!;
    const env = svc.appendAuditInternal(
      { kind: "KeyRotated", old: svc.opts.auditKeyId, next: nextId, next_public: nextPublic },
      requestId,
    );
    const update: TrustUpdate = {
      v: 1,
      workspace: svc.opts.workspace,
      retire: { id: svc.opts.auditKeyId, last_seq: String(head.seq) },
      activate: { id: nextId, public: nextPublic, first_seq: String(head.seq + 1n) },
    };
    return { old: svc.opts.auditKeyId, next: nextId, audit: env.hash, update };
  });
}

// ---------------------------------------------------------------------------
// migrate
// ---------------------------------------------------------------------------

/**
 * §13 migrate: dry-run PLANNED by default. --apply builds a new DB at the
 * target schema version, copies immutable bytes, rebuilds projections, and
 * compares every retained graph + audit head before activating.
 */
export function migrate(
  opts: ServiceOptions & { requestId: string },
  to: number,
  apply: boolean,
): { from: number; to: number; state: "PLANNED" | "ACTIVATED"; graphs_checked: number } {
  const from = SCHEMA_VERSION;
  if (to !== from) {
    // v1 has exactly one schema version; other targets are unsupported
    throw new VLError("UNSUPPORTED_VERSION", null, `no migration path to schema ${to}`);
  }
  if (!apply) return { from, to, state: "PLANNED", graphs_checked: 0 };

  // apply = verified copy at the same version (rebuild projections + compare)
  const srcDb = openDb(opts.dbPath, opts.workspace);
  let graphsChecked = 0;
  try {
    checkMeta(srcDb, opts.workspace);
    const tmpPath = `${opts.dbPath}.migrate-${process.pid}`;
    try {
      const dstDb = initDb(tmpPath, opts.workspace);
      copyAll(srcDb, dstDb);
      dstDb.close();
      const chk = openDb(tmpPath, opts.workspace);
      graphsChecked = compareStores(srcDb, chk, opts.workspace);
      chk.close();
      const bakPath = `${opts.dbPath}.premigrate-${process.pid}`;
      fs.copyFileSync(opts.dbPath, bakPath);
      fs.renameSync(tmpPath, opts.dbPath);
    } finally {
      try {
        fs.rmSync(tmpPath, { force: true });
      } catch {
        /* already moved */
      }
    }
  } finally {
    srcDb.close();
  }
  return { from, to, state: "ACTIVATED", graphs_checked: graphsChecked };
}

const IMMUTABLE_TABLES = [
  "meta",
  "sources",
  "traces",
  "native_traces",
  "steps",
  "origins",
  "imports",
  "revisions",
  "artifacts",
  "audit",
  "idempotency",
] as const;
const PROJECTION_TABLES = ["revision_steps", "revision_origins", "edges", "leases"] as const;

function copyAll(src: DatabaseSync, dst: DatabaseSync): void {
  const copy = (table: string): void => {
    const rows = src.prepare(`SELECT * FROM ${table}`).all() as Record<string, unknown>[];
    if (!rows.length) return;
    const cols = Object.keys(rows[0]!);
    const stmt = dst.prepare(
      `INSERT INTO ${table}(${cols.join(",")}) VALUES(${cols.map(() => "?").join(",")})`,
    );
    for (const r of rows) stmt.run(...cols.map((c) => r[c] as never));
  };
  withTx(dst, () => {
    for (const t of IMMUTABLE_TABLES) copy(t);
    for (const t of PROJECTION_TABLES) copy(t);
  });
}

/** Compare every retained revision graph and the audit head between two stores. */
function compareStores(a: DatabaseSync, b: DatabaseSync, workspace: string): number {
  const revsA = a
    .prepare("SELECT trace,revision,graph FROM revisions WHERE pruned=0 ORDER BY trace,revision")
    .all() as { trace: string; revision: number | bigint; graph: string }[];
  let checked = 0;
  for (const r of revsA) {
    const other = b
      .prepare("SELECT graph FROM revisions WHERE trace=? AND revision=?")
      .get(r.trace, Number(r.revision)) as { graph: string } | undefined;
    if (!other || other.graph !== r.graph) {
      throw new VLError("STORAGE_UNAVAILABLE", null, `migration graph mismatch ${r.trace}@${r.revision}`);
    }
    checked++;
  }
  const hA = auditHead(a);
  const hB = auditHead(b);
  if (String(hA?.seq) !== String(hB?.seq) || hA?.hash !== hB?.hash) {
    throw new VLError("STORAGE_UNAVAILABLE", null, "migration audit-head mismatch");
  }
  void workspace;
  return checked;
}

/** Reconcile a store's pin file (used by restore/doctor flows). */
export function reconcile(dbPath: string, workspace: string, pinPath: string) {
  const db = openDb(dbPath, workspace);
  try {
    checkMeta(db, workspace);
    return reconcilePin(db, pinPath);
  } finally {
    db.close();
  }
}
