import * as fs from "node:fs";
import * as path from "node:path";
import { timingSafeEqual, createHash } from "node:crypto";
import {
  IMPLEMENTATION,
  J,
  PROTOCOL,
  SCHEMA_VERSION,
  VLError,
  genId,
  isId,
  parseJsonBytes,
  parseJsonText,
  verify as coreVerify,
  publicKeyBytes,
  D,
  type Config,
  type PathResult,
  type Verification,
} from "@latticeag/vislineage-core";
import {
  WorkspaceService,
  applyPrune,
  backup as doBackup,
  doctor as doDoctor,
  keyRotate,
  migrate as doMigrate,
  prunePlan,
  restore as doRestore,
  writePinFile,
  type Credential,
  type RpcFailureObj,
} from "@latticeag/vislineage-sqlite";
import { CliError, auditKey, authToken, configHash, loadConfig, type LoadedConfig } from "./config.js";
import { Journal } from "./journal.js";
import { remoteCall } from "./remote.js";
import { renderPath, renderVerification } from "./render.js";
import { serve } from "./serve.js";

const VERSION_OUT = { protocol: PROTOCOL, schema: SCHEMA_VERSION, implementation: IMPLEMENTATION };

interface Flags {
  [k: string]: string | boolean | undefined;
}

function parseArgs(argv: string[]): { cmd: string[]; flags: Flags } {
  const cmd: string[] = [];
  const flags: Flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq >= 0) {
        flags[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith("--")) {
          flags[a.slice(2)] = next;
          i++;
        } else {
          flags[a.slice(2)] = true;
        }
      }
    } else {
      cmd.push(a);
    }
  }
  return { cmd, flags };
}

const KNOWN_FLAGS = new Set([
  "config", "json", "quiet", "remote", "request-id", "workspace", "db", "key-env",
  "id", "profile", "namespace", "project", "source", "trace", "file", "origins",
  "artifacts", "expected-revision", "revision", "record", "max-depth", "max-nodes",
  "out", "attachments", "bundle", "trust", "bind", "port", "deep", "from", "into",
  "pin", "before-revision", "apply", "confirm-graph", "next-id", "next-key-env",
  "trust-out", "to", "help",
]);

function fstr(flags: Flags, name: string, required = true): string {
  const v = flags[name];
  if (v === undefined || v === true || v === "") {
    if (required) throw new CliError("SCHEMA_INVALID", `missing --${name}`, 2);
    return "";
  }
  return v as string;
}

function exitForRpcError(code: string): number {
  if (code === "UNAUTHENTICATED" || code === "FORBIDDEN") return 6;
  if (code === "BUSY" || code === "RATE_LIMIT" || code === "STORAGE_UNAVAILABLE") return 7;
  if (
    code === "READ_ONLY" ||
    code === "REVISION_PRUNED" ||
    code === "ARTIFACT_UNAVAILABLE" ||
    code === "UNSUPPORTED_VERSION"
  ) {
    return 8;
  }
  return 2;
}

function writeOut(file: string, bytes: Buffer): void {
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true, mode: 0o700 });
  let fd: number;
  try {
    fd = fs.openSync(file, "wx", 0o600);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      throw new CliError("OUT_EXISTS", `output exists: ${file}`, 2);
    }
    throw e;
  }
  try {
    fs.writeSync(fd, bytes);
  } finally {
    fs.closeSync(fd);
  }
}

interface Ctx {
  flags: Flags;
  cfg: LoadedConfig | null;
  json: boolean;
  remote: string | null;
}

function outJson(ctx: Ctx, v: unknown): void {
  process.stdout.write(JSON.stringify(v) + "\n");
}

async function rpc(ctx: Ctx, method: string, params: unknown, needsWrite: boolean): Promise<unknown> {
  const id =
    typeof ctx.flags["request-id"] === "string" ? (ctx.flags["request-id"] as string) : genId("request");
  if (!isId("request", id)) throw new CliError("ID_INVALID", "--request-id must be a vlq_ id", 2);
  const request = { id, method, params };
  if (ctx.remote) {
    const journal = new Journal(ctx.cfg!.stateDir);
    journal.pending(id, method, params);
    const token = authToken(ctx.cfg!);
    const resp = await remoteCall(ctx.remote, token, request);
    journal.responded(id, method, params, resp);
    if (!resp.ok) {
      const e = resp.error!;
      throw new CliError(e.code, `remote ${method} failed: ${e.code}`, exitForRpcError(e.code));
    }
    return resp.result;
  }
  const svc = openService(ctx.cfg!, needsWrite);
  try {
    const resp = svc.dispatch(request, ADMIN_CRED(ctx.cfg!.config.workspace));
    if (!resp.ok) {
      const e = (resp as RpcFailureObj).error;
      throw new CliError(e.code, `${method}: ${e.code}`, exitForRpcError(e.code));
    }
    return resp.result;
  } finally {
    svc.close();
  }
}

function ADMIN_CRED(workspace: string): Credential {
  return { roles: new Set(["read", "write", "admin"]), workspace };
}

function openService(cfg: LoadedConfig, needsWrite: boolean): WorkspaceService {
  const key = needsWrite ? auditKey(cfg) : { key: null, public: "" };
  return new WorkspaceService({
    dbPath: cfg.dbPath,
    stateDir: cfg.stateDir,
    artifactsDir: cfg.artifactsDir,
    workspace: cfg.config.workspace,
    auditKeyId: cfg.config.audit_key_id,
    auditKey: key.key,
    limits: cfg.config.limits,
    retention: cfg.config.retention,
    recoveryPinPath: cfg.pinPath,
    log: (level, event, request, code, ms) => {
      const rec = { level, event, request, code, duration_ms: ms };
      process.stderr.write(J(rec).toString("utf8") + "\n");
    },
  });
}

function parseJsonFile(p: string, numbers: "core" | "vendor"): unknown {
  const raw = fs.readFileSync(p);
  if (raw.length > 256 * 1024 * 1024) throw new CliError("BODY_LIMIT", "file exceeds 256 MiB", 2);
  return parseJsonBytes(raw, { numbers, trackSpans: numbers === "vendor" });
}

/** Import row file: JSONL (nonblank lines) or a JSON array. */
function parseRowsFile(p: string): { rows: unknown[] } {
  const text = fs.readFileSync(p, "utf8");
  const trimmed = text.trimStart();
  if (trimmed.startsWith("[")) {
    const v = parseJsonText(text, { numbers: "vendor", trackSpans: true });
    if (!Array.isArray(v)) throw new VLError("SCHEMA_INVALID", null, "row file must be an array or JSONL");
    return { rows: v };
  }
  const rows: unknown[] = [];
  const lines = text.split("\n");
  if (lines.length && lines[lines.length - 1] === "") lines.pop(); // one terminal LF allowed
  for (const [i, line] of lines.entries()) {
    if (line.trim() === "") throw new VLError("JSON_INVALID", null, `blank line ${i + 1}`);
    rows.push(parseJsonText(line, { numbers: "vendor", trackSpans: true }));
  }
  return { rows };
}

async function main(): Promise<number> {
  const { cmd, flags } = parseArgs(process.argv.slice(2));
  for (const k of Object.keys(flags)) {
    if (!KNOWN_FLAGS.has(k)) {
      process.stderr.write(`vislineage: unknown flag --${k}\n`);
      return 2;
    }
  }
  if (flags.help || cmd[0] === "help") {
    printHelp();
    return 0;
  }
  const json = flags.json === true || flags.quiet === true;
  const ctx: Ctx = { flags, cfg: null, json, remote: null };

  // version needs no config
  if (cmd[0] === "version") {
    outJson(ctx, VERSION_OUT);
    return 0;
  }

  const configPath = typeof flags.config === "string" ? flags.config : "./vislineage.json";

  // ---- init ---------------------------------------------------------------
  if (cmd[0] === "init") {
    const workspace = fstr(flags, "workspace");
    if (!isId("workspace", workspace)) throw new CliError("ID_INVALID", "--workspace must be a vlw_ id", 2);
    const dbPath = path.resolve(fstr(flags, "db"));
    const keyEnv = fstr(flags, "key-env");
    if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(keyEnv)) throw new CliError("SCHEMA_INVALID", "bad --key-env name", 2);
    const cfgPath = path.resolve(configPath);
    if (fs.existsSync(cfgPath) || (fs.existsSync(dbPath) && fs.statSync(dbPath).size > 0)) {
      throw new CliError("SOURCE_CONFLICT", "refusing to initialize over a nonempty target", 2);
    }
    const seed = process.env[keyEnv];
    if (seed === undefined) throw new CliError("CONFIG_SECRET_MISSING", `${keyEnv} is not set`, 2);
    const { key } = auditKey({
      config: { audit_key_env: keyEnv } as Config,
    } as LoadedConfig);
    const auditKeyId = genId("key");
    const stateDir = path.dirname(dbPath);
    const artifactsDir = path.join(stateDir, "artifacts");
    const pinPath = path.join(stateDir, "external-head.json");
    const config: Config = {
      version: 1,
      workspace,
      database: path.relative(path.dirname(cfgPath), dbPath),
      artifacts: path.relative(path.dirname(cfgPath), artifactsDir),
      audit_key_id: auditKeyId,
      audit_key_env: keyEnv,
      bind: "127.0.0.1",
      port: 8787,
      auth: { token_env: "VISLINEAGE_ADMIN_TOKEN", roles: ["admin"] },
      retention: { stage_ttl_seconds: 86400, history_revisions: 100, artifacts_days: 30 },
      limits: { stage_rows: 1000, request_bytes: 8388608, path_nodes: 4096, bundle_bytes: 67108864 },
      observability: { level: "info", metrics_socket: path.relative(path.dirname(cfgPath), path.join(stateDir, "metrics.sock")) },
      recovery_pin: path.relative(path.dirname(cfgPath), pinPath),
    };
    const requestId = genId("request");
    const svc = WorkspaceService.create({
      dbPath,
      stateDir,
      artifactsDir,
      workspace,
      auditKeyId,
      auditKey: key,
      limits: config.limits,
      retention: config.retention,
      recoveryPinPath: null,
      configHash: configHash(config),
      requestId,
    });
    const headRow = svc.db.prepare("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").get() as { hash: string };
    writePinFile(pinPath, { seq: 1n, hash: headRow.hash }, workspace);
    svc.close();
    writeOut(cfgPath, J(config));
    outJson(ctx, { command: "init", workspace, schema: 1, audit: headRow.hash, request: requestId });
    return 0;
  }

  ctx.cfg = loadConfig(configPath);
  if (typeof flags.remote === "string") ctx.remote = flags.remote;
  if (flags.remote && flags.db) throw new CliError("SCHEMA_INVALID", "--remote and --db cannot combine", 2);

  const c = cmd.join(" ");
  switch (c) {
    case "source add": {
      const source = {
        id: fstr(flags, "id"),
        profile: fstr(flags, "profile"),
        namespace: fstr(flags, "namespace"),
        project: fstr(flags, "project"),
      };
      const r = await rpc(ctx, "source.register", source, true);
      outJson(ctx, r);
      return 0;
    }
    case "source list": {
      const r = await rpc(ctx, "source.list", {}, false);
      outJson(ctx, r);
      return 0;
    }
    case "trace create": {
      const r = await rpc(ctx, "trace.create", { trace: fstr(flags, "id") }, true);
      outJson(ctx, r);
      return 0;
    }
    case "trace get": {
      const r = await rpc(ctx, "trace.get", { trace: fstr(flags, "id") }, false);
      outJson(ctx, r);
      return 0;
    }
    case "import stage": {
      const { rows } = parseRowsFile(fstr(flags, "file"));
      const origins = flags.origins ? (parseJsonFile(fstr(flags, "origins"), "core") as unknown[]) : [];
      const artifacts = flags.artifacts ? (parseJsonFile(fstr(flags, "artifacts"), "core") as unknown[]) : [];
      if (!Array.isArray(origins) || !Array.isArray(artifacts)) {
        throw new CliError("SCHEMA_INVALID", "--origins/--artifacts must be JSON arrays", 2);
      }
      const params = {
        import: fstr(flags, "id"),
        trace: fstr(flags, "trace"),
        source: fstr(flags, "source"),
        rows,
        origins,
        artifacts,
      };
      const r = await rpc(ctx, "import.stage", params, true);
      outJson(ctx, r);
      return 0;
    }
    case "import get": {
      const r = await rpc(ctx, "import.get", { import: fstr(flags, "id") }, false);
      outJson(ctx, r);
      return 0;
    }
    case "import commit": {
      const r = await rpc(
        ctx,
        "import.commit",
        { import: fstr(flags, "id"), expected_revision: fstr(flags, "expected-revision") },
        true,
      );
      outJson(ctx, r);
      return 0;
    }
    case "import cancel": {
      const r = await rpc(ctx, "import.cancel", { import: fstr(flags, "id") }, true);
      outJson(ctx, r);
      return 0;
    }
    case "path": {
      const pr = pathParams(flags);
      const r = (await rpc(ctx, "path.get", pr, false)) as PathResult;
      if (json) {
        outJson(ctx, r);
      } else {
        process.stdout.write(renderPath(r) + "\n");
      }
      return r.structural === "CONFLICTED" ? 5 : r.structural === "INCOMPLETE" ? 4 : 0;
    }
    case "export": {
      const pr = pathParams(flags);
      const policy = fstr(flags, "attachments", false) || "omit";
      if (policy !== "include" && policy !== "omit") {
        throw new CliError("SCHEMA_INVALID", "--attachments must be include|omit", 2);
      }
      const r = (await rpc(ctx, "bundle.export", { path: pr, attachments: policy.toUpperCase() }, false)) as {
        bundle: unknown;
        sunlight: unknown;
      };
      const bundleBytes = J(r.bundle);
      writeOut(fstr(flags, "out"), bundleBytes);
      outJson(ctx, r.sunlight);
      return 0;
    }
    case "verify": {
      const bundleRaw = fs.readFileSync(fstr(flags, "bundle"));
      const trustRaw = fs.readFileSync(fstr(flags, "trust"));
      if (bundleRaw.length > 64 * 1024 * 1024 + 4 * 1024 * 1024) {
        throw new CliError("BODY_LIMIT", "bundle exceeds cap", 2);
      }
      if (trustRaw.length > 4 * 1024 * 1024) throw new CliError("BODY_LIMIT", "trust file exceeds cap", 2);
      let bundleV: unknown, trustV: unknown;
      try {
        bundleV = parseJsonBytes(bundleRaw, { numbers: "core" });
        trustV = parseJsonBytes(trustRaw, { numbers: "core" });
      } catch (e) {
        throw new CliError(e instanceof VLError ? e.code : "SCHEMA_INVALID", "malformed bundle/trust file", 2);
      }
      const out = coreVerify(bundleV, trustV);
      if ("ok" in out && out.ok === false) {
        // malformed bundle/trust is a schema failure → exit 2
        outJson(ctx, { error: { code: out.error.code, retryable: false } });
        return 2;
      }
      const v = out as Verification;
      if (json) outJson(ctx, v);
      else process.stdout.write(renderVerification(v) + "\n");
      if (v.integrity === "INVALID") return 3;
      if (v.structural === "CONFLICTED" || v.origin === "CONFLICTED") return 5;
      if (v.origin !== "TRUSTED_AT_PIN" || v.audit !== "TRUSTED_AT_PIN" || v.structural !== "COMPLETE_RELATIVE") {
        return 4;
      }
      return 0;
    }
    case "serve": {
      const bind = fstr(flags, "bind", false) || ctx.cfg.config.bind;
      const port = flags.port ? Number(flags.port) : ctx.cfg.config.port;
      const token = authToken(ctx.cfg);
      const svc = openService(ctx.cfg, true);
      const tokenHash = createHash("sha256").update(token).digest();
      const server = serve({
        svc,
        bind,
        port,
        resolveToken: (presented) => {
          const h = createHash("sha256").update(presented).digest();
          if (h.length === tokenHash.length && timingSafeEqual(h, tokenHash)) {
            return { roles: new Set(ctx.cfg!.config.auth.roles), workspace: ctx.cfg!.config.workspace };
          }
          return null;
        },
        requestBytes: ctx.cfg.config.limits.request_bytes,
        bundleBytes: ctx.cfg.config.limits.bundle_bytes,
        metricsSocket: ctx.cfg.metricsSocket,
      });
      await new Promise<void>((resolve) => {
        server.listen(port, bind, () => {
          process.stderr.write(`vislineage: serving ${bind}:${port} (${svc.state})\n`);
        });
        const shutdown = (sig: string) => {
          svc.state = "DRAINING";
          server.close(() => {
            svc.close();
            process.exit(sig === "SIGINT" ? 130 : 143);
          });
          setTimeout(() => process.exit(sig === "SIGINT" ? 130 : 143), 5000).unref();
        };
        process.on("SIGINT", () => shutdown("SIGINT"));
        process.on("SIGTERM", () => shutdown("SIGTERM"));
        void resolve;
      });
      return 0;
    }
    case "doctor": {
      const svc = openService(ctx.cfg, false);
      try {
        const r = doDoctor(svc, flags.deep === true);
        outJson(ctx, r);
        return r.integrity === "FAILED" ? 3 : 0;
      } finally {
        svc.close();
      }
    }
    case "backup": {
      const svc = openService(ctx.cfg, false);
      try {
        const r = doBackup(svc, fstr(flags, "out"));
        const head = svc.db.prepare("SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1").get() as {
          seq: number | bigint;
          hash: string;
        };
        writePinFile(ctx.cfg.pinPath, { seq: BigInt(head.seq), hash: head.hash }, ctx.cfg.config.workspace);
        outJson(ctx, { command: "backup", manifest: r.manifest, digest: r.digest });
        return 0;
      } finally {
        svc.close();
      }
    }
    case "restore": {
      const r = doRestore(fstr(flags, "from"), fstr(flags, "into"), fstr(flags, "pin"), path.join(fstr(flags, "into"), "external-head.json"));
      outJson(ctx, { command: "restore", workspace: r.workspace, state: r.state, head: r.head });
      return 0;
    }
    case "prune": {
      const before = BigInt(fstr(flags, "before-revision"));
      const traceId = fstr(flags, "trace");
      const apply = flags.apply === true;
      const svc = openService(ctx.cfg, apply);
      try {
        if (!apply) {
          const plan = prunePlan(svc, traceId, before);
          outJson(ctx, { command: "prune", applied: false, plan, audit: null });
          return 0;
        }
        const confirm = fstr(flags, "confirm-graph");
        const requestId = genId("request");
        const { plan, audit } = applyPrune(svc, traceId, before, confirm, requestId);
        outJson(ctx, { command: "prune", applied: true, plan, audit, request: requestId });
        return 0;
      } finally {
        svc.close();
      }
    }
    case "key rotate": {
      const nextId = fstr(flags, "next-id");
      const nextEnv = fstr(flags, "next-key-env");
      const trustOut = fstr(flags, "trust-out");
      const nextKey = auditKey({
        config: { audit_key_env: nextEnv } as Config,
      } as LoadedConfig);
      const svc = openService(ctx.cfg, true);
      try {
        const requestId = genId("request");
        const r = keyRotate(svc, nextId, publicKeyBytes(nextKey.key).toString("base64url"), requestId);
        writeOut(trustOut, J(r.update));
        // rewrite config only after the signed rotation committed (§10.3)
        const cfgRaw = fs.readFileSync(configPath, "utf8");
        const cfgObj = JSON.parse(cfgRaw) as Record<string, unknown>;
        cfgObj.audit_key_id = nextId;
        cfgObj.audit_key_env = nextEnv;
        writeOutAtomic(configPath, J(cfgObj));
        outJson(ctx, {
          command: "key.rotate",
          old: r.old,
          next: r.next,
          audit: r.audit,
          trust_file_digest: D("VL-TRUST-UPDATE/1", r.update),
          request: requestId,
        });
        return 0;
      } finally {
        svc.close();
      }
    }
    case "migrate": {
      const to = Number(fstr(flags, "to"));
      if (!Number.isSafeInteger(to) || to < 1) throw new CliError("SCHEMA_INVALID", "bad --to", 2);
      const svc = openService(ctx.cfg, flags.apply === true);
      try {
        const r = doMigrate(
          {
            dbPath: ctx.cfg.dbPath,
            stateDir: ctx.cfg.stateDir,
            artifactsDir: ctx.cfg.artifactsDir,
            workspace: ctx.cfg.config.workspace,
            auditKeyId: ctx.cfg.config.audit_key_id,
            auditKey: null,
            limits: ctx.cfg.config.limits,
            retention: ctx.cfg.config.retention,
            recoveryPinPath: ctx.cfg.pinPath,
            requestId: genId("request"),
          },
          to,
          flags.apply === true,
        );
        outJson(ctx, { command: "migrate", from: r.from, to: r.to, state: r.state, graphs_checked: r.graphs_checked });
        return 0;
      } finally {
        svc.close();
      }
    }
    default:
      process.stderr.write(`vislineage: unknown command '${c}'\n`);
      printHelp();
      return 2;
  }
}

function writeOutAtomic(file: string, bytes: Buffer): void {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, bytes, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function pathParams(flags: Flags): unknown {
  const pr: Record<string, unknown> = {
    trace: fstr(flags, "trace"),
    revision: fstr(flags, "revision"),
    action: { source: fstr(flags, "source"), record: fstr(flags, "record") },
    max_depth: flags["max-depth"] !== undefined ? Number(flags["max-depth"]) : 256,
    max_nodes: flags["max-nodes"] !== undefined ? Number(flags["max-nodes"]) : 4096,
  };
  if (flags["max-depth"] !== undefined) {
    const n = Number(flags["max-depth"]);
    if (!Number.isSafeInteger(n) || n < 1 || n > 256) throw new CliError("SCHEMA_INVALID", "--max-depth must be 1..256", 2);
    pr.max_depth = n;
  }
  if (flags["max-nodes"] !== undefined) {
    const n = Number(flags["max-nodes"]);
    if (!Number.isSafeInteger(n) || n < 1 || n > 4096) throw new CliError("SCHEMA_INVALID", "--max-nodes must be 1..4096", 2);
    pr.max_nodes = n;
  }
  return pr;
}

function printHelp(): void {
  process.stdout.write(`vislineage — export-scoped lineage joiner (vislineage/1)

Usage: vislineage <command> [flags]   (global: --config PATH --json --quiet)

  init --workspace ID --db PATH --key-env NAME [--config PATH]
  source add --id ID --profile PROFILE --namespace TEXT --project TEXT
  source list
  trace create --id ID | trace get --id ID
  import stage --id ID --source ID --trace ID --file PATH [--origins PATH] [--artifacts PATH]
  import get --id ID | import commit --id ID --expected-revision N | import cancel --id ID
  path --trace ID --revision N --source ID --record TEXT [--max-depth N] [--max-nodes N]
  export --trace ID --revision N --source ID --record TEXT --out PATH [--attachments include|omit]
  verify --bundle PATH --trust PATH
  serve [--bind ADDR] [--port N]
  doctor [--deep]
  backup --out PATH
  restore --from PATH --into PATH --pin PATH
  prune --before-revision N --trace ID [--apply --confirm-graph HASH]
  key rotate --next-id ID --next-key-env NAME --trust-out PATH
  migrate --to N [--apply]
  version

Evidence labels: structural paths are CLAIMED, never verified; missing policy
displays UNKNOWN; disclosure is NORMALIZED_ONLY. Completeness is relative to
disclosed exports only. Not supported: provider URL fetching, token minting,
action dispatch, Treaty operations, live subscriptions, remote SQL.
`);
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    if (e instanceof CliError) {
      const obj = { error: { code: e.code, retryable: e.code === "BUSY" || e.code === "STORAGE_UNAVAILABLE" || e.code === "RATE_LIMIT" } };
      process.stderr.write(J(obj).toString("utf8") + "\n");
      process.exit(e.exit);
    }
    if (e instanceof VLError) {
      const obj = { error: { code: e.code, retryable: e.retryable } };
      process.stderr.write(J(obj).toString("utf8") + "\n");
      process.exit(exitForRpcError(e.code));
    }
    process.stderr.write(`vislineage: internal error: ${(e as Error).message}\n`);
    process.exit(1);
  });
