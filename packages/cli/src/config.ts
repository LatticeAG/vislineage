import * as fs from "node:fs";
import * as path from "node:path";
import type { KeyObject } from "node:crypto";
import {
  D,
  FIXTURE_SEEDS,
  J,
  VLError,
  isId,
  isHash,
  parseJsonBytes,
  privateKeyFromSeed,
  publicKeyBytes,
  schema as sch,
  type Config,
} from "@latticeag/vislineage-core";

const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;

export class CliError extends Error {
  code: string;
  exit: number;
  constructor(code: string, msg: string, exit: number) {
    super(msg);
    this.code = code;
    this.exit = exit;
  }
}

export interface LoadedConfig {
  config: Config;
  dir: string; // config file directory; relative paths resolve against it
  dbPath: string;
  artifactsDir: string;
  pinPath: string;
  metricsSocket: string;
  stateDir: string;
}

const CONFIG_KEYS = new Set([
  "version",
  "workspace",
  "database",
  "artifacts",
  "audit_key_id",
  "audit_key_env",
  "bind",
  "port",
  "auth",
  "retention",
  "limits",
  "observability",
  "recovery_pin",
]);

export function loadConfig(configPath: string): LoadedConfig {
  let raw: Buffer;
  try {
    raw = fs.readFileSync(configPath);
  } catch {
    throw new CliError("CONFIG_MISSING", `config not found: ${configPath}`, 2);
  }
  if (raw.length > 64 * 1024) throw new CliError("BODY_LIMIT", "config exceeds 64 KiB", 2);
  let v: unknown;
  try {
    v = parseJsonBytes(raw, { numbers: "core" });
  } catch (e) {
    throw new CliError(e instanceof VLError ? e.code : "SCHEMA_INVALID", "config is not strict JSON", 2);
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new CliError("SCHEMA_INVALID", "config must be an object", 2);
  }
  const c = v as Record<string, unknown>;
  for (const k of Object.keys(c)) {
    if (!CONFIG_KEYS.has(k)) throw new CliError("SCHEMA_INVALID", `unknown config key: ${k}`, 2);
  }
  const req = (k: string): unknown => {
    if (!(k in c)) throw new CliError("SCHEMA_INVALID", `missing config key: ${k}`, 2);
    return c[k];
  };
  if (req("version") !== 1) throw new CliError("UNSUPPORTED_VERSION", "unsupported config version", 2);
  const workspace = c.workspace;
  if (!isId("workspace", workspace)) throw new CliError("SCHEMA_INVALID", "bad workspace id", 2);
  const str = (k: string): string => {
    const x = req(k);
    if (typeof x !== "string" || x.length === 0) throw new CliError("SCHEMA_INVALID", `bad ${k}`, 2);
    return x;
  };
  const auditKeyId = str("audit_key_id");
  if (!isId("key", auditKeyId)) throw new CliError("ID_INVALID", "bad audit_key_id", 2);
  const auditKeyEnv = str("audit_key_env");
  if (!ENV_NAME.test(auditKeyEnv)) throw new CliError("SCHEMA_INVALID", "bad audit_key_env name", 2);

  const auth = c.auth;
  if (typeof auth !== "object" || auth === null) throw new CliError("SCHEMA_INVALID", "bad auth", 2);
  const a = auth as Record<string, unknown>;
  for (const k of Object.keys(a)) if (k !== "token_env" && k !== "roles") {
    throw new CliError("SCHEMA_INVALID", `unknown auth key: ${k}`, 2);
  }
  const tokenEnv = a.token_env;
  if (typeof tokenEnv !== "string" || !ENV_NAME.test(tokenEnv)) {
    throw new CliError("SCHEMA_INVALID", "bad auth.token_env", 2);
  }
  const roles = a.roles;
  if (!Array.isArray(roles) || roles.some((r) => r !== "read" && r !== "write" && r !== "admin")) {
    throw new CliError("SCHEMA_INVALID", "bad auth.roles", 2);
  }

  const retention = c.retention as Record<string, unknown>;
  const limits = c.limits as Record<string, unknown>;
  const observability = c.observability as Record<string, unknown>;
  const closed = (o: Record<string, unknown> | undefined, name: string, allowed: string[]) => {
    if (!o || typeof o !== "object") throw new CliError("SCHEMA_INVALID", `missing config section`, 2);
    for (const k of Object.keys(o)) {
      if (!allowed.includes(k)) throw new CliError("SCHEMA_INVALID", `unknown ${name} key: ${k}`, 2);
    }
  };
  closed(retention, "retention", ["stage_ttl_seconds", "history_revisions", "artifacts_days"]);
  closed(limits, "limits", ["stage_rows", "request_bytes", "path_nodes", "bundle_bytes"]);
  closed(observability, "observability", ["level", "metrics_socket"]);
  const num = (o: Record<string, unknown> | undefined, k: string, lo: number, hi: number): number => {
    if (!o || typeof o !== "object") throw new CliError("SCHEMA_INVALID", `missing config section`, 2);
    const x = o[k];
    if (typeof x !== "number" || !Number.isSafeInteger(x) || x < lo || x > hi) {
      throw new CliError("SCHEMA_INVALID", `bad ${k}`, 2);
    }
    return x;
  };
  const config: Config = {
    version: 1,
    workspace,
    database: str("database"),
    artifacts: str("artifacts"),
    audit_key_id: auditKeyId,
    audit_key_env: auditKeyEnv,
    bind: str("bind"),
    port: num(c, "port", 1, 65535),
    auth: { token_env: tokenEnv, roles: roles as Config["auth"]["roles"] },
    retention: {
      stage_ttl_seconds: num(retention, "stage_ttl_seconds", 60, 604800),
      history_revisions: num(retention, "history_revisions", 1, 10000),
      artifacts_days: num(retention, "artifacts_days", 1, 3650),
    },
    limits: {
      stage_rows: num(limits, "stage_rows", 1, 1000),
      request_bytes: num(limits, "request_bytes", 4096, 8 * 1024 * 1024),
      path_nodes: num(limits, "path_nodes", 1, 4096),
      bundle_bytes: num(limits, "bundle_bytes", 4096, 64 * 1024 * 1024),
    },
    observability: {
      level: (() => {
        const l = (observability as Record<string, unknown> | undefined)?.level;
        if (l !== "error" && l !== "warn" && l !== "info") {
          throw new CliError("SCHEMA_INVALID", "bad observability.level", 2);
        }
        return l;
      })(),
      metrics_socket: (() => {
        const s = (observability as Record<string, unknown> | undefined)?.metrics_socket;
        if (typeof s !== "string" || !s) throw new CliError("SCHEMA_INVALID", "bad metrics_socket", 2);
        return s;
      })(),
    },
    recovery_pin: str("recovery_pin"),
  };
  const dir = path.dirname(path.resolve(configPath));
  const res = (p: string): string => (path.isAbsolute(p) ? p : path.join(dir, p));
  return {
    config,
    dir,
    dbPath: res(config.database),
    artifactsDir: res(config.artifacts),
    pinPath: res(config.recovery_pin),
    metricsSocket: res(config.observability.metrics_socket),
    stateDir: path.dirname(res(config.database)),
  };
}

/** Resolve the audit keypair from the configured environment variable. */
export function auditKey(cfg: LoadedConfig): { key: KeyObject; public: string } {
  const seedHex = process.env[cfg.config.audit_key_env];
  if (seedHex === undefined) {
    throw new CliError("CONFIG_SECRET_MISSING", `${cfg.config.audit_key_env} is not set`, 2);
  }
  if (!/^[0-9a-f]{64}$/.test(seedHex)) {
    throw new CliError("CONFIG_SECRET_MISSING", `${cfg.config.audit_key_env} must be 64 lowercase hex chars`, 2);
  }
  if (FIXTURE_SEEDS.has(seedHex)) {
    throw new CliError("CONFIG_SECRET_MISSING", "fixture seeds are rejected in production", 2);
  }
  const key = privateKeyFromSeed(Buffer.from(seedHex, "hex"));
  return { key, public: publicKeyBytes(key).toString("base64url") };
}

/** Resolve the serve/remote bearer token from the configured env var. */
export function authToken(cfg: LoadedConfig): string {
  const t = process.env[cfg.config.auth.token_env];
  if (t === undefined) {
    throw new CliError("CONFIG_SECRET_MISSING", `${cfg.config.auth.token_env} is not set`, 2);
  }
  return t;
}

export function configHash(config: Config): string {
  return D("VL-CONFIG/1", config);
}
