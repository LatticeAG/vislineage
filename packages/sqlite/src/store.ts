import { DatabaseSync } from "node:sqlite";
import * as fs from "node:fs";
import * as path from "node:path";
import { VLError, isHash, ZERO, type ExternalHead } from "@latticeag/vislineage-core";

export const SCHEMA_SQL = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, body BLOB NOT NULL UNIQUE) STRICT;
CREATE TABLE IF NOT EXISTS traces (id TEXT PRIMARY KEY, revision INTEGER NOT NULL, graph TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS native_traces (source TEXT NOT NULL REFERENCES sources(id), native TEXT NOT NULL, trace TEXT NOT NULL REFERENCES traces(id), PRIMARY KEY(source,native)) STRICT;
CREATE TABLE IF NOT EXISTS steps (hash TEXT PRIMARY KEY, source TEXT NOT NULL REFERENCES sources(id), record TEXT NOT NULL, trace TEXT NOT NULL REFERENCES traces(id), native_trace TEXT NOT NULL, native_span TEXT NOT NULL, body BLOB NOT NULL) STRICT;
CREATE INDEX IF NOT EXISTS steps_record ON steps(source,record);
CREATE INDEX IF NOT EXISTS steps_span ON steps(source,native_trace,native_span);
CREATE TABLE IF NOT EXISTS origins (digest TEXT PRIMARY KEY, hash TEXT NOT NULL, source TEXT NOT NULL REFERENCES sources(id), stream TEXT NOT NULL, seq INTEGER NOT NULL, step TEXT NOT NULL, envelope BLOB NOT NULL) STRICT;
CREATE INDEX IF NOT EXISTS origins_slot ON origins(source,stream,seq);
CREATE INDEX IF NOT EXISTS origins_step ON origins(step);
CREATE TABLE IF NOT EXISTS imports (id TEXT PRIMARY KEY, trace TEXT NOT NULL REFERENCES traces(id), state TEXT NOT NULL CHECK(state IN ('STAGED','COMMITTED','CANCELLED')), batch TEXT NOT NULL, staged BLOB, stage_result BLOB NOT NULL, expires_at INTEGER NOT NULL, result BLOB) STRICT;
CREATE INDEX IF NOT EXISTS imports_expiry ON imports(state,expires_at);
CREATE TABLE IF NOT EXISTS revisions (trace TEXT NOT NULL REFERENCES traces(id), revision INTEGER NOT NULL, graph TEXT NOT NULL, manifest BLOB, audit_seq INTEGER NOT NULL REFERENCES audit(seq), pruned INTEGER NOT NULL CHECK(pruned IN (0,1)), PRIMARY KEY(trace,revision)) STRICT;
CREATE TABLE IF NOT EXISTS revision_steps (trace TEXT NOT NULL, revision INTEGER NOT NULL, hash TEXT NOT NULL REFERENCES steps(hash), PRIMARY KEY(trace,revision,hash), FOREIGN KEY(trace,revision) REFERENCES revisions(trace,revision)) STRICT;
CREATE TABLE IF NOT EXISTS revision_origins (trace TEXT NOT NULL, revision INTEGER NOT NULL, digest TEXT NOT NULL REFERENCES origins(digest), PRIMARY KEY(trace,revision,digest), FOREIGN KEY(trace,revision) REFERENCES revisions(trace,revision)) STRICT;
CREATE TABLE IF NOT EXISTS edges (trace TEXT NOT NULL, revision INTEGER NOT NULL, hash TEXT NOT NULL, parent TEXT NOT NULL, child TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY(trace,revision,hash), FOREIGN KEY(trace,revision) REFERENCES revisions(trace,revision)) STRICT;
CREATE INDEX IF NOT EXISTS edges_child ON edges(trace,revision,child);
CREATE TABLE IF NOT EXISTS artifacts (digest TEXT PRIMARY KEY, format TEXT NOT NULL, bytes INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('AVAILABLE','PRUNED')), relative_path TEXT, created_at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, envelope BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS idempotency (id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, response BLOB NOT NULL, audit_seq INTEGER NOT NULL REFERENCES audit(seq)) STRICT;
CREATE TABLE IF NOT EXISTS leases (id TEXT PRIMARY KEY, trace TEXT NOT NULL, revision INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;
`;

export const SCHEMA_VERSION = 1;

export interface Opened {
  db: DatabaseSync;
  workspace: string;
  /** release the writer lock */
  close(): void;
}

/**
 * Single-writer workspace lock: a lock file carrying the owner pid. A live
 * owner causes failure; a dead owner's lock is reclaimed.
 */
export function acquireWriterLock(stateDir: string): () => void {
  const lockPath = path.join(stateDir, "writer.lock");
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  for (;;) {
    try {
      const fd = fs.openSync(lockPath, "wx", 0o600);
      fs.writeSync(fd, String(process.pid));
      fs.closeSync(fd);
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      let pid = 0;
      try {
        pid = Number(fs.readFileSync(lockPath, "utf8").trim());
      } catch {
        /* unreadable lock file */
      }
      if (pid > 0) {
        try {
          process.kill(pid, 0);
          throw new VLError("BUSY", null, "workspace writer lock is held");
        } catch (ke) {
          if ((ke as NodeJS.ErrnoException).code === "ESRCH") {
            fs.rmSync(lockPath, { force: true });
            continue;
          }
          if (ke instanceof VLError) throw ke;
          // EPERM: process exists under another user → treat as held
          throw new VLError("BUSY", null, "workspace writer lock is held");
        }
      } else {
        fs.rmSync(lockPath, { force: true });
      }
    }
  }
  return () => {
    try {
      fs.rmSync(lockPath, { force: true });
    } catch {
      /* already gone */
    }
  };
}

export function openDb(dbPath: string, workspace: string): DatabaseSync {
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA synchronous = FULL;");
  db.exec("PRAGMA busy_timeout = 5000;");
  return db;
}

export function dbMeta(db: DatabaseSync, key: string): string | undefined {
  const row = db.prepare("SELECT value FROM meta WHERE key=?").get(key) as { value: Buffer } | undefined;
  return row ? Buffer.from(row.value).toString("utf8") : undefined;
}

export function setMeta(db: DatabaseSync, key: string, value: string): void {
  db.prepare("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(
    key,
    Buffer.from(value, "utf8"),
  );
}

/** Verify the DB belongs to this workspace and schema versions agree. */
export function checkMeta(db: DatabaseSync, workspace: string): void {
  const ws = dbMeta(db, "workspace");
  const schema = dbMeta(db, "schema");
  const uvRow = db.prepare("PRAGMA user_version").get() as { user_version: number } | undefined;
  const uv = Number(uvRow?.user_version ?? 0);
  if (ws !== workspace) throw new VLError("STORAGE_UNAVAILABLE", null, "workspace id mismatch");
  if (schema !== String(SCHEMA_VERSION) || uv !== SCHEMA_VERSION) {
    throw new VLError("READ_ONLY", null, "schema version mismatch");
  }
}

export function initDb(dbPath: string, workspace: string): DatabaseSync {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });
  const db = openDb(dbPath, workspace);
  db.exec(SCHEMA_SQL);
  setMeta(db, "workspace", workspace);
  setMeta(db, "schema", String(SCHEMA_VERSION));
  db.exec(`PRAGMA user_version = ${SCHEMA_VERSION};`);
  return db;
}

export function auditHead(db: DatabaseSync): { seq: bigint; hash: string } | null {
  const row = db.prepare("SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1").get() as
    | { seq: number | bigint; hash: string }
    | undefined;
  if (!row) return null;
  return { seq: BigInt(row.seq), hash: row.hash };
}

export function auditAt(db: DatabaseSync, seq: bigint): { hash: string } | null {
  const row = db.prepare("SELECT hash FROM audit WHERE seq=?").get(seq) as { hash: string } | undefined;
  return row ?? null;
}

export interface ReconcileResult {
  state: "READY" | "READ_ONLY";
  reason: string | null;
}

/** §11.3 startup reconciliation of the external recovery pin. */
export function reconcilePin(db: DatabaseSync, pinPath: string): ReconcileResult {
  const head = auditHead(db);
  if (!head) return { state: "READ_ONLY", reason: "NO_AUDIT" };
  let raw: string;
  try {
    raw = fs.readFileSync(pinPath, "utf8");
  } catch {
    return { state: "READ_ONLY", reason: "PIN_MISSING" };
  }
  let pin: ExternalHead;
  try {
    pin = JSON.parse(raw) as ExternalHead;
  } catch {
    return { state: "READ_ONLY", reason: "PIN_MISSING" };
  }
  if (pin.v !== 1 || typeof pin.seq !== "string" || !isHash(pin.hash)) {
    return { state: "READ_ONLY", reason: "PIN_MISSING" };
  }
  const pinSeq = BigInt(pin.seq);
  if (pinSeq > head.seq) return { state: "READ_ONLY", reason: "PIN_AHEAD" };
  const slot = auditAt(db, pinSeq);
  if (!slot) return { state: "READ_ONLY", reason: "PIN_AHEAD" };
  if (slot.hash !== pin.hash) return { state: "READ_ONLY", reason: "AUDIT_FORK" };
  return { state: "READY", reason: null };
}

/** Storage-pressure check against the filesystem holding dir (§11.3). */
export function storagePressure(dir: string): number {
  try {
    const st = fs.statfsSync(dir);
    if (st.blocks === 0) return 0;
    return 1 - Number(st.bavail) / Number(st.blocks);
  } catch {
    return 0;
  }
}

export function artifactPath(artifactsDir: string, digest: string): string {
  return path.join(artifactsDir, digest.slice(0, 2), digest.slice(2));
}

/** Write artifact bytes: temp → fsync → rename → fsync parent (§11.2). */
export function writeArtifactFile(artifactsDir: string, digest: string, bytes: Buffer): string {
  const rel = path.join(digest.slice(0, 2), digest.slice(2));
  const abs = path.join(artifactsDir, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true, mode: 0o700 });
  if (fs.existsSync(abs)) return rel; // verified by caller against digest
  const tmp = `${abs}.tmp-${process.pid}-${Math.floor(Math.random() * 1e9)}`;
  const fd = fs.openSync(tmp, "wx", 0o600);
  try {
    fs.writeSync(fd, bytes);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, abs);
  const dfd = fs.openSync(path.dirname(abs), "r");
  try {
    fs.fsyncSync(dfd);
  } finally {
    fs.closeSync(dfd);
  }
  return rel;
}

export function withTx<T>(db: DatabaseSync, fn: () => T): T {
  db.exec("BEGIN IMMEDIATE;");
  try {
    const r = fn();
    db.exec("COMMIT;");
    return r;
  } catch (e) {
    try {
      db.exec("ROLLBACK;");
    } catch {
      /* already rolled back */
    }
    throw e;
  }
}

export { ZERO };
