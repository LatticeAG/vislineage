import * as http from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import * as net from "node:net";
import * as fs from "node:fs";
import {
  J,
  VLError,
  parseJsonBytes,
  isId,
} from "@latticeag/vislineage-core";
import {
  WorkspaceService,
  type Credential,
  type Role,
  type RpcFailureObj,
  type RpcSuccess,
} from "@latticeag/vislineage-sqlite";

const HTTP_STATUS: Record<string, number> = {
  JSON_INVALID: 400,
  SCHEMA_INVALID: 400,
  PROFILE_MISMATCH: 400,
  METHOD_UNKNOWN: 400,
  ID_INVALID: 400,
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  SOURCE_CONFLICT: 409,
  TRACE_MISMATCH: 409,
  IDEMPOTENCY_CONFLICT: 409,
  IMPORT_STATE: 409,
  REVISION_CONFLICT: 409,
  ACTION_CONFLICT: 409,
  IMPORT_CONFLICT: 409,
  ARTIFACT_FORMAT_CONFLICT: 409,
  REVISION_PRUNED: 410,
  ARTIFACT_UNAVAILABLE: 410,
  BODY_LIMIT: 413,
  ROW_LIMIT: 413,
  PATH_LIMIT: 413,
  BUNDLE_LIMIT: 413,
  TRACE_LIMIT: 413,
  HASH_MISMATCH: 422,
  ARTIFACT_UNREFERENCED: 422,
  ORIGIN_UNREFERENCED: 422,
  TRUST_INVALID: 422,
  UNSUPPORTED_VERSION: 422,
  RATE_LIMIT: 429,
  BUSY: 503,
  STORAGE_UNAVAILABLE: 503,
  READ_ONLY: 503,
};

function httpStatus(code: string): number {
  return HTTP_STATUS[code] ?? 500;
}

interface Bucket {
  tokens: number;
  last: number;
}

/** Per-credential token bucket: 60 tokens, 1/s; bundle.verify costs 10. */
export class RateLimiter {
  private buckets = new Map<string, Bucket>();
  admit(credentialKey: string, cost: number): boolean {
    const now = Date.now() / 1000;
    let b = this.buckets.get(credentialKey);
    if (!b) {
      b = { tokens: 60, last: now };
      this.buckets.set(credentialKey, b);
    }
    b.tokens = Math.min(60, b.tokens + (now - b.last));
    b.last = now;
    if (b.tokens < cost) return false;
    b.tokens -= cost;
    return true;
  }
}

/** Metrics sink: newline "name value" samples on a mode-0600 unix socket. */
export class MetricsSink {
  private counts = new Map<string, number>();
  constructor(private socketPath: string | null) {}
  inc(name: string): void {
    this.counts.set(name, (this.counts.get(name) ?? 0) + 1);
  }
  set(name: string, v: number): void {
    this.counts.set(name, v);
  }
  /** Start a tiny admin-only unix socket that dumps samples on connect. */
  start(): net.Server | null {
    if (!this.socketPath) return null;
    try {
      fs.rmSync(this.socketPath, { force: true });
      const srv = net.createServer((conn) => {
        let out = "";
        for (const [k, v] of [...this.counts.entries()].sort()) out += `${k} ${v}\n`;
        conn.end(out);
      });
      srv.listen(this.socketPath, () => {
        fs.chmodSync(this.socketPath!, 0o600);
      });
      return srv;
    } catch {
      return null;
    }
  }
}

export interface ServeOptions {
  svc: WorkspaceService;
  bind: string;
  port: number;
  /** token → roles resolution (local: one configured credential) */
  resolveToken: (token: string) => Credential | null;
  requestBytes: number;
  bundleBytes: number;
  metricsSocket: string | null;
  log?: (level: string, event: string, request: string | null, code: string | null, ms: number) => void;
}

function tokenKey(token: string): string {
  return createHash("sha256").update(token).digest("hex").slice(0, 16);
}

export function serve(o: ServeOptions): http.Server {
  const limiter = new RateLimiter();
  const metrics = new MetricsSink(o.metricsSocket);
  metrics.start();
  let writerQueue = 0;
  let readers = 0;
  metrics.set("recovery_read_only", o.svc.state === "READ_ONLY" ? 1 : 0);

  const server = http.createServer((req, res) => {
    const send = (status: number, obj: unknown, headers: Record<string, string> = {}): void => {
      const body = J(obj);
      res.writeHead(status, { "content-type": "application/json", "content-length": String(body.length), ...headers });
      res.end(body);
    };
    const u = new URL(req.url ?? "/", "http://localhost");
    if (u.pathname === "/healthz") {
      if (o.svc.state === "READY") {
        send(200, { status: "ready", protocol: "vislineage/1" });
      } else {
        send(503, { status: "unavailable", protocol: "vislineage/1" });
      }
      return;
    }
    if (u.pathname !== "/v1/rpc") {
      send(404, { id: null, ok: false, error: { code: "NOT_FOUND", retryable: false, details: { field: null } } });
      return;
    }
    if (req.method === "OPTIONS") {
      res.writeHead(405, { allow: "POST" });
      res.end();
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405, { allow: "POST" });
      res.end();
      return;
    }
    const ct = (req.headers["content-type"] ?? "").split(";")[0]?.trim();
    const ce = req.headers["content-encoding"];
    if (ct !== "application/json" || (ce !== undefined && ce !== "identity")) {
      send(400, {
        id: null,
        ok: false,
        error: { code: "JSON_INVALID", retryable: false, details: { field: null } },
      });
      return;
    }
    // authentication
    const auth = req.headers.authorization;
    let cred: Credential | null = null;
    if (typeof auth === "string" && auth.startsWith("Bearer ")) {
      const presented = auth.slice(7);
      cred = o.resolveToken(presented);
    }
    const credKey = cred ? tokenKey(auth!.slice(7)) : "anonymous";

    const chunks: Buffer[] = [];
    let total = 0;
    let overflow = false;
    const hardCap = Math.max(o.requestBytes, o.bundleBytes + 4 * 1024 * 1024);
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > hardCap) {
        overflow = true;
        req.destroy();
      } else {
        chunks.push(c);
      }
    });
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      let parsed: unknown;
      try {
        parsed = overflow ? null : parseJsonBytes(body, { numbers: "core" });
      } catch (e) {
        const code = e instanceof VLError ? e.code : "JSON_INVALID";
        send(httpStatus(code), {
          id: null,
          ok: false,
          error: { code, retryable: false, details: { field: null } },
        });
        return;
      }
      // method peek for rate cost + body cap (before dispatch)
      const method =
        typeof parsed === "object" && parsed !== null
          ? String((parsed as Record<string, unknown>).method)
          : "";
      const methodCap = method === "bundle.verify" ? o.bundleBytes + 4 * 1024 * 1024 : o.requestBytes;
      if (total > methodCap) {
        send(413, {
          id: typeof parsed === "object" && parsed !== null && isId("request", (parsed as { id?: unknown }).id) ? (parsed as { id: string }).id : null,
          ok: false,
          error: { code: "BODY_LIMIT", retryable: false, details: { field: null } },
        });
        return;
      }
      const cost = method === "bundle.verify" ? 10 : 1;
      if (!limiter.admit(credKey, cost)) {
        send(
          429,
          {
            id: typeof parsed === "object" && parsed !== null && isId("request", (parsed as { id?: unknown }).id) ? (parsed as { id: string }).id : null,
            ok: false,
            error: { code: "RATE_LIMIT", retryable: true, details: { field: null } },
          },
          { "retry-after": "1" },
        );
        return;
      }
      const isWrite =
        cred !== null &&
        ["import.stage", "import.commit", "import.cancel", "source.register", "trace.create"].includes(method);
      if (isWrite && writerQueue >= 16) {
        send(503, {
          id: null,
          ok: false,
          error: { code: "BUSY", retryable: true, details: { field: null } },
        });
        return;
      }
      if (!isWrite && readers >= 4) {
        send(503, {
          id: null,
          ok: false,
          error: { code: "BUSY", retryable: true, details: { field: null } },
        });
        return;
      }
      if (isWrite) writerQueue++;
      else readers++;
      metrics.set("writer_queue_depth", writerQueue);
      const deadline = setTimeout(() => {
        // deadline expiry before commit → BUSY (a possibly-committed
        // disconnected call is retried idempotently by the client)
        if (!res.writableEnded) {
          send(503, {
            id: null,
            ok: false,
            error: { code: "BUSY", retryable: true, details: { field: null } },
          });
        }
      }, 30_000);
      try {
        const out = o.svc.dispatch(parsed, cred);
        clearTimeout(deadline);
        if (!out.ok) {
          metrics.inc("rpc_denied_total");
          if (out.error.code === "UNAUTHENTICATED" || out.error.code === "FORBIDDEN") {
            metrics.inc("rpc_denied_total");
          }
        }
        send(out.ok ? 200 : httpStatus(out.error.code), out);
      } finally {
        clearTimeout(deadline);
        if (isWrite) writerQueue--;
        else readers--;
        metrics.set("writer_queue_depth", writerQueue);
      }
    });
    req.on("error", () => {
      /* client vanished */
    });
  });
  return server;
}
