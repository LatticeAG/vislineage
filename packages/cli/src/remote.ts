import { J } from "@latticeag/vislineage-core";
import { CliError } from "./config.js";

/**
 * Remote RPC client for --remote URL. Requires HTTPS unless the target is a
 * loopback host. The bearer token comes only from the configured env var.
 */
export async function remoteCall(
  baseUrl: string,
  token: string,
  request: { id: string; method: string; params: unknown },
): Promise<{ id: string | null; ok: boolean; result?: unknown; error?: { code: string; retryable: boolean; details: { field: string | null } } }> {
  let u: URL;
  try {
    u = new URL(baseUrl);
  } catch {
    throw new CliError("SCHEMA_INVALID", "invalid --remote URL", 2);
  }
  const loopback = ["127.0.0.1", "::1", "localhost"].includes(u.hostname);
  if (u.protocol !== "https:" && !loopback) {
    throw new CliError("SCHEMA_INVALID", "--remote requires HTTPS unless loopback", 2);
  }
  const endpoint = new URL("/v1/rpc", u);
  const body = J(request);
  let resp: Response;
  try {
    resp = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body,
      redirect: "error",
    });
  } catch {
    throw new CliError("BUSY", "remote endpoint unreachable", 7);
  }
  let out: unknown;
  try {
    out = await resp.json();
  } catch {
    throw new CliError("JSON_INVALID", "remote returned non-JSON", 2);
  }
  return out as { id: string | null; ok: boolean; result?: unknown; error?: { code: string; retryable: boolean; details: { field: string | null } } };
}
