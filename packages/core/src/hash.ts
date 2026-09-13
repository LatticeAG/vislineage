import { createHash } from "node:crypto";
import { J } from "./jcs.js";
import { VLError } from "./errors.js";

export const ZERO = "0".repeat(64);

/** H(b): lowercase SHA-256 hex of bytes. */
export function H(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
}

/** D(tag,x) = H(UTF8(tag) || 0x00 || J(x)). */
export function D(tag: string, x: unknown): string {
  return H(Buffer.concat([Buffer.from(tag, "utf8"), Buffer.from([0]), J(x)]));
}

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

/** Strict unpadded base64url decode; requires canonical round-trip and exact length. */
export function b64urlDecode(s: string, expectedBytes: number, field: string | null = null): Buffer {
  if (typeof s !== "string" || s.length === 0 || !B64URL_RE.test(s) || s.includes("=")) {
    throw new VLError("SCHEMA_INVALID", field, "invalid base64url");
  }
  const b = Buffer.from(s, "base64url");
  if (b.length !== expectedBytes || b.toString("base64url") !== s) {
    throw new VLError("SCHEMA_INVALID", field, "non-canonical base64url");
  }
  return b;
}

export function b64urlEncode(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

const HEX64_RE = /^[0-9a-f]{64}$/;

/** Strict lowercase hex Hash check. */
export function isHash(s: unknown): s is string {
  return typeof s === "string" && HEX64_RE.test(s);
}

export function requireHash(s: unknown, field: string): asserts s is string {
  if (!isHash(s)) throw new VLError("SCHEMA_INVALID", field, "expected lowercase 64-hex hash");
}

const B64URL_32 = /^[A-Za-z0-9_-]{43}$/;
const B64URL_64 = /^[A-Za-z0-9_-]{86}$/;

export function isPublicKey(s: unknown): s is string {
  return typeof s === "string" && B64URL_32.test(s) && b64len(s, 32);
}
export function isSignature(s: unknown): s is string {
  return typeof s === "string" && B64URL_64.test(s) && b64len(s, 64);
}
function b64len(s: string, n: number): boolean {
  try {
    return Buffer.from(s, "base64url").length === n && Buffer.from(s, "base64url").toString("base64url") === s;
  } catch {
    return false;
  }
}
