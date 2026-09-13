import canonicalizePkg from "canonicalize";
import { VLError } from "./errors.js";

const canonicalize = canonicalizePkg as unknown as (v: unknown) => string | undefined;

/**
 * J(x): RFC 8785 canonical UTF-8 bytes. Uses the vetted `canonicalize`
 * reference implementation (JCS applies ECMAScript number serialization and
 * UTF-16 key ordering; no Unicode normalization is ever performed).
 */
export function J(x: unknown): Buffer {
  const s = canonicalize(x);
  if (s === undefined) throw new VLError("SCHEMA_INVALID", null, "value is not JCS-serializable");
  return Buffer.from(s, "utf8");
}

/** Compare canonical JCS bytes of two values (deterministic ordering). */
export function jcsCmp(a: unknown, b: unknown): number {
  return Buffer.compare(J(a), J(b));
}

export function hexCmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
