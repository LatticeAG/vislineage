import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";
import { VLError } from "./errors.js";

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Ed25519 group order L; signatures with non-canonical S >= L are rejected. */
const L = 7237005577332262213976186563042994240857116359379907606001950938285454250989n;

const L_BYTES = (() => {
  const b = Buffer.alloc(32);
  let x = L;
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
})();

const P = 57896044618658097711785492504343953926634992332820282019728792003956564819949n;

/** The eight small-order Ed25519 point encodings (canonical form). */
const SMALL_ORDER = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445c13439c656b30da05f1560c9800",
  "e00000000000000000000000000000000000000000000000000000000000000000",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
].map((s) => Buffer.from(s, "hex").toString("base64url")));

/** Load an Ed25519 private key from a 32-byte seed. */
export function privateKeyFromSeed(seed: Buffer): KeyObject {
  if (seed.length !== 32) throw new VLError("SCHEMA_INVALID", null, "seed must be 32 bytes");
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
}

/** Raw 32-byte Ed25519 public key. */
export function publicKeyBytes(priv: KeyObject): Buffer {
  return Buffer.from(createPublicKey(priv).export({ format: "der", type: "spki" }).subarray(-32));
}

export function publicKeyFromBytes(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new VLError("SCHEMA_INVALID", null, "public key must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

function isCanonicalField(b: Buffer, modulus: bigint): boolean {
  // Interpret little-endian 32-byte value; reject values >= modulus.
  let x = 0n;
  for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(b[i]!);
  return x < modulus;
}

/**
 * Strict Ed25519 verification (ordinary Ed25519, not Ed25519ph):
 * rejects small-order public keys/R values and non-canonical S, then runs the
 * vetted OpenSSL-backed verifier.
 */
export function verifySignature(publicRawB64: string, message: Buffer, signatureB64: string): boolean {
  const pub = Buffer.from(publicRawB64, "base64url");
  const sig = Buffer.from(signatureB64, "base64url");
  if (pub.length !== 32 || sig.length !== 64) return false;
  if (SMALL_ORDER.has(publicRawB64)) return false;
  const r = sig.subarray(0, 32);
  const s = sig.subarray(32, 64);
  const rB64 = r.toString("base64url");
  if (SMALL_ORDER.has(rB64)) return false;
  // Reject non-canonical S (S >= L) and non-canonical public-key/R y-coords.
  let sv = 0n;
  for (let i = 31; i >= 0; i--) sv = (sv << 8n) | BigInt(s[i]!);
  if (sv >= L) return false;
  const yP = Buffer.from(pub);
  yP[31] = yP[31]! & 0x7f;
  const yR = Buffer.from(r);
  yR[31] = yR[31]! & 0x7f;
  if (!isCanonicalField(yP, P) || !isCanonicalField(yR, P)) return false;
  void L_BYTES;
  try {
    return edVerify(null, message, publicKeyFromBytes(pub), sig);
  } catch {
    return false;
  }
}

export function signMessage(priv: KeyObject, message: Buffer): string {
  return edSign(null, message, priv).toString("base64url");
}

/** Domain-separated signature message: UTF8(tag) || 0x00 || raw 32-byte digest. */
export function signPayload(tag: string, hashHex: string): Buffer {
  return Buffer.concat([Buffer.from(tag, "utf8"), Buffer.from([0]), Buffer.from(hashHex, "hex")]);
}
