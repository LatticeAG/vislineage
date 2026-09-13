import { randomBytes } from "node:crypto";

/** nanoid alphabet and 21-character suffix per spec §3.1. */
export const ALPHABET = "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
export const ID_SUFFIX_LEN = 21;

export const PREFIX = {
  workspace: "vlw_",
  source: "vls_",
  trace: "vlt_",
  import: "vli_",
  request: "vlq_",
  delegation: "vld_",
  key: "vlk_",
} as const;

export type IdPrefix = keyof typeof PREFIX;

const ALPHABET_SET = new Set(ALPHABET.split(""));

/** CSPRNG-generated protocol identifier: locked prefix + 21 alphabet chars. */
export function genId(kind: IdPrefix): string {
  const prefix = PREFIX[kind];
  const bytes = randomBytes(ID_SUFFIX_LEN); // 64-char alphabet divides 256 evenly
  let out = prefix;
  for (let i = 0; i < ID_SUFFIX_LEN; i++) out += ALPHABET[bytes[i]! & 0x3f];
  return out;
}

export function isId(kind: IdPrefix, value: unknown): value is string {
  if (typeof value !== "string") return false;
  const prefix = PREFIX[kind];
  if (!value.startsWith(prefix)) return false;
  const suffix = value.slice(prefix.length);
  if (suffix.length !== ID_SUFFIX_LEN) return false;
  for (const ch of suffix) if (!ALPHABET_SET.has(ch)) return false;
  return true;
}
