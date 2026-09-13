import { VLError } from "./errors.js";

/**
 * Strict JSON text parser for vislineage/1.
 *
 * Enforces, before any object materialization: UTF-8 without BOM, duplicate
 * member rejection, lone-surrogate rejection, non-finite number rejection, and
 * the generic depth/member/element/byte parser caps (JSON_INVALID).
 * Number-domain policy is applied after structural parsing: "core" accepts
 * only safe integers 0..2^53-1 (SCHEMA_INVALID otherwise, including -0);
 * "vendor" accepts any finite binary64 (vendor payloads may contain floats).
 */

export interface ParseOptions {
  /** "core": only safe integers 0..2^53-1. "vendor": any finite binary64. */
  numbers: "core" | "vendor";
  maxDepth?: number; // default 32
  maxMembers?: number; // default 1024
  maxElements?: number; // default 4096
  /** Track source char spans of parsed values (for raw-row byte limits). */
  trackSpans?: boolean;
}

const spans = new WeakMap<object, [number, number]>();

/** Char-offset span [start,end) of a parsed value in its source text. */
export function spanOf(value: unknown): [number, number] | undefined {
  return typeof value === "object" && value !== null ? spans.get(value) : undefined;
}

const decoder = new TextDecoder("utf-8", { fatal: true });

export function parseJsonBytes(buf: Uint8Array, opts: ParseOptions): unknown {
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    throw new VLError("JSON_INVALID", null, "UTF-8 BOM");
  }
  let text: string;
  try {
    text = decoder.decode(buf);
  } catch {
    throw new VLError("JSON_INVALID", null, "invalid UTF-8");
  }
  return parseJsonText(text, opts);
}

const NUM_RE = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/;

class Parser {
  i = 0;
  constructor(
    private readonly text: string,
    private readonly opts: Required<Omit<ParseOptions, "numbers" | "trackSpans">>,
    private readonly track: boolean,
  ) {}
  private ws(): void {
    const t = this.text;
    while (this.i < t.length) {
      const c = t.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }
  private bad(msg: string): never {
    throw new VLError("JSON_INVALID", null, msg);
  }
  parse(): unknown {
    this.ws();
    const v = this.value(1);
    this.ws();
    if (this.i !== this.text.length) this.bad("trailing characters");
    return v;
  }
  private value(depth: number): unknown {
    if (this.i >= this.text.length) this.bad("unexpected end");
    const start = this.i;
    const c = this.text.charCodeAt(this.i);
    let out: unknown;
    if (c === 0x7b) out = this.object(depth);
    else if (c === 0x5b) out = this.array(depth);
    else if (c === 0x22) out = this.string();
    else if (c === 0x74) {
      this.lit("true");
      out = true;
    } else if (c === 0x66) {
      this.lit("false");
      out = false;
    } else if (c === 0x6e) {
      this.lit("null");
      out = null;
    } else if (c === 0x2d || (c >= 0x30 && c <= 0x39)) out = this.number();
    else this.bad("unexpected token");
    if (this.track && typeof out === "object" && out !== null) {
      spans.set(out, [start, this.i]);
    }
    return out;
  }
  private lit(s: string): void {
    if (this.text.startsWith(s, this.i)) this.i += s.length;
    else this.bad("bad literal");
  }
  private number(): number {
    const m = NUM_RE.exec(this.text.slice(this.i));
    if (!m) this.bad("bad number");
    this.i += m[0].length;
    const n = Number(m[0]);
    if (!Number.isFinite(n)) this.bad("non-finite number");
    return n;
  }
  private string(): string {
    const t = this.text;
    this.i++; // opening quote
    let out = "";
    for (;;) {
      if (this.i >= t.length) this.bad("unterminated string");
      const c = t.charCodeAt(this.i);
      if (c === 0x22) {
        this.i++;
        return out;
      }
      if (c === 0x5c) {
        this.i++;
        if (this.i >= t.length) this.bad("bad escape");
        const e = t.charCodeAt(this.i++);
        switch (e) {
          case 0x22:
            out += '"';
            break;
          case 0x5c:
            out += "\\";
            break;
          case 0x2f:
            out += "/";
            break;
          case 0x62:
            out += "\b";
            break;
          case 0x66:
            out += "\f";
            break;
          case 0x6e:
            out += "\n";
            break;
          case 0x72:
            out += "\r";
            break;
          case 0x74:
            out += "\t";
            break;
          case 0x75: {
            const h1 = this.hex4();
            if (h1 >= 0xd800 && h1 <= 0xdbff) {
              if (t.charCodeAt(this.i) !== 0x5c || t.charCodeAt(this.i + 1) !== 0x75) {
                this.bad("lone surrogate");
              }
              this.i += 2;
              const h2 = this.hex4();
              if (h2 < 0xdc00 || h2 > 0xdfff) this.bad("lone surrogate");
              out += String.fromCharCode(h1, h2);
            } else if (h1 >= 0xdc00 && h1 <= 0xdfff) {
              this.bad("lone surrogate");
            } else {
              out += String.fromCharCode(h1);
            }
            break;
          }
          default:
            this.bad("bad escape");
        }
        continue;
      }
      if (c < 0x20) this.bad("unescaped control");
      // UTF-8 decoding already rejected lone surrogates / invalid sequences.
      out += t[this.i++];
    }
  }
  private hex4(): number {
    const t = this.text;
    if (this.i + 4 > t.length) this.bad("bad \\u escape");
    let v = 0;
    for (let k = 0; k < 4; k++) {
      const c = t.charCodeAt(this.i++);
      v = v * 16 + (c <= 0x39 ? c - 0x30 : c <= 0x46 ? c - 0x37 : c <= 0x66 ? c - 0x57 : this.bad("bad \\u escape"));
    }
    return v;
  }
  private object(depth: number): Record<string, unknown> {
    if (depth > this.opts.maxDepth) this.bad("depth limit");
    this.i++; // {
    const keys = new Set<string>();
    const entries: [string, unknown][] = [];
    this.ws();
    if (this.text.charCodeAt(this.i) === 0x7d) {
      this.i++;
      return {};
    }
    for (;;) {
      this.ws();
      if (this.text.charCodeAt(this.i) !== 0x22) this.bad("expected member name");
      const k = this.string();
      if (keys.has(k)) this.bad("duplicate member");
      keys.add(k);
      this.ws();
      if (this.text.charCodeAt(this.i) !== 0x3a) this.bad("expected :");
      this.i++;
      this.ws();
      entries.push([k, this.value(depth + 1)]);
      if (entries.length > this.opts.maxMembers) this.bad("member limit");
      this.ws();
      const c = this.text.charCodeAt(this.i);
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x7d) {
        this.i++;
        return Object.fromEntries(entries);
      }
      this.bad("expected , or }");
    }
  }
  private array(depth: number): unknown[] {
    if (depth > this.opts.maxDepth) this.bad("depth limit");
    this.i++; // [
    const out: unknown[] = [];
    this.ws();
    if (this.text.charCodeAt(this.i) === 0x5d) {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value(depth + 1));
      if (out.length > this.opts.maxElements) this.bad("element limit");
      this.ws();
      const c = this.text.charCodeAt(this.i);
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x5d) {
        this.i++;
        return out;
      }
      this.bad("expected , or ]");
    }
  }
}

export function parseJsonText(text: string, opts: ParseOptions): unknown {
  const p = new Parser(
    text,
    {
      maxDepth: opts.maxDepth ?? 32,
      maxMembers: opts.maxMembers ?? 1024,
      maxElements: opts.maxElements ?? 4096,
    },
    opts.trackSpans ?? false,
  );
  const v = p.parse();
  if (opts.numbers === "core") checkCoreNumbers(v, "");
  return v;
}

/** Core positions permit only safe integers 0..9007199254740991. */
export function checkCoreNumbers(v: unknown, path: string): void {
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || v < 0 || Object.is(v, -0)) {
      throw new VLError("SCHEMA_INVALID", path || null, "number outside core domain");
    }
    return;
  }
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) checkCoreNumbers(v[i], `${path}/${i}`);
    return;
  }
  if (typeof v === "object" && v !== null) {
    for (const [k, x] of Object.entries(v)) checkCoreNumbers(x, `${path}/${escPtr(k)}`);
  }
}

export function escPtr(k: string): string {
  return k.replace(/~/g, "~0").replace(/\//g, "~1");
}
