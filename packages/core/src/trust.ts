import { verifySignature, signPayload } from "./crypto.js";
import { ZERO } from "./hash.js";
import type { Audit, HeadPin, KeyPin, Origin, TrustPackage } from "./types.js";

/**
 * Scoped-pin trust evaluation (§7). Pure; no clocks, no "latest key wins".
 * Chain structure derives from bodies/links only; signatures and pins decide
 * trust attribution, never graph structure.
 */

export interface Signed {
  body: { source: string | null; stream: string | null; seq: string; prev: string; key: string };
  hash: string;
  signature: string;
}

export function signedOfOrigin(o: Origin): Signed {
  return o as unknown as Signed;
}

export function signedOfAudit(a: Audit): Signed {
  return {
    body: { source: null, stream: null, seq: a.body.seq, prev: a.body.prev, key: a.body.key },
    hash: a.hash,
    signature: a.signature,
  };
}

export interface ChainEval {
  integrity: "VALID" | "INVALID";
  verdict: "TRUSTED_AT_PIN" | "UNSIGNED" | "UNTRUSTED" | "INCOMPLETE" | "CONFLICTED";
  reasons: string[];
}

function streamOf(role: "origin" | "audit", e: Signed): string {
  return role === "origin" ? `${e.body.source} ${e.body.stream}` : "audit";
}

/** Structural slots for one stream: seq → distinct body hashes, and prev per hash. */
function slots(list: Signed[]): Map<bigint, Map<string, string>> {
  const m = new Map<bigint, Map<string, string>>();
  for (const e of list) {
    const seq = BigInt(e.body.seq);
    let s = m.get(seq);
    if (!s) {
      s = new Map();
      m.set(seq, s);
    }
    s.set(e.hash, e.body.prev);
  }
  return m;
}

/**
 * Evaluate chains for one role over the supplied envelopes.
 * requiredSteps (origin only): step hashes needing ≥1 fully verified
 * attestation. Pass null for the audit role.
 * stepOf: envelope → attested step hash (audit: null).
 */
export function evalChains(
  role: "origin" | "audit",
  envelopes: Signed[],
  requiredSteps: Set<string> | null,
  stepOf: (e: Signed) => string | null,
  trust: TrustPackage,
): ChainEval {
  const reasons = new Set<string>();
  let integrity: "VALID" | "INVALID" = "VALID";
  const covered = new Set<string>();
  const explained = new Set<string>();

  const keyPins = new Map<string, KeyPin[]>();
  for (const k of trust.keys) {
    const l = keyPins.get(k.id) ?? [];
    l.push(k);
    keyPins.set(k.id, l);
  }
  const heads = trust.heads.filter((h) => h.role === role);

  const streams = new Map<string, Signed[]>();
  for (const e of envelopes) {
    const k = streamOf(role, e);
    const l = streams.get(k) ?? [];
    l.push(e);
    streams.set(k, l);
  }

  for (const [, list] of streams) {
    const slotMap = slots(list);
    const seqs = [...slotMap.keys()].sort((a, b) => (a < b ? -1 : 1));
    const earliest = seqs[0]!;
    const latest = seqs[seqs.length - 1]!;
    const src = list[0]!.body.source;
    const stm = list[0]!.body.stream;
    const streamHeads = heads.filter((h) => h.source === src && h.stream === stm);
    const headAt = new Map<bigint, HeadPin>();
    for (const h of streamHeads) headAt.set(BigInt(h.seq), h);

    // --- structural findings -------------------------------------------
    // broken link: supplied position n>1 whose prev matches no hash at n-1,
    // or earliest position > 1 (incomplete prefix).
    const isBroken = (e: Signed): boolean => {
      const seq = BigInt(e.body.seq);
      if (seq === 1n) return e.body.prev !== ZERO;
      const prevSlot = slotMap.get(seq - 1n);
      return !prevSlot || !prevSlot.has(e.body.prev);
    };
    const anchorCovered = (e: Signed): boolean => {
      const pin = headAt.get(BigInt(e.body.seq) - 1n);
      return pin !== undefined && pin.hash === e.body.prev;
    };
    let anyUnanchoredBreak = false;
    for (const e of list) {
      if (isBroken(e) && !anchorCovered(e)) anyUnanchoredBreak = true;
    }
    if (anyUnanchoredBreak) reasons.add(role === "origin" ? "ORIGIN_GAP" : "AUDIT_GAP");

    // fork slots: ≥2 distinct body hashes at one position
    let anyFork = false;
    for (const [, h] of slotMap) if (h.size >= 2) anyFork = true;
    if (anyFork) reasons.add(role === "origin" ? "ORIGIN_FORK" : "AUDIT_FORK");

    // head pins
    for (const h of streamHeads) {
      const seq = BigInt(h.seq);
      if (seq < earliest) {
        if (seq === earliest - 1n) {
          // immediate-predecessor anchor: mismatch → PIN_MISMATCH
          const prevs = new Set((slotMap.get(earliest) ?? new Map()).values());
          if (!prevs.has(h.hash)) reasons.add("PIN_MISMATCH");
        }
        continue; // below-earliest non-anchor pins do not participate
      }
      const slot = slotMap.get(seq);
      if (slot) {
        if (!slot.has(h.hash)) reasons.add("PIN_MISMATCH");
      } else {
        // supplied history never reaches this pin
        reasons.add("PIN_AHEAD");
      }
    }
    void latest;

    // --- anchoring (recursive over links + anchor pins) -----------------
    const envs = new Map<string, Signed[]>(); // "seq hash" -> envs
    for (const e of list) {
      const k = `${e.body.seq} ${e.hash}`;
      const l = envs.get(k) ?? [];
      l.push(e);
      envs.set(k, l);
    }
    const memo = new Map<Signed, boolean>();
    const anchored = (e: Signed): boolean => {
      const m = memo.get(e);
      if (m !== undefined) return m;
      memo.set(e, false);
      const seq = BigInt(e.body.seq);
      let ok: boolean;
      if (seq === 1n) {
        ok = e.body.prev === ZERO;
      } else {
        const pin = headAt.get(seq - 1n);
        if (pin !== undefined && pin.hash === e.body.prev) {
          ok = true;
        } else {
          const prevSlot = slotMap.get(seq - 1n);
          ok = false;
          if (prevSlot && prevSlot.has(e.body.prev)) {
            for (const p of envs.get(`${seq - 1n} ${e.body.prev}`) ?? []) {
              if (anchored(p)) {
                ok = true;
                break;
              }
            }
          }
        }
      }
      memo.set(e, ok);
      return ok;
    };

    // --- signature + pin scope per envelope -----------------------------
    for (const e of list) {
      const stepHash = stepOf(e);
      const fail = (reason: string) => {
        reasons.add(reason);
        if (stepHash) explained.add(stepHash);
      };
      const pins = keyPins.get(e.body.key);
      const rolePins = (pins ?? []).filter((p) => p.role === role);
      const scoped = rolePins.filter((p) => p.source === e.body.source && p.stream === e.body.stream);
      if (!pins || pins.length === 0 || rolePins.length === 0) {
        fail(role === "origin" ? "ORIGIN_KEY_UNKNOWN" : "AUDIT_KEY_UNKNOWN");
        continue;
      }
      if (scoped.length === 0) {
        fail(role === "origin" ? "ORIGIN_SCOPE_MISMATCH" : "AUDIT_SCOPE_MISMATCH");
        continue;
      }
      const covering = scoped.filter(
        (p) => BigInt(p.first_seq) <= BigInt(e.body.seq) && BigInt(e.body.seq) <= BigInt(p.last_seq),
      );
      if (covering.length === 0) {
        fail(role === "origin" ? "ORIGIN_KEY_UNKNOWN" : "AUDIT_KEY_UNKNOWN");
        continue;
      }
      if (covering.some((p) => p.status === "COMPROMISED")) {
        fail("KEY_COMPROMISED");
        continue;
      }
      const msg = signPayload(role === "origin" ? "VL-ORIGIN-SIGN/1" : "VL-AUDIT-SIGN/1", e.hash);
      const ok = covering.some((p) => verifySignature(p.public, msg, e.signature));
      if (!ok) {
        fail("SIGNATURE_INVALID");
        integrity = "INVALID";
        continue;
      }
      if (anchored(e)) {
        if (stepHash) covered.add(stepHash);
      } else {
        if (stepHash) explained.add(stepHash);
      }
    }
  }

  // coverage (only meaningful when records exist — zero records is UNSIGNED)
  if (requiredSteps && envelopes.length > 0) {
    for (const s of requiredSteps) {
      if (!covered.has(s) && !explained.has(s)) {
        reasons.add("ORIGIN_COVERAGE_MISSING");
        break;
      }
    }
  }

  // Combine in the spec's precedence order: conflict → untrusted →
  // incomplete → unsigned → trusted. The audit dimension has no CONFLICTED
  // value: audit fork/mismatch map to UNTRUSTED (§7).
  const has = (...rs: string[]) => rs.some((r) => reasons.has(r));
  let verdict: ChainEval["verdict"];
  if (role === "origin" && has("ORIGIN_FORK", "PIN_MISMATCH")) verdict = "CONFLICTED";
  else if (
    has(
      "AUDIT_FORK",
      "PIN_MISMATCH",
      "SIGNATURE_INVALID",
      "ORIGIN_KEY_UNKNOWN",
      "AUDIT_KEY_UNKNOWN",
      "ORIGIN_SCOPE_MISMATCH",
      "AUDIT_SCOPE_MISMATCH",
      "KEY_COMPROMISED",
    )
  )
    verdict = "UNTRUSTED";
  else if (has("ORIGIN_GAP", "AUDIT_GAP", "PIN_AHEAD", "ORIGIN_COVERAGE_MISSING")) verdict = "INCOMPLETE";
  else if (envelopes.length === 0) verdict = role === "origin" ? "UNSIGNED" : "INCOMPLETE";
  else if (requiredSteps && [...requiredSteps].some((s) => !covered.has(s))) verdict = "INCOMPLETE";
  else verdict = "TRUSTED_AT_PIN";

  if (envelopes.length === 0 && role === "origin") reasons.add("ORIGIN_UNSIGNED");
  if (envelopes.length === 0 && role === "audit") reasons.add("AUDIT_GAP");

  return { integrity, verdict, reasons: [...reasons].sort() };
}
