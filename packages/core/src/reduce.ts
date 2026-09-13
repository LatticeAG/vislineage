import { D, ZERO } from "./hash.js";
import { J } from "./jcs.js";
import type { Edge, EdgeBody, Gap, GraphManifest, Origin, Step } from "./types.js";

/**
 * Deterministic graph reduction (spec §5.2).
 * Pure: no clock, randomness, filesystem, or network. All ordering is derived
 * from canonical encodings.
 */

export interface Reduced {
  manifest: GraphManifest;
  /** Unsuppressed edges (candidate edges minus SCC-internal/self-loop edges). */
  edges: Edge[];
  gaps: Gap[];
}

function edgeHash(parent: string, child: string, kind: "NATIVE_PARENT" | "DELEGATES", delegation: string | null, scope: string | null, trace: string): Edge {
  const body: EdgeBody = { v: 1, trace, parent, child, kind, delegation, scope };
  return { body, hash: D("VL-EDGE/1", body) };
}

function gapCmp(a: Gap, b: Gap): number {
  if (a.code !== b.code) return a.code < b.code ? -1 : 1;
  if (a.subject !== b.subject) return a.subject < b.subject ? -1 : 1;
  return Buffer.compare(J(a.related), J(b.related));
}

/** Stream structure diagnostics: broken-link positions and fork slots (§3.2). */
export interface StreamDiag {
  broken: bigint[];
  forks: Map<bigint, string[]>;
}

export function originStreamDiags(origins: Origin[]): Map<string, StreamDiag> {
  const streams = new Map<string, Origin[]>();
  for (const o of origins) {
    const k = `${o.body.source} ${o.body.stream}`;
    const list = streams.get(k) ?? [];
    list.push(o);
    streams.set(k, list);
  }
  const out = new Map<string, StreamDiag>();
  for (const [k, list] of streams) {
    const slots = new Map<bigint, Map<string, string>>(); // seq -> bodyHash -> prev
    for (const o of list) {
      const seq = BigInt(o.body.seq);
      let m = slots.get(seq);
      if (!m) {
        m = new Map();
        slots.set(seq, m);
      }
      m.set(o.hash, o.body.prev);
    }
    const broken = new Set<bigint>();
    for (const [seq, hashToPrev] of slots) {
      const prevSlots = slots.get(seq - 1n);
      for (const prev of hashToPrev.values()) {
        if (seq === 1n) {
          if (prev !== ZERO) broken.add(seq); // schema-invalid envelope defensively treated as broken
        } else if (!prevSlots || !prevSlots.has(prev)) {
          broken.add(seq);
        }
      }
    }
    const forks = new Map<bigint, string[]>();
    for (const [seq, hashToPrev] of slots) {
      if (hashToPrev.size >= 2) forks.set(seq, [...hashToPrev.keys()].sort());
    }
    out.set(k, { broken: [...broken].sort((a, b) => (a < b ? -1 : 1)), forks });
  }
  return out;
}

/** reduce(steps, origins, {workspace, trace}) → manifest + derived edges + gaps. */
export function reduce(steps: Step[], origins: Origin[], workspace: string, trace: string): Reduced {
  const gaps: Gap[] = [];
  const stepByHash = new Map<string, Step>();
  for (const s of steps) stepByHash.set(s.hash, s);

  const pushIdx = (m: Map<string, Step[]>, k: string, s: Step): void => {
    const l = m.get(k);
    if (l) l.push(s);
    else m.set(k, [s]);
  };

  const byRecord = new Map<string, Step[]>(); // source|record
  const byNTRecord = new Map<string, Step[]>(); // source|native_trace|record
  const byNTSpan = new Map<string, Step[]>(); // source|native_trace|native_span
  for (const s of steps) {
    pushIdx(byRecord, `${s.body.source} ${s.body.record}`, s);
    pushIdx(byNTRecord, `${s.body.source} ${s.body.native_trace} ${s.body.record}`, s);
    pushIdx(byNTSpan, `${s.body.source} ${s.body.native_trace} ${s.body.native_span}`, s);
  }

  const conflicted = new Set<string>();
  for (const [rk, cands] of byRecord) {
    const hashes = [...new Set(cands.map((c) => c.hash))].sort();
    if (hashes.length > 1) {
      conflicted.add(rk);
      gaps.push({ code: "SOURCE_CONFLICT", subject: hashes[0]!, related: hashes });
    }
  }

  const candidateEdges = new Map<string, Edge>();

  for (const s of steps) {
    const childConflicted = conflicted.has(`${s.body.source} ${s.body.record}`);
    for (const p of s.body.parents) {
      const key = `${s.body.source} ${s.body.native_trace} ${p.value}`;
      const cands = (p.kind === "record" ? byNTRecord.get(key) : byNTSpan.get(key)) ?? [];
      const hashes = [...new Set(cands.map((c) => c.hash))].sort();
      if (hashes.length === 0) {
        gaps.push({ code: "PARENT_MISSING", subject: s.hash, related: [] });
        continue;
      }
      if (hashes.length > 1) {
        gaps.push({ code: "PARENT_AMBIGUOUS", subject: s.hash, related: hashes });
        continue;
      }
      if (childConflicted) continue; // conflicted endpoint suppresses the edge
      const e = edgeHash(hashes[0]!, s.hash, "NATIVE_PARENT", null, null, trace);
      candidateEdges.set(e.hash, e);
    }
  }

  const offersByDel = new Map<string, { step: Step; offer: Step["body"]["offers"][number] }[]>();
  const acceptsByDel = new Map<string, { step: Step; accept: NonNullable<Step["body"]["accept"]> }[]>();
  for (const s of steps) {
    for (const o of s.body.offers) {
      const l = offersByDel.get(o.id) ?? [];
      l.push({ step: s, offer: o });
      offersByDel.set(o.id, l);
    }
    if (s.body.accept) {
      const a = s.body.accept;
      const l = acceptsByDel.get(a.id) ?? [];
      l.push({ step: s, accept: a });
      acceptsByDel.set(a.id, l);
    }
  }

  for (const id of [...new Set([...offersByDel.keys(), ...acceptsByDel.keys()])].sort()) {
    const offers = offersByDel.get(id) ?? [];
    const accepts = acceptsByDel.get(id) ?? [];
    const offererHashes = new Set(offers.map((o) => o.step.hash));
    const accepterHashes = new Set(accepts.map((a) => a.step.hash));
    if (offererHashes.size >= 2 || accepterHashes.size >= 2) {
      const involved = [...new Set([...offererHashes, ...accepterHashes])].sort();
      gaps.push({ code: "DELEGATION_REUSED", subject: involved[0]!, related: involved });
      continue;
    }
    if (offers.length === 0) {
      gaps.push({ code: "OFFER_MISSING", subject: accepts[0]!.step.hash, related: [] });
      continue;
    }
    if (accepts.length === 0) {
      gaps.push({ code: "ACCEPT_MISSING", subject: offers[0]!.step.hash, related: [] });
      continue;
    }
    const { step: offerStep, offer } = offers[0]!;
    const { step: childStep, accept } = accepts[0]!;
    const namedCands = [...new Set((byRecord.get(`${accept.parent.source} ${accept.parent.record}`) ?? []).map((c) => c.hash))].sort();
    const namedExact = namedCands.includes(accept.parent.hash) ? stepByHash.get(accept.parent.hash)! : undefined;
    if (namedCands.length === 0) {
      gaps.push({ code: "DELEGATION_MISMATCH", subject: childStep.hash, related: [] });
      continue;
    }
    if (!namedExact) {
      gaps.push({ code: "PARENT_HASH_MISMATCH", subject: childStep.hash, related: namedCands });
      continue;
    }
    const childAgentOk =
      childStep.body.agent !== null && Buffer.compare(J(childStep.body.agent), J(offer.child_agent)) === 0;
    const matched =
      offerStep.hash === namedExact.hash &&
      offer.child_source === childStep.body.source &&
      childAgentOk &&
      offer.scope === accept.scope &&
      namedExact.body.source !== childStep.body.source &&
      namedExact.body.trace === childStep.body.trace &&
      namedExact.body.offers.some((o) => Buffer.compare(J(o), J(offer)) === 0);
    if (!matched) {
      gaps.push({ code: "DELEGATION_MISMATCH", subject: childStep.hash, related: namedCands });
      continue;
    }
    const e = edgeHash(namedExact.hash, childStep.hash, "DELEGATES", id, offer.scope, trace);
    candidateEdges.set(e.hash, e);
  }

  // SCC suppression (iterative Tarjan) over the candidate-edge graph.
  const adj = new Map<string, string[]>();
  const nodes = new Set<string>();
  for (const e of candidateEdges.values()) {
    nodes.add(e.body.parent);
    nodes.add(e.body.child);
    const l = adj.get(e.body.parent) ?? [];
    l.push(e.body.child);
    adj.set(e.body.parent, l);
  }
  const index = new Map<string, number>();
  const low = new Map<string, number>();
  const onStack = new Set<string>();
  const stack: string[] = [];
  const compOf = new Map<string, number>();
  let counter = 0;
  let compCount = 0;
  for (const start of nodes) {
    if (index.has(start)) continue;
    const work: [string, Iterator<string>][] = [[start, (adj.get(start) ?? [])[Symbol.iterator]()] as [string, Iterator<string>]];
    index.set(start, counter);
    low.set(start, counter);
    counter++;
    stack.push(start);
    onStack.add(start);
    while (work.length) {
      const [v, it] = work[work.length - 1]!;
      const nx = it.next();
      if (!nx.done) {
        const w = nx.value;
        if (!index.has(w)) {
          index.set(w, counter);
          low.set(w, counter);
          counter++;
          stack.push(w);
          onStack.add(w);
          work.push([w, (adj.get(w) ?? [])[Symbol.iterator]()]);
        } else if (onStack.has(w)) {
          low.set(v, Math.min(low.get(v)!, index.get(w)!));
        }
        continue;
      }
      work.pop();
      if (work.length) {
        const parent = work[work.length - 1]![0];
        low.set(parent, Math.min(low.get(parent)!, low.get(v)!));
      }
      if (low.get(v) === index.get(v)) {
        const comp: string[] = [];
        for (;;) {
          const w = stack.pop()!;
          onStack.delete(w);
          comp.push(w);
          compOf.set(w, compCount);
          if (w === v) break;
        }
        const selfLoop = comp.length === 1 && (adj.get(v) ?? []).includes(v);
        if (comp.length > 1 || selfLoop) {
          const sorted = comp.sort();
          gaps.push({ code: "CYCLE", subject: sorted[0]!, related: sorted });
        }
        compCount++;
      }
    }
  }

  const edges: Edge[] = [];
  for (const e of candidateEdges.values()) {
    const cp = compOf.get(e.body.parent);
    const cc = compOf.get(e.body.child);
    if (cp !== undefined && cp === cc) continue; // internal to a nontrivial SCC or self-loop
    edges.push(e);
  }

  // Origin stream derivations restricted to steps of this trace.
  const stepHashes = new Set(steps.map((s) => s.hash));
  const diags = originStreamDiags(origins);
  const byStream = new Map<string, Origin[]>();
  for (const o of origins) {
    const k = `${o.body.source} ${o.body.stream}`;
    const l = byStream.get(k) ?? [];
    l.push(o);
    byStream.set(k, l);
  }
  for (const [k, list] of byStream) {
    const diag = diags.get(k)!;
    const attestPos = new Map<string, bigint[]>();
    for (const o of list) {
      if (!stepHashes.has(o.body.step)) continue;
      const seq = BigInt(o.body.seq);
      const l = attestPos.get(o.body.step) ?? [];
      l.push(seq);
      attestPos.set(o.body.step, l);
    }
    for (const [sh, positions] of attestPos) {
      if (diag.broken.some((b) => positions.some((p) => p >= b))) {
        gaps.push({ code: "ORIGIN_GAP", subject: sh, related: [] });
      }
      for (const [f, hashes] of diag.forks) {
        if (positions.some((p) => p >= f)) {
          gaps.push({ code: "ORIGIN_FORK", subject: sh, related: hashes });
        }
      }
    }
  }

  const seen = new Set<string>();
  const uniqGaps = gaps.filter((g) => {
    const k = `${g.code} ${g.subject} ${J(g.related).toString("hex")}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  uniqGaps.sort(gapCmp);

  const manifest: GraphManifest = {
    v: 1,
    workspace,
    trace,
    steps: [...stepByHash.keys()].sort(),
    origins: [...new Set(origins.map((o) => o.hash))].sort(),
    edges: edges.map((e) => e.hash).sort(),
    gaps: uniqGaps,
  };
  return { manifest, edges, gaps: uniqGaps };
}
