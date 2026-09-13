import { VLError } from "./errors.js";
import { D } from "./hash.js";
import { J } from "./jcs.js";
import type { Edge, Gap, Origin, PathRequest, PathResult, Step } from "./types.js";

const CONFLICT_CODES = new Set([
  "SOURCE_CONFLICT",
  "PARENT_AMBIGUOUS",
  "DELEGATION_REUSED",
  "CYCLE",
  "ORIGIN_FORK",
]);

export interface PathGraph {
  steps: Step[];
  edges: Edge[]; // unsuppressed edges of the revision
  origins: Origin[]; // pinned origin set of the revision
  gaps: Gap[];
  graph: string; // manifest hash
}

/**
 * Bounded ancestor-subgraph path query (§5.3). Pure function over a pinned
 * revision's stored projections.
 */
export function computePath(g: PathGraph, req: PathRequest): PathResult {
  const candidates = g.steps.filter(
    (s) => s.body.source === req.action.source && s.body.record === req.action.record,
  );
  if (candidates.length === 0) throw new VLError("NOT_FOUND", null, "action not found");
  if (candidates.length > 1) throw new VLError("ACTION_CONFLICT", null, "multiple action versions");
  const action = candidates[0]!;

  const incoming = new Map<string, Edge[]>();
  for (const e of g.edges) {
    const l = incoming.get(e.body.child) ?? [];
    l.push(e);
    incoming.set(e.body.child, l);
  }

  // Iterative BFS over incoming edges, tracking minimum depth.
  const depth = new Map<string, number>([[action.hash, 0]]);
  const wl = [action.hash];
  while (wl.length) {
    const v = wl.pop()!;
    const d = depth.get(v)!;
    for (const e of incoming.get(v) ?? []) {
      const p = e.body.parent;
      if (depth.has(p)) continue;
      if (d + 1 > req.max_depth) {
        throw new VLError("PATH_LIMIT", null, "ancestor depth exceeds bound");
      }
      depth.set(p, d + 1);
      wl.push(p);
    }
  }
  if (depth.size > req.max_nodes) throw new VLError("PATH_LIMIT", null, "node bound exceeded");

  const returned = new Set(depth.keys());
  const edges = g.edges.filter((e) => returned.has(e.body.parent) && returned.has(e.body.child));
  if (edges.length > 16384) throw new VLError("PATH_LIMIT", null, "edge bound exceeded");

  // Kahn topological order, lowest step hash first among ready vertices.
  const indeg = new Map<string, number>();
  const out = new Map<string, string[]>();
  for (const h of returned) indeg.set(h, 0);
  for (const e of edges) {
    indeg.set(e.body.child, indeg.get(e.body.child)! + 1);
    (out.get(e.body.parent) ?? out.set(e.body.parent, []).get(e.body.parent)!).push(e.body.child);
  }
  const ready = [...returned].filter((h) => indeg.get(h) === 0).sort();
  const order: string[] = [];
  while (ready.length) {
    const v = ready.shift()!;
    order.push(v);
    const nexts: string[] = [];
    for (const w of out.get(v) ?? []) {
      const d = indeg.get(w)! - 1;
      indeg.set(w, d);
      if (d === 0) nexts.push(w);
    }
    if (nexts.length) {
      ready.push(...nexts);
      ready.sort();
    }
  }
  const stepByHash = new Map(g.steps.map((s) => [s.hash, s]));
  const steps = order.map((h) => stepByHash.get(h)!);

  const gaps = g.gaps.filter(
    (gp) => returned.has(gp.subject) || gp.related.some((r) => returned.has(r)),
  );

  let structural: PathResult["structural"] = "COMPLETE_RELATIVE";
  if (gaps.some((gp) => CONFLICT_CODES.has(gp.code))) structural = "CONFLICTED";
  else if (gaps.length > 0) structural = "INCOMPLETE";

  // Origins: attestations of returned steps plus same-stream predecessors.
  const attestingSeq = new Map<string, bigint>(); // stream -> max attested seq needed... collect all attesting seqs
  const byStream = new Map<string, Origin[]>();
  for (const o of g.origins) {
    const k = `${o.body.source} ${o.body.stream}`;
    (byStream.get(k) ?? byStream.set(k, []).get(k)!).push(o);
    if (returned.has(o.body.step)) {
      const cur = attestingSeq.get(k);
      const seq = BigInt(o.body.seq);
      attestingSeq.set(k, cur === undefined || seq > cur ? seq : cur);
    }
  }
  const origins = g.origins.filter((o) => {
    const k = `${o.body.source} ${o.body.stream}`;
    if (returned.has(o.body.step)) return true;
    const maxSeq = attestingSeq.get(k);
    return maxSeq !== undefined && BigInt(o.body.seq) <= maxSeq;
  });
  origins.sort((a, b) => Buffer.compare(J(a), J(b)));
  edges.sort((a, b) => (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));

  return {
    trace: req.trace,
    revision: req.revision,
    graph: g.graph,
    action: action.hash,
    steps,
    origins,
    edges,
    gaps,
    structural,
    evidence: "CLAIMED",
    disclosure: "NORMALIZED_ONLY",
  };
}

/** Manifest hash helper. */
export function graphHash(manifest: unknown): string {
  return D("VL-GRAPH/1", manifest);
}
