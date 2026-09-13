import { VLError } from "./errors.js";
import { D, H, ZERO, b64urlDecode } from "./hash.js";
import { J } from "./jcs.js";
import { computePath } from "./path.js";
import { reduce } from "./reduce.js";
import { bundle as bundleSchema, trustPackage as trustSchema } from "./schema.js";
import { evalChains, signedOfAudit, signedOfOrigin } from "./trust.js";
import type { Audit, Bundle, GraphManifest, TrustPackage, Verification } from "./types.js";

export type VerifyOutcome = Verification | { ok: false; error: { code: string; retryable: false; details: { field: string | null } } };

function failure(e: VLError): { ok: false; error: { code: string; retryable: false; details: { field: string | null } } } {
  return { ok: false, error: { code: e.code, retryable: false, details: { field: e.field } } };
}

function deepJ(a: unknown, b: unknown): boolean {
  return Buffer.compare(J(a), J(b)) === 0;
}

/**
 * verify(bundle, trust) → Verification, or the §9 failure object on structural
 * parse/version/limit failures. Pure and offline.
 *
 * Order (§8): strict parse/version/limits → inventory & content hashes →
 * step/origin scope → graph reduction equality → path recomputation equality →
 * audit binding/chain → origin signatures/pins.
 */
export function verify(bundleIn: unknown, trustIn: unknown): VerifyOutcome {
  let b: Bundle;
  let trust: TrustPackage;
  try {
    b = bundleSchema(bundleIn, "/bundle");
    trust = trustSchema(trustIn, "/trust");
  } catch (e) {
    return failure(e as VLError);
  }
  if (trust.workspace !== b.body.workspace) {
    return { ok: false, error: { code: "TRUST_INVALID", retryable: false, details: { field: "/trust/workspace" } } };
  }

  const conservative = (reasons: string[]): Verification => ({
    integrity: "INVALID",
    structural: "INCOMPLETE",
    origin: "UNTRUSTED",
    audit: "UNTRUSTED",
    disclosure: "NORMALIZED_ONLY",
    semantics: "NOT_VERIFIED",
    current_authority: "UNKNOWN",
    reasons: [...new Set(reasons)].sort(),
  });
  const done = (
    integrity: "VALID" | "INVALID",
    structural: Verification["structural"],
    origin: Verification["origin"],
    audit: Verification["audit"],
    reasons: string[],
  ): Verification => ({
    integrity,
    structural,
    origin,
    audit,
    disclosure: "NORMALIZED_ONLY",
    semantics: "NOT_VERIFIED",
    current_authority: "UNKNOWN",
    reasons: [...new Set(reasons)].sort(),
  });

  // ---- phase 2: inventory + content hashes -------------------------------
  const inventoryReasons = new Set<string>();
  const recomputed = { step: new Set<string>(), origin: new Set<string>(), audit: new Set<string>(), attachment: new Set<string>() };
  const checkEnv = (kind: keyof typeof recomputed, env: { body: unknown; hash: string }, tag: string): void => {
    const want = D(tag, env.body);
    if (env.hash !== want) inventoryReasons.add("INVENTORY_MISMATCH");
    const digest = H(J(env));
    if (recomputed[kind].has(digest)) inventoryReasons.add("INVENTORY_MISMATCH"); // duplicate full envelope
    recomputed[kind].add(digest);
  };
  for (const s of b.steps) checkEnv("step", s, "VL-STEP/1");
  for (const o of b.origins) checkEnv("origin", o, "VL-ORIGIN/1");
  for (const a of b.audit) checkEnv("audit", a, "VL-AUDIT/1");
  if (b.hash !== D("VL-BUNDLE/1", b.body)) inventoryReasons.add("INVENTORY_MISMATCH");

  // attachment refs across bundled steps (dedup by digest)
  const refs = new Map<string, { format: string; bytes: string }>();
  for (const s of b.steps) for (const r of s.body.attachments) refs.set(r.digest, { format: r.format, bytes: r.bytes });
  const suppliedArt = new Set<string>();
  for (const a of b.attachments) {
    let raw: Buffer;
    try {
      raw = b64urlDecode(a.content, Number(BigInt(a.bytes)), "/bundle/attachments");
    } catch {
      inventoryReasons.add("INVENTORY_MISMATCH");
      continue;
    }
    if (H(raw) !== a.digest || BigInt(a.bytes) !== BigInt(raw.length)) inventoryReasons.add("INVENTORY_MISMATCH");
    if (suppliedArt.has(a.digest)) inventoryReasons.add("INVENTORY_MISMATCH");
    suppliedArt.add(a.digest);
    const ref = refs.get(a.digest);
    if (!ref || ref.format !== a.format || BigInt(ref.bytes) !== BigInt(raw.length)) {
      inventoryReasons.add("INVENTORY_MISMATCH");
    }
    recomputed.attachment.add(a.digest);
  }
  if (b.body.attachment_policy === "OMIT" && b.attachments.length !== 0) {
    inventoryReasons.add("INVENTORY_MISMATCH");
  }
  if (b.body.attachment_policy === "INCLUDE") {
    for (const digest of refs.keys()) {
      if (!suppliedArt.has(digest)) inventoryReasons.add("INVENTORY_MISMATCH");
    }
  }
  for (const digest of refs.keys()) recomputed.attachment.add(digest);

  const expectedInv = new Map<string, string>();
  for (const it of b.body.inventory) {
    const k = `${it.kind} ${it.digest}`;
    if (expectedInv.has(k)) inventoryReasons.add("INVENTORY_MISMATCH");
    expectedInv.set(k, it.bytes);
  }
  const actualInv = new Map<string, string>();
  const invAdd = (kind: string, digest: string, bytes: string) => actualInv.set(`${kind} ${digest}`, bytes);
  // inventory digests are over envelope bytes for step/origin/audit
  for (const s of b.steps) invAdd("step", H(J(s)), String(J(s).length));
  for (const o of b.origins) invAdd("origin", H(J(o)), String(J(o).length));
  for (const a of b.audit) invAdd("audit", H(J(a)), String(J(a).length));
  for (const [digest, ref] of refs) invAdd("attachment", digest, ref.bytes);
  if (actualInv.size !== expectedInv.size) inventoryReasons.add("INVENTORY_MISMATCH");
  for (const [k, bytes] of actualInv) {
    if (expectedInv.get(k) !== bytes) inventoryReasons.add("INVENTORY_MISMATCH");
  }
  if (inventoryReasons.size) return conservative([...inventoryReasons]);

  // ---- phase 3: step/origin scope ----------------------------------------
  const stepHashes = new Set(b.steps.map((s) => s.hash));
  for (const s of b.steps) {
    if (s.body.workspace !== b.body.workspace || s.body.trace !== b.body.trace) {
      return conservative(["INVENTORY_MISMATCH"]);
    }
  }
  const byStreamO = new Map<string, typeof b.origins>();
  for (const o of b.origins) {
    if (o.body.workspace !== b.body.workspace) return conservative(["INVENTORY_MISMATCH"]);
    const k = `${o.body.source} ${o.body.stream}`;
    (byStreamO.get(k) ?? byStreamO.set(k, []).get(k)!).push(o);
  }
  for (const o of b.origins) {
    // needed iff some supplied origin in the same stream attests a supplied
    // step at seq >= o.seq
    const stream = byStreamO.get(`${o.body.source} ${o.body.stream}`)!;
    const needed = stream.some((p) => stepHashes.has(p.body.step) && BigInt(p.body.seq) >= BigInt(o.body.seq));
    if (!needed) return conservative(["INVENTORY_MISMATCH"]);
  }

  // ---- phase 4: graph reduction equality ---------------------------------
  const graph: GraphManifest = b.body.graph;
  const red = reduce(b.steps, b.origins, b.body.workspace, b.body.trace);
  const recomputedGraph = red.manifest;
  if (!deepJ(recomputedGraph, graph)) {
    return {
      ...conservative(["GRAPH_MISMATCH"]),
      structural: "INCOMPLETE",
    };
  }
  const graphHashVal = D("VL-GRAPH/1", graph);

  // ---- phase 5: path recomputation equality -------------------------------
  let recomputedPath;
  try {
    recomputedPath = computePath(
      {
        steps: b.steps,
        edges: red.edges,
        origins: b.origins,
        gaps: recomputedGraph.gaps,
        graph: graphHashVal,
      },
      b.body.path_request,
    );
  } catch {
    return { ...conservative(["PATH_MISMATCH"]), structural: "INCOMPLETE" };
  }
  if (
    b.body.path_request.trace !== b.body.trace ||
    b.body.path_request.revision !== b.body.revision ||
    !deepJ(recomputedPath, b.body.path)
  ) {
    return { ...conservative(["PATH_MISMATCH"]), structural: recomputedPath.structural };
  }

  // ---- phase 6: audit binding + chain ------------------------------------
  const auditEntries: Audit[] = [...b.audit].sort((x, y) =>
    BigInt(x.body.seq) < BigInt(y.body.seq) ? -1 : BigInt(x.body.seq) > BigInt(y.body.seq) ? 1 : 0,
  );
  const bindOk = (() => {
    const last = auditEntries[auditEntries.length - 1];
    if (!last) return false;
    const d = last.body.data;
    if (b.body.revision === "0") {
      return d.kind === "TraceCreated" && d.trace === b.body.trace && d.graph === graphHashVal;
    }
    return (
      d.kind === "ImportCommitted" &&
      d.trace === b.body.trace &&
      d.revision === b.body.revision &&
      d.graph === graphHashVal
    );
  })();
  if (!bindOk) {
    return { ...conservative(["AUDIT_BINDING_MISMATCH"]), structural: recomputedPath.structural };
  }
  for (const a of auditEntries) {
    if (a.body.workspace !== b.body.workspace) {
      return { ...conservative(["AUDIT_BINDING_MISMATCH"]), structural: recomputedPath.structural };
    }
  }
  const auditEval = evalChains(
    "audit",
    auditEntries.map(signedOfAudit),
    null,
    () => null,
    trust,
  );
  if (auditEval.integrity === "INVALID") {
    return {
      ...conservative(auditEval.reasons),
      structural: recomputedPath.structural,
    };
  }
  const auditVerdict = auditEval.verdict === "CONFLICTED" ? "UNTRUSTED" : auditEval.verdict;
  const auditOut = auditVerdict === "UNSIGNED" ? "INCOMPLETE" : auditVerdict;

  // ---- phase 7: origin signatures + pins ---------------------------------
  const requiredSteps = new Set(recomputedPath.steps.map((s) => s.hash));
  const originEval = evalChains(
    "origin",
    b.origins.map(signedOfOrigin),
    requiredSteps,
    (e) => {
      const o = e as unknown as { body: { step: string } };
      return o.body.step;
    },
    trust,
  );
  if (originEval.integrity === "INVALID") {
    return done("INVALID", recomputedPath.structural, originEval.verdict, auditOut, originEval.reasons);
  }

  const allReasons = [...auditEval.reasons, ...originEval.reasons];
  return done("VALID", recomputedPath.structural, originEval.verdict, auditOut, allReasons);
}
