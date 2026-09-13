// Shared fixture helpers: mirror the §14 generator exactly.
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  D, H, J, ZERO, VLError,
  parseJsonBytes,
  normalize, reduce, computePath, evalChains, signedOfOrigin, signedOfAudit, verify,
  privateKeyFromSeed, publicKeyBytes, signMessage, signPayload,
} from "../packages/core/dist/index.js";
import { WorkspaceService } from "../packages/sqlite/dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const DOC = JSON.parse(readFileSync(path.join(here, "fixtures.json"), "utf8"));
// fixture doc: {W,T,I,Q,SA..SC,A..C,OA..OC,AB,BC,F0,ST,F,examples}; merge F's
// members (bundle/trust/path/…) with the top-level ids for one namespace.
export const F = { ...DOC, ...DOC.F };

export const ONE = "1".repeat(64);
export const D1 = "vld_" + "d".repeat(21);
export const D2 = "vld_" + "e".repeat(21);

const seedKey = (byte, idChar) => {
  const secret = privateKeyFromSeed(Buffer.alloc(32, byte));
  return { id: "vlk_" + idChar.repeat(21), secret, public: publicKeyBytes(secret).toString("base64url") };
};
export const KA = seedKey(0x44, "k");
export const K1 = seedKey(0x11, "l");
export const K2 = seedKey(0x22, "m");
export const K3 = seedKey(0x33, "n");

export const signed = (tag, body, k) => {
  const hash = D(tag, body);
  return { body, hash, signature: signMessage(k.secret, signPayload(tag.replace("/1", "-SIGN/1"), hash)) };
};

export const agent = (subject, principal = null) => ({ namespace: "lab", subject, principal });
export const policy = { digest: ONE, version: "policy-1", decision: "ALLOW" };

export const step = (body) => ({ body, hash: D("VL-STEP/1", body) });
export const n = (source, record, parents = [], patch = {}) =>
  step({
    v: 1, workspace: F.W, trace: F.T, source: source.id, profile: source.profile,
    record, native_trace: "native-" + source.project, native_span: record,
    parents, agent: null, policy: null, offers: [], accept: null, attachments: [], ...patch,
  });
export const rebody = (s, patch) => step({ ...s.body, ...patch });
export const parent = (v) => ({ kind: "record", value: v });
export const spanParent = (v) => ({ kind: "span", value: v });

export const cleanA = n(F.SA, "a");
export const cleanB = n(F.SB, "b");
export const cleanC = n(F.SC, "c");

export const metadata = (s) => ({
  v: 1, trace_id: F.T, agent: s.body.agent, policy: s.body.policy,
  offers: s.body.offers, accept: s.body.accept, attachments: s.body.attachments,
});
export const RA = F.ST.request.rows[0];
export const RB = { id: "b", traceId: "native-lf", parentObservationId: null, metadata: { vislineage: metadata(F.B) } };
export const RC = { id: "c", span_id: "c", root_span_id: "native-bt", span_parents: [], metadata: { vislineage: metadata(F.C) } };

export const origin = (s, k, seq = "1", prev = ZERO) =>
  signed("VL-ORIGIN/1", { v: 1, workspace: F.W, source: s.body.source, stream: "main", seq, prev, step: s.hash, key: k.id }, k);

export const pin = (k, role, source, last_seq) => ({
  id: k.id, public: k.public, role, workspace: F.W, source,
  stream: source === null ? null : "main", first_seq: "1", last_seq, status: "ACTIVE",
});
export const head = (role, source, e) => ({
  role, source, stream: source === null ? null : "main", seq: e.body.seq, hash: e.hash,
});

const ctx = (source) => ({ workspace: F.W, trace: F.T, source });
export const norm = (source, row) => normalize(source.profile, row, ctx(source));

// canon(str): strict-parse then JCS; {canonical} or {error}
export const canon = (str) => {
  try {
    const v = parseJsonBytes(Buffer.from(str, "utf8"), { numbers: "core" });
    return { canonical: J(v).toString("utf8") };
  } catch (e) {
    return { error: e instanceof VLError ? e.code : "JSON_INVALID" };
  }
};

// join(steps, origins): reduce → {nodes, pairs, codes}
export const join = (steps, origins = []) => {
  const r = reduce(steps, origins, F.W, F.T);
  return {
    nodes: r.manifest.steps.length,
    pairs: r.edges.map((e) => [e.body.parent, e.body.child, e.body.kind]).sort(),
    codes: r.manifest.gaps.map((g) => g.code).sort(),
  };
};

// origin_check(origins, requiredStepHashes, trust)
export const originCheck = (origins, required, trust) => {
  const r = evalChains("origin", origins.map(signedOfOrigin), new Set(required), (e) => e.body.step, trust);
  return { integrity: r.integrity, origin: r.verdict, reasons: r.reasons };
};
export const auditCheck = (audits, trust) => {
  const r = evalChains("audit", audits.map(signedOfAudit), null, () => null, trust);
  return { integrity: r.integrity, audit: r.verdict, reasons: r.reasons };
};

// path_check(steps, action, bounds)
export const pathCheck = (steps, action, bounds) => {
  try {
    const r = reduce(steps, [], F.W, F.T);
    const res = computePath(
      { steps, edges: r.edges, origins: [], gaps: r.manifest.gaps, graph: D("VL-GRAPH/1", r.manifest) },
      { trace: F.T, revision: "0", action, max_depth: bounds.max_depth, max_nodes: bounds.max_nodes },
    );
    return { nodes: res.steps.length };
  } catch (e) {
    return { nodes: 0, error: e instanceof VLError ? e.code : "INTERNAL" };
  }
};

// ---- live service ---------------------------------------------------------

export const ADMIN = { roles: new Set(["admin"]), workspace: F.W };
export const NONE = { roles: new Set(), workspace: F.W };

export function makeService(extra = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), "vl-"));
  const svc = WorkspaceService.create({
    dbPath: path.join(dir, "w.db"),
    stateDir: dir,
    artifactsDir: path.join(dir, "artifacts"),
    workspace: F.W,
    auditKeyId: KA.id,
    auditKey: KA.secret,
    limits: { stage_rows: 1024, request_bytes: 4 * 1024 * 1024, path_nodes: 4096, bundle_bytes: 16 * 1024 * 1024 },
    retention: { stage_ttl_seconds: 3600, history_revisions: 32, artifacts_days: 30 },
    recoveryPinPath: null,
    configHash: D("VL-CONFIG/1", { v: 1, workspace: F.W, profile: "fixture-only" }),
    requestId: "vlq_" + "0".repeat(21),
    ...extra,
  });
  return { svc, dir };
}

export const rq = (id, method, params) => ({ id, method, params });

// Replay the §14 operation sequence so audit bytes match the fixture exactly.
export function replayF(svc) {
  const out = [];
  for (const [i, s] of [F.SA, F.SB, F.SC].entries()) {
    out.push(svc.dispatch(rq("vlq_" + String(i + 1).repeat(21), "source.register", s), ADMIN));
  }
  out.push(svc.dispatch(rq("vlq_" + "4".repeat(21), "trace.create", { trace: F.T }), ADMIN));
  out.push(svc.dispatch(rq(F.ST.stage_id, "import.stage", F.ST.request), ADMIN));
  out.push(svc.dispatch(rq(F.ST.commit_id, "import.commit", { import: F.I, expected_revision: "0" }), ADMIN));
  const bImport = "vli_" + "j".repeat(21);
  const cImport = "vli_" + "h".repeat(21);
  out.push(svc.dispatch(rq("vlq_" + "7".repeat(21), "import.stage",
    { import: bImport, trace: F.T, source: F.SB.id, rows: [RB], origins: [F.OB], artifacts: [] }), ADMIN));
  out.push(svc.dispatch(rq("vlq_" + "8".repeat(21), "import.commit",
    { import: bImport, expected_revision: "1" }), ADMIN));
  out.push(svc.dispatch(rq("vlq_" + "9".repeat(21), "import.stage",
    { import: cImport, trace: F.T, source: F.SC.id, rows: [RC], origins: [F.OC], artifacts: [] }), ADMIN));
  out.push(svc.dispatch(rq("vlq_" + "A".repeat(21), "import.commit",
    { import: cImport, expected_revision: "2" }), ADMIN));
  return out;
}

export function auditEntries(svc) {
  return svc.db.prepare("SELECT envelope FROM audit ORDER BY seq").all()
    .map((r) => JSON.parse(Buffer.from(r.envelope).toString("utf8")));
}

export function writePin(dir, pin) {
  const p = path.join(dir, "recovery-pin.json");
  writeFileSync(p, JSON.stringify(pin));
  return p;
}
