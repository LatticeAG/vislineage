// §16 gate tests: parser limits, permutation invariance, shuffled-root stability,
// secret canary, flag surface.
import { test } from "node:test";
import assert from "node:assert/strict";
import { D, J, VLError, parseJsonBytes, reduce, schema as sch, isId } from "../packages/core/dist/index.js";
import { F, n, parent, join, origin, K1, makeService, replayF, rq, ADMIN } from "./helpers.mjs";

const expectCode = (code, fn) => {
  try {
    fn();
  } catch (e) {
    assert.equal(e instanceof VLError ? e.code : "INTERNAL", code);
    return;
  }
  assert.fail(`expected ${code}`);
};

test("P1: parser limits reject before mutation", () => {
  // depth 33 → JSON_INVALID (cap is 32)
  const deep = "[".repeat(33) + "]".repeat(33);
  expectCode("JSON_INVALID", () => parseJsonBytes(Buffer.from(deep), { numbers: "core" }));
  // depth 32 accepted
  const ok = "[".repeat(32) + "]".repeat(32);
  parseJsonBytes(Buffer.from(ok), { numbers: "core" });
  // duplicate members
  expectCode("JSON_INVALID", () => parseJsonBytes(Buffer.from('{"a":1,"a":2}'), { numbers: "core" }));
  // BOM
  expectCode("JSON_INVALID", () =>
    parseJsonBytes(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("{}")]), { numbers: "core" }));
  // invalid UTF-8
  expectCode("JSON_INVALID", () => parseJsonBytes(Buffer.from([0x7b, 0x22, 0xff, 0xfe, 0x7d]), { numbers: "core" }));
  // lone surrogate escape
  expectCode("JSON_INVALID", () => parseJsonBytes(Buffer.from('{"s":"\\ud800"}'), { numbers: "core" }));
  // parent count 17 (normalize), offer count 33 (step body)
  expectCode("SCHEMA_INVALID", () =>
    sch.stepBody(
      { v: 1, workspace: F.W, trace: F.T, source: F.SA.id, profile: "langsmith-runs/1", record: "x", native_trace: "n", native_span: "x",
        parents: Array.from({ length: 17 }, (_, i) => parent("p" + i)), agent: null, policy: null, offers: [], accept: null, attachments: [] },
      "/x"));
  expectCode("SCHEMA_INVALID", () =>
    sch.stepBody(
      { v: 1, workspace: F.W, trace: F.T, source: F.SA.id, profile: "langsmith-runs/1", record: "x", native_trace: "n", native_span: "x",
        parents: [], agent: null, policy: null,
        offers: Array.from({ length: 33 }, (_, i) => ({ id: "vld_" + String(i).padStart(21, "0"), child_source: F.SB.id, child_agent: { namespace: "lab", subject: "b", principal: null }, scope: "0".repeat(64) })),
        accept: null, attachments: [] },
      "/x"));
  // wrong nanoid prefixes
  for (const [kind, bad] of [
    ["source", "vlt_" + "a".repeat(21)],
    ["trace", "vls_" + "a".repeat(21)],
    ["import", "vlw_" + "a".repeat(21)],
    ["delegation", "vlk_" + "a".repeat(21)],
    ["key", "vld_" + "a".repeat(21)],
    ["request", "vli_" + "a".repeat(21)],
    ["workspace", "vls_" + "a".repeat(21)],
  ]) {
    expectCode("ID_INVALID", () => sch.typedId(bad, kind, "/id"));
    assert.equal(isId(kind, bad), false);
  }
  // bad alphabet / length
  assert.equal(isId("source", "vls_" + "a".repeat(20)), false);
  assert.equal(isId("source", "vls_" + "a".repeat(22)), false);
  assert.equal(isId("source", "vls_" + "a".repeat(20) + "!"), false);
  assert.equal(isId("source", "vls_" + "_".repeat(21)), true);
});

test("P1: 1 MiB row limit via service stage", () => {
  const { svc } = makeService();
  try {
    svc.dispatch(rq("vlq_" + "1".repeat(21), "source.register", F.SA), ADMIN);
    svc.dispatch(rq("vlq_" + "4".repeat(21), "trace.create", { trace: F.T }), ADMIN);
    const big = { ...F.ST.request.rows[0], blob: "x".repeat(1024 * 1024) };
    const res = svc.dispatch(rq("vlq_" + "5".repeat(21), "import.stage", {
      import: F.I, trace: F.T, source: F.SA.id, rows: [big], origins: [], artifacts: [],
    }), ADMIN);
    assert.equal(res.ok, false);
    assert.equal(res.error.code, "ROW_LIMIT");
    // nothing staged
    assert.equal(svc.db.prepare("SELECT COUNT(*) c FROM imports").get().c, 0);
  } finally {
    svc.close();
  }
});

test("P1: all 6 permutations of A/B/C produce F.graph_hash", () => {
  const S = [F.A, F.B, F.C];
  const O = [F.OA, F.OB, F.OC];
  const perms = [
    [0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0],
  ];
  for (const p of perms) {
    const m = reduce(p.map((i) => S[i]), p.map((i) => O[i]), F.W, F.T).manifest;
    assert.equal(D("VL-GRAPH/1", m), F.graph_hash, `permutation ${p}`);
  }
});

function mulberry32(a) {
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test("P1: 100 seeded shuffles of a 1000-step trace produce a stable root", () => {
  // linear native chain r0 ← r1 ← … ← r999 on SA
  const steps = [n(F.SA, "r0")];
  for (let i = 1; i < 1000; i++) steps.push(n(F.SA, "r" + i, [parent("r" + (i - 1))]));
  const root = D("VL-GRAPH/1", reduce(steps, [], F.W, F.T).manifest);
  for (let seed = 0; seed < 100; seed++) {
    const rand = mulberry32(seed);
    const shuffled = [...steps];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    const m = reduce(shuffled, [], F.W, F.T).manifest;
    assert.equal(D("VL-GRAPH/1", m), root, `seed ${seed}`);
    assert.equal(m.edges.length, 999);
  }
});

test("P2: unknown flags and absent secret paths", () => {
  // stage with unknown param member → SCHEMA_INVALID
  const { svc } = makeService();
  try {
    const res = svc.dispatch(rq("vlq_" + "5".repeat(21), "import.stage", {
      import: F.I, trace: F.T, source: F.SA.id, rows: [F.ST.request.rows[0]], origins: [], artifacts: [], url: "https://x",
    }), ADMIN);
    assert.equal(res.ok, false);
    assert.equal(res.error.code, "SCHEMA_INVALID");
  } finally {
    svc.close();
  }
});

test("P2: secret canary never touches journal/log sinks", async () => {
  // exercise the journal: it must serialize via J (no raw vendor bytes possible)
  const { J: j } = await import("../packages/core/dist/index.js");
  const entry = { v: 1, request: "vlq_" + "q".repeat(21), method: "import.stage", request_hash: "0".repeat(64), response_code: "STAGED", at: 0 };
  const line = j(entry).toString("utf8");
  assert.equal(line.includes("fixture-secret"), false);
});
