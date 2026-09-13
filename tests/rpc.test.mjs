// §9 RPC examples: schema round-trip + live dispatch byte-parity with §14 fixture.
import { test } from "node:test";
import assert from "node:assert/strict";
import { J, VLError, schema as sch } from "../packages/core/dist/index.js";
import {
  F, RB, RC, ADMIN, NONE, makeService, rq, replayF, auditEntries,
} from "./helpers.mjs";

const jeq = (a, b) => assert.deepEqual(JSON.parse(J(a).toString("utf8")), JSON.parse(J(b).toString("utf8")));

const RESULT_VALIDATORS = {
  "source.register": (v) => sch.source(v, "/result"),
  "source.list": (v) => sch.sourceListResult(v, "/result"),
  "trace.create": (v) => sch.traceResult(v, "/result"),
  "trace.get": (v) => sch.traceResult(v, "/result"),
  "import.stage": (v) => sch.stageResult(v, "/result"),
  "import.get": (v) => sch.importState(v, "/result"),
  "import.commit": (v) => sch.commitResult(v, "/result"),
  "import.cancel": (v) => {
    if (!sch.isObj(v) || typeof v.import !== "string" || v.state !== "CANCELLED") {
      throw new VLError("SCHEMA_INVALID", "/result");
    }
    return v;
  },
  "path.get": (v) => sch.pathResult(v, "/result"),
  "bundle.export": (v) => {
    sch.bundle(v.bundle, "/result/bundle");
    sch.sunlightHandoff(v.sunlight, "/result/sunlight");
    return v;
  },
  "bundle.verify": (v) => sch.verification(v, "/result"),
};

test("examples: all §9 pairs validate and match live dispatch", () => {
  const { svc } = makeService();
  try {
    const live = new Map();

    // replay the lifecycle using the fixture's request ids so audit bytes match
    const outs = replayF(svc);
    live.set("source.register", outs[0].result);
    live.set("trace.create", outs[3].result);
    live.set("import.stage", outs[4].result);
    live.set("import.commit", outs[5].result);

    // reads need no new request-id semantics; use fresh read ids
    const q = (m, p) => svc.dispatch(rq("vlq_" + "f".repeat(21), m, p), ADMIN);
    live.set("source.list", q("source.list", {}).result);
    live.set("trace.get", q("trace.get", { trace: F.T }).result);
    live.set("path.get", q("path.get", F.path_request).result);
    live.set("bundle.export", q("bundle.export", { path: F.path_request, attachments: "OMIT" }).result);
    live.set("bundle.verify", q("bundle.verify", { bundle: F.bundle, trust: F.trust }).result);

    for (const ex of F.examples) {
      const { request, response } = ex;
      // request envelope shape
      assert.equal(typeof request.id, "string");
      assert.equal(typeof request.method, "string");
      assert.ok(sch.isObj(request.params));
      // response validates against its result schema
      const validator = RESULT_VALIDATORS[request.method];
      assert.ok(validator, `no validator for ${request.method}`);
      validator(response.result);

      const got = live.get(request.method);
      if (got !== undefined) {
        jeq(got, response.result);
      }
    }

    // import.get of the committed import shows COMMITTED + commit
    const ig = q("import.get", { import: F.I });
    sch.importState(ig.result, "/result");
    assert.equal(ig.result.state, "COMMITTED");
    assert.equal(ig.result.reason, null);

    // import.cancel: stage a fresh import then cancel → shape matches example
    const zImport = "vli_" + "z".repeat(21);
    const st = svc.dispatch(rq("vlq_" + "e".repeat(21), "import.stage", {
      import: zImport, trace: F.T, source: F.SA.id, rows: [F.ST.request.rows[0]], origins: [F.OA], artifacts: [],
    }), ADMIN);
    assert.equal(st.ok, true);
    const cancelEx = F.examples.find((e) => e.request.method === "import.cancel");
    const cx = svc.dispatch(rq("vlq_" + "d".repeat(21), "import.cancel", { import: zImport }), ADMIN);
    assert.equal(cx.ok, true);
    assert.deepEqual(cx.result, { import: zImport, state: "CANCELLED" });
    assert.deepEqual(cancelEx.response.result.state, "CANCELLED");
  } finally {
    svc.close();
  }
});

test("dispatch: auth before method resolution", () => {
  const { svc } = makeService();
  try {
    const q = "vlq_" + "q".repeat(21);
    // absent credentials → UNAUTHENTICATED before method resolution
    assert.deepEqual(svc.dispatch(rq(q, "import.url", {}), null), {
      id: q, ok: false,
      error: { code: "UNAUTHENTICATED", retryable: false, details: { field: null } },
    });
    // wrong workspace → FORBIDDEN
    const alien = { roles: new Set(["admin"]), workspace: "vlw_" + "x".repeat(21) };
    assert.deepEqual(svc.dispatch(rq(q, "source.list", {}), alien).error.code, "FORBIDDEN");
    // write-only cred on a read method → FORBIDDEN (write does not include read)
    const writer = { roles: new Set(["write"]), workspace: F.W };
    assert.equal(svc.dispatch(rq(q, "path.get", F.path_request), writer).error.code, "FORBIDDEN");
    assert.equal(svc.dispatch(rq(q, "source.list", {}), writer).error.code, "FORBIDDEN");
    // write-only cred on a write method passes the role gate (fails later on params)
    const st = svc.dispatch(rq(q, "import.commit", { import: "vli_" + "z".repeat(21), expected_revision: "0" }), writer);
    assert.equal(st.error.code, "NOT_FOUND");
  } finally {
    svc.close();
  }
});

test("dispatch: envelope/schema/state errors per method", () => {
  const { svc } = makeService();
  try {
    const q = "vlq_" + "q".repeat(21);
    // malformed envelope
    assert.equal(svc.dispatch({ id: "nope", method: "source.list", params: {} }, ADMIN).error.code, "JSON_INVALID");
    assert.equal(svc.dispatch({ id: q, method: "source.list" }, ADMIN).error.code, "JSON_INVALID");
    // schema errors
    assert.equal(svc.dispatch(rq(q, "trace.get", { trace: "not-an-id" }), ADMIN).error.code, "ID_INVALID");
    assert.equal(svc.dispatch(rq(q, "trace.create", { trace: F.T, extra: 1 }), ADMIN).error.code, "SCHEMA_INVALID");
    assert.equal(svc.dispatch(rq(q, "import.commit", { import: "vli_" + "z".repeat(21), expected_revision: -1 }), ADMIN).error.code, "SCHEMA_INVALID");
    // NOT_FOUND on missing resources
    assert.equal(svc.dispatch(rq(q, "trace.get", { trace: F.T }), ADMIN).error.code, "NOT_FOUND");
    assert.equal(svc.dispatch(rq(q, "import.get", { import: F.I }), ADMIN).error.code, "NOT_FOUND");
    assert.equal(svc.dispatch(rq(q, "import.cancel", { import: F.I }), ADMIN).error.code, "NOT_FOUND");
    // state errors: commit before stage → NOT_FOUND; cancel committed → IMPORT_STATE
    replayF(svc);
    assert.equal(
      svc.dispatch(rq(q, "import.cancel", { import: F.I }), ADMIN).error.code,
      "IMPORT_STATE",
    );
    // idempotent cancel replay on a cancelled import returns CANCELLED
    const zImport = "vli_" + "z".repeat(21);
    svc.dispatch(rq("vlq_" + "d".repeat(21), "import.stage", {
      import: zImport, trace: F.T, source: F.SA.id, rows: [F.ST.request.rows[0]], origins: [F.OA], artifacts: [],
    }), ADMIN);
    const c1 = svc.dispatch(rq("vlq_" + "c".repeat(21), "import.cancel", { import: zImport }), ADMIN);
    const c2 = svc.dispatch(rq("vlq_" + "c".repeat(21), "import.cancel", { import: zImport }), ADMIN);
    assert.deepEqual(c1.result, c2.result);
    // same request id, different params → IDEMPOTENCY_CONFLICT
    const conflict = svc.dispatch(rq("vlq_" + "c".repeat(21), "import.cancel", { import: F.I }), ADMIN);
    assert.equal(conflict.error.code, "IDEMPOTENCY_CONFLICT");
  } finally {
    svc.close();
  }
});

test("audit chain: byte parity with fixture", () => {
  const { svc } = makeService();
  try {
    replayF(svc);
    const entries = auditEntries(svc);
    assert.equal(entries.length, 11);
    entries.forEach((a, i) => {
      jeq(a, F.bundle.audit[i]);
      sch.auditEnvelope(a, `/audit/${i}`);
    });
  } finally {
    svc.close();
  }
});
