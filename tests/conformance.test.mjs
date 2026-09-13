// §15 conformance vectors TV-V-01 .. TV-V-42 + §14 golden values.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import {
  D, H, J, ZERO, VLError, parseJsonBytes,
  normalize, reduce, computePath, evalChains, signedOfOrigin, signedOfAudit,
  verify, signMessage, signPayload,
} from "../packages/core/dist/index.js";
import { WorkspaceService } from "../packages/sqlite/dist/index.js";
import {
  F, ONE, D1, D2, KA, K1, K2, K3, signed, agent, policy, step, n, rebody,
  parent, spanParent, cleanA, cleanB, cleanC, metadata, RA, RB, RC,
  origin, pin, head, norm, canon, join, originCheck, auditCheck, pathCheck,
  ADMIN, NONE, makeService, rq, replayF, auditEntries, writePin,
} from "./helpers.mjs";

const jeq = (a, b) => assert.deepEqual(JSON.parse(J(a).toString("utf8")), JSON.parse(J(b).toString("utf8")));

// ---------- P0: canonicalization / strict parse ----------------------------

test("TV-V-01 canonical member order", () => {
  assert.deepEqual(canon('{"b":2,"a":1}'), { canonical: '{"a":1,"b":2}' });
});

test("TV-V-02 duplicate members", () => {
  assert.deepEqual(canon('{"a":1,"a":2}'), { error: "JSON_INVALID" });
});

test("TV-V-03 unsafe integer and negative zero", () => {
  assert.deepEqual(
    [canon('{"n":9007199254740992}'), canon('{"n":-0}')],
    [{ error: "SCHEMA_INVALID" }, { error: "SCHEMA_INVALID" }],
  );
});

test("TV-V-04 Unicode is not normalized", () => {
  const [a, b] = [canon('{"s":"é"}'), canon('{"s":"e\\u0301"}')];
  assert.equal(a.canonical, '{"s":"é"}'); // U+00E9 precomposed
  assert.equal(b.canonical, '{"s":"é"}'); // U+0065 + U+0301 decomposed
  assert.notEqual(H(Buffer.from(a.canonical)), H(Buffer.from(b.canonical)));
  assert.equal(Buffer.from(a.canonical, "utf8").length, 10); // é = 2-byte UTF-8
  assert.equal(Buffer.from(b.canonical, "utf8").length, 11); // e+◌́ = 3 bytes
});

// ---------- P1: normalization ----------------------------------------------

test("TV-V-05 missing identity/policy is explicit", () => {
  const r = norm(F.SA, { id: "a", trace_id: "native-ls", parent_run_id: null });
  jeq(r.step, cleanA);
  assert.deepEqual(r.warnings, ["METADATA_ABSENT"]);
  assert.equal(r.step.body.agent, null);
  assert.equal(r.step.body.policy, null);
});

test("TV-V-06 Langfuse physical parent survives root flag", () => {
  const r = norm(F.SB, { id: "b", traceId: "native-lf", parentObservationId: "p", isRootObservation: true });
  jeq(r.step, n(F.SB, "b", [parent("p")]));
  assert.deepEqual(r.warnings, ["METADATA_ABSENT"]);
});

test("TV-V-07 Braintrust row identity differs from span identity", () => {
  const r = norm(F.SC, { id: "row", span_id: "span", root_span_id: "native-bt", span_parents: ["p"] });
  jeq(r.step, n(F.SC, "row", [spanParent("p")], { native_span: "span" }));
  assert.deepEqual(r.warnings, ["METADATA_ABSENT"]);
});

// ---------- P1: graph reduction ---------------------------------------------

test("TV-V-08 native parent is not delegation", () => {
  const child = n(F.SA, "child", [parent("a")]);
  assert.deepEqual(join([cleanA, child]), {
    nodes: 2,
    pairs: [[cleanA.hash, child.hash, "NATIVE_PARENT"]],
    codes: [],
  });
});

test("TV-V-09 same record ID on another platform", () => {
  assert.deepEqual(join([cleanA, n(F.SB, "a")]), { nodes: 2, pairs: [], codes: [] });
});

test("TV-V-10 trace label does not join sources", () => {
  assert.deepEqual(join([cleanA, cleanB, cleanC]), { nodes: 3, pairs: [], codes: [] });
});

test("TV-V-11 offer without accept", () => {
  assert.deepEqual(join([F.A]), { nodes: 1, pairs: [], codes: ["ACCEPT_MISSING"] });
});

test("TV-V-12 accept without offer", () => {
  const bNoOffer = rebody(F.B, { offers: [] });
  assert.deepEqual(join([bNoOffer]), { nodes: 1, pairs: [], codes: ["OFFER_MISSING"] });
});

test("TV-V-13 complete cross-platform chain", () => {
  const r = join([F.A, F.B, F.C], [F.OA, F.OB, F.OC]);
  assert.equal(r.nodes, 3);
  assert.deepEqual(r.pairs, [
    [F.A.hash, F.B.hash, "DELEGATES"],
    [F.B.hash, F.C.hash, "DELEGATES"],
  ].sort());
  assert.deepEqual(r.codes, []);
});

test("TV-V-14 delegation replay to another child record", () => {
  const b1 = rebody(F.B, { offers: [] });
  const b2 = rebody(b1, { record: "b2", native_span: "b2" });
  assert.deepEqual(join([F.A, b1, b2]), { nodes: 3, pairs: [], codes: ["DELEGATION_REUSED"] });
});

test("TV-V-15 exact parent hash binding", () => {
  const bBad = rebody(F.B, {
    offers: [],
    accept: { id: D1, parent: { source: F.SA.id, record: "a", hash: ONE }, scope: ONE },
  });
  assert.deepEqual(join([F.A, bBad]), { nodes: 2, pairs: [], codes: ["PARENT_HASH_MISMATCH"] });
});

test("TV-V-16 conflicting mapped source record", () => {
  const a2 = rebody(cleanA, { policy });
  assert.deepEqual(join([cleanA, a2]), { nodes: 2, pairs: [], codes: ["SOURCE_CONFLICT"] });
});

test("TV-V-17 native cycle", () => {
  const a = n(F.SA, "a", [parent("b")]);
  const b = n(F.SA, "b", [parent("a")]);
  assert.deepEqual(join([a, b]), { nodes: 2, pairs: [], codes: ["CYCLE"] });
});

test("TV-V-18 path bound is not truncation", () => {
  const a = cleanA;
  const b = n(F.SA, "b", [parent("a")]);
  const c = n(F.SA, "c", [parent("b")]);
  assert.deepEqual(
    pathCheck([a, b, c], { source: F.SA.id, record: "c" }, { max_depth: 256, max_nodes: 2 }),
    { nodes: 0, error: "PATH_LIMIT" },
  );
});

test("TV-V-19 import-order invariance", () => {
  const r1 = join([F.A, F.B, F.C], [F.OA, F.OB, F.OC]);
  const r2 = join([F.C, F.A, F.B], [F.OC, F.OA, F.OB]);
  assert.deepEqual(r1, r2);
  const m1 = reduce([F.A, F.B, F.C], [F.OA, F.OB, F.OC], F.W, F.T).manifest;
  const m2 = reduce([F.C, F.A, F.B], [F.OC, F.OA, F.OB], F.W, F.T).manifest;
  assert.equal(J(m1).toString("utf8"), J(m2).toString("utf8"));
  assert.equal(D("VL-GRAPH/1", m1), F.graph_hash);
  assert.equal(F.graph_hash, "254266ac6c98e6250badf6de27c4afdf2e2a32284e4bdb79210aa8b18f5c720a");
});

test("TV-V-20 timestamp and ignored-field changes", () => {
  const r1 = norm(F.SA, { ...RA, start_time: "2099-01-01T00:00:00Z", outputs: { result: "x" } });
  const r2 = norm(F.SA, { ...RA, start_time: "1970-01-01T00:00:00Z", outputs: { result: "y" } });
  jeq(r1.step, F.A);
  jeq(r2.step, F.A);
  assert.deepEqual(r1.warnings, []);
  assert.deepEqual(r2.warnings, []);
});

test("TV-V-21 ambiguous Braintrust span alias", () => {
  const r1 = n(F.SC, "r1", [], { native_span: "p" });
  const r2 = n(F.SC, "r2", [], { native_span: "p" });
  const r3 = n(F.SC, "r3", [spanParent("p")]);
  assert.deepEqual(join([r1, r2, r3]), { nodes: 3, pairs: [], codes: ["PARENT_AMBIGUOUS"] });
});

// ---------- P3: origin/audit trust ------------------------------------------

const trust = F.trust;

test("TV-V-22 missing origin predecessor", () => {
  const oa2 = origin(cleanA, K1, "2", ONE);
  const t = { ...trust, keys: [pin(K1, "origin", F.SA.id, "2")], heads: [] };
  assert.deepEqual(originCheck([oa2], [cleanA.hash], t), {
    integrity: "VALID", origin: "INCOMPLETE", reasons: ["ORIGIN_GAP"],
  });
});

test("TV-V-23 source head pin is ahead", () => {
  const t = {
    ...trust,
    keys: [pin(K1, "origin", F.SA.id, "2")],
    heads: [{ role: "origin", source: F.SA.id, stream: "main", seq: "2", hash: ONE }],
  };
  assert.deepEqual(originCheck([F.OA], [F.A.hash], t), {
    integrity: "VALID", origin: "INCOMPLETE", reasons: ["PIN_AHEAD"],
  });
});

test("TV-V-24 complete trusted bundle", () => {
  const v = verify(F.bundle, F.trust);
  jeq(v, F.verification);
  assert.equal(F.bundle.hash, "d0297474ddc9c378f7e0b16537fa1d702bd2cb160fceaa75832cb4937578ecfa");
});

test("TV-V-25 self-supplied unknown key", () => {
  const t = { v: 1, workspace: F.W, keys: [], heads: [] };
  assert.deepEqual(originCheck([F.OA], [F.A.hash], t), {
    integrity: "VALID", origin: "UNTRUSTED", reasons: ["ORIGIN_KEY_UNKNOWN"],
  });
});

test("TV-V-26 invalid Ed25519 signature", () => {
  const bad = { ...F.OA, signature: Buffer.alloc(64).toString("base64url") };
  const t = { ...trust, keys: [pin(K1, "origin", F.SA.id, "1")], heads: [] };
  assert.deepEqual(originCheck([bad], [F.A.hash], t), {
    integrity: "INVALID", origin: "UNTRUSTED", reasons: ["SIGNATURE_INVALID"],
  });
});

test("TV-V-27 key pin bound to the wrong source", () => {
  const t = { ...trust, keys: [pin(K1, "origin", F.SB.id, "1")], heads: [] };
  assert.deepEqual(originCheck([F.OA], [F.A.hash], t), {
    integrity: "VALID", origin: "UNTRUSTED", reasons: ["ORIGIN_SCOPE_MISMATCH"],
  });
});

test("TV-V-28 retired versus compromised key", () => {
  const compromised = { ...trust, keys: [{ ...pin(K1, "origin", F.SA.id, "1"), status: "COMPROMISED" }], heads: [] };
  assert.deepEqual(originCheck([F.OA], [F.A.hash], compromised), {
    integrity: "VALID", origin: "UNTRUSTED", reasons: ["KEY_COMPROMISED"],
  });
  const retired = { ...trust, keys: [{ ...pin(K1, "origin", F.SA.id, "1"), status: "RETIRED" }], heads: [] };
  assert.deepEqual(originCheck([F.OA], [F.A.hash], retired), {
    integrity: "VALID", origin: "TRUSTED_AT_PIN", reasons: [],
  });
});

test("TV-V-29 same-slot pinned head mismatch", () => {
  const t = {
    ...trust,
    keys: [pin(K1, "origin", F.SA.id, "1")],
    heads: [{ role: "origin", source: F.SA.id, stream: "main", seq: "1", hash: ONE }],
  };
  assert.deepEqual(originCheck([F.OA], [F.A.hash], t), {
    integrity: "VALID", origin: "CONFLICTED", reasons: ["PIN_MISMATCH"],
  });
});

test("TV-V-30 attributable origin fork", () => {
  const fork = origin(cleanA, K1); // same key/source/stream/seq, different hash than OA
  assert.notEqual(fork.hash, F.OA.hash);
  const t = { ...trust, keys: [pin(K1, "origin", F.SA.id, "1")], heads: [] };
  assert.deepEqual(originCheck([F.OA, fork], [F.A.hash, cleanA.hash], t), {
    integrity: "VALID", origin: "CONFLICTED", reasons: ["ORIGIN_FORK"],
  });
});

test("TV-V-31 audit signature cannot replace source evidence", () => {
  const t = {
    ...trust,
    keys: [pin(KA, "audit", null, "11")],
    heads: [head("audit", null, F.bundle.audit.at(-1))],
  };
  assert.deepEqual(originCheck([], [F.A.hash], t), {
    integrity: "VALID", origin: "UNSIGNED", reasons: ["ORIGIN_UNSIGNED"],
  });
});

// ---------- P2/P3: secrets, dispatch, storage -------------------------------

test("TV-V-32 secrets discarded from raw vendor fields", () => {
  const r = norm(F.SA, {
    ...RA,
    inputs: { token: "fixture-secret" },
    outputs: { authorization: "Bearer fixture-secret" },
    error: "fixture-secret",
  });
  jeq(r.step, F.A);
  assert.deepEqual(r.warnings, []);
  // no secret survives in the normalized step or its canonical bytes
  assert.equal(J(r.step).toString("utf8").includes("fixture-secret"), false);

  // stage through a live service and scan the DB for the byte string
  const { svc } = makeService();
  const dbPath = svc.opts.dbPath;
  svc.dispatch(rq("vlq_" + "1".repeat(21), "source.register", F.SA), ADMIN);
  svc.dispatch(rq("vlq_" + "4".repeat(21), "trace.create", { trace: F.T }), ADMIN);
  const poisoned = { ...RA, inputs: { token: "fixture-secret" }, outputs: { authorization: "Bearer fixture-secret" }, error: "fixture-secret" };
  const res = svc.dispatch(rq("vlq_" + "5".repeat(21), "import.stage",
    { import: F.I, trace: F.T, source: F.SA.id, rows: [poisoned], origins: [F.OA], artifacts: [] }), ADMIN);
  assert.equal(res.ok, true);
  svc.close();
  for (const suffix of ["", "-wal", "-shm"]) {
    let bytes;
    try { bytes = readFileSync(dbPath + suffix); } catch { continue; }
    assert.equal(bytes.includes("fixture-secret"), false, `secret persisted in ${dbPath}${suffix}`);
  }
});

test("TV-V-33 no fetch, attachment execution, or archive support", () => {
  const { svc } = makeService();
  try {
    const r = svc.dispatch(
      rq("vlq_" + "q".repeat(21), "import.url", { url: "file:///etc/passwd" }),
      ADMIN,
    );
    assert.deepEqual(r, {
      id: "vlq_" + "q".repeat(21), ok: false,
      error: { code: "METHOD_UNKNOWN", retryable: false, details: { field: "/method" } },
    });
  } finally {
    svc.close();
  }
  assert.throws(
    () => norm(F.SB, { id: "b", trace_id: "native-lf", parent_observation_id: null }),
    (e) => e instanceof VLError && e.code === "PROFILE_MISMATCH",
  );
});

test("TV-V-34 unauthorized workspace lookup", () => {
  const q = "vlq_" + "q".repeat(21);
  const expected = {
    id: q, ok: false,
    error: { code: "FORBIDDEN", retryable: false, details: { field: null } },
  };
  const { svc } = makeService();
  try {
    replayF(svc);
    assert.deepEqual(svc.dispatch(rq(q, "path.get", F.path_request), NONE), expected);
  } finally {
    svc.close();
  }
  const { svc: empty } = makeService();
  try {
    assert.deepEqual(empty.dispatch(rq(q, "path.get", F.path_request), NONE), expected);
  } finally {
    empty.close();
  }
});

test("TV-V-35 stale revision does not commit a stage", () => {
  const { svc } = makeService();
  try {
    svc.dispatch(rq("vlq_" + "1".repeat(21), "source.register", F.SA), ADMIN);
    svc.dispatch(rq("vlq_" + "2".repeat(21), "source.register", F.SB), ADMIN);
    svc.dispatch(rq("vlq_" + "4".repeat(21), "trace.create", { trace: F.T }), ADMIN);
    svc.dispatch(rq(F.ST.stage_id, "import.stage", F.ST.request), ADMIN);
    // commit a different import first → trace advances to revision 1
    const bImport = "vli_" + "j".repeat(21);
    svc.dispatch(rq("vlq_" + "7".repeat(21), "import.stage",
      { import: bImport, trace: F.T, source: F.SB.id, rows: [RB], origins: [F.OB], artifacts: [] }), ADMIN);
    svc.dispatch(rq("vlq_" + "8".repeat(21), "import.commit",
      { import: bImport, expected_revision: "0" }), ADMIN);
    const auditsBefore = svc.db.prepare("SELECT COUNT(*) c FROM audit").get().c;
    const res = svc.dispatch(rq(F.ST.commit_id, "import.commit",
      { import: F.I, expected_revision: "0" }), ADMIN);
    assert.equal(res.ok, false);
    assert.equal(res.error.code, "REVISION_CONFLICT");
    const im = svc.db.prepare("SELECT state FROM imports WHERE id=?").get(F.I);
    assert.equal(im.state, "STAGED");
    const t = svc.db.prepare("SELECT revision FROM traces WHERE id=?").get(F.T);
    assert.equal(String(t.revision), "1");
    const auditsAfter = svc.db.prepare("SELECT COUNT(*) c FROM audit").get().c;
    assert.equal(auditsAfter - auditsBefore, 0);
  } finally {
    svc.close();
  }
});

test("TV-V-36 no authorization or Treaty expansion", () => {
  const { svc } = makeService();
  try {
    replayF(svc);
    const q = "vlq_" + "q".repeat(21);
    for (const method of ["token.mint", "token.chain", "action.dispatch", "treaty.commit", "policy.allow_all"]) {
      assert.deepEqual(svc.dispatch(rq(q, method, {}), ADMIN), {
        id: q, ok: false,
        error: { code: "METHOD_UNKNOWN", retryable: false, details: { field: "/method" } },
      });
    }
  } finally {
    svc.close();
  }
});

test("TV-V-37 signatures never verify real-world semantics", () => {
  const v = verify(F.bundle, F.trust);
  assert.equal(v.semantics, "NOT_VERIFIED");
  assert.equal(v.current_authority, "UNKNOWN");
  assert.equal(v.disclosure, "NORMALIZED_ONLY");
});

test("TV-V-38 principal remains a claim", () => {
  const row = {
    ...RA,
    extra: { metadata: { vislineage: { ...metadata(F.A), agent: agent("alice", "claimed-human") } } },
  };
  const r = norm(F.SA, row);
  jeq(r.step, rebody(F.A, { agent: agent("alice", "claimed-human") }));
  assert.deepEqual(r.warnings, []);
  // principal is text inside the claim — no verification flag exists on Step
  assert.equal("verified" in r.step.body, false);
});

test("TV-V-39 opaque sibling artifact, explicit disclosure", () => {
  const content = Buffer.from('{"format":"world-lineage/1","disclosure":"HASHES_ONLY","hypothetical":true}');
  const digest = H(content);
  const rowA = {
    ...RA,
    extra: {
      metadata: {
        vislineage: {
          ...metadata(F.A),
          attachments: [{ digest, format: "world-lineage/1", bytes: String(content.length) }],
        },
      },
    },
  };
  const sA = norm(F.SA, rowA).step;
  const oA = origin(sA, K1);
  const { svc } = makeService();
  try {
    svc.dispatch(rq("vlq_" + "1".repeat(21), "source.register", F.SA), ADMIN);
    svc.dispatch(rq("vlq_" + "4".repeat(21), "trace.create", { trace: F.T }), ADMIN);
    const st = svc.dispatch(rq("vlq_" + "5".repeat(21), "import.stage", {
      import: F.I, trace: F.T, source: F.SA.id, rows: [rowA], origins: [oA],
      artifacts: [{ digest, format: "world-lineage/1", bytes: String(content.length), content: content.toString("base64url") }],
    }), ADMIN);
    assert.equal(st.ok, true, JSON.stringify(st));
    const c = svc.dispatch(rq("vlq_" + "6".repeat(21), "import.commit", { import: F.I, expected_revision: "0" }), ADMIN);
    assert.equal(c.ok, true);
    const exp = svc.dispatch(rq("vlq_" + "7".repeat(21), "bundle.export", {
      path: { trace: F.T, revision: "1", action: { source: F.SA.id, record: "a" }, max_depth: 256, max_nodes: 4096 },
      attachments: "OMIT",
    }), ADMIN);
    assert.equal(exp.ok, true);
    const { bundle, sunlight } = exp.result;
    assert.equal(bundle.attachments.length, 0, "artifact bytes not included under OMIT");
    assert.equal(bundle.body.attachment_policy, "OMIT");
    assert.equal(bundle.body.disclosure, "NORMALIZED_ONLY");
    assert.equal(sunlight.disclosure, "NORMALIZED_ONLY");
    assert.equal(sunlight.semantics, "NOT_VERIFIED");
    // artifact never parsed: inventory carries digest+bytes only
    const inv = bundle.body.inventory.filter((i) => i.kind === "attachment");
    assert.equal(inv.length, 1);
    assert.equal(inv[0].digest, digest);
    // the artifact content (a foreign "world" claim) is never interpreted
    assert.equal(JSON.stringify(bundle).includes("hypothetical"), false);
  } finally {
    svc.close();
  }
});

test("TV-V-40 commit response lost and retried", () => {
  let faults = 0;
  const { svc } = makeService({
    fault: (point) => {
      if (point === "afterCommit" && faults++ === 0) {
        throw new Error("CONNECTION_LOST");
      }
    },
  });
  try {
    svc.dispatch(rq("vlq_" + "1".repeat(21), "source.register", F.SA), ADMIN);
    svc.dispatch(rq("vlq_" + "2".repeat(21), "source.register", F.SB), ADMIN);
    svc.dispatch(rq("vlq_" + "3".repeat(21), "source.register", F.SC), ADMIN);
    svc.dispatch(rq("vlq_" + "4".repeat(21), "trace.create", { trace: F.T }), ADMIN);
    svc.dispatch(rq(F.ST.stage_id, "import.stage", F.ST.request), ADMIN);
    assert.throws(
      () => svc.dispatch(rq(F.ST.commit_id, "import.commit", { import: F.I, expected_revision: "0" }), ADMIN),
      /CONNECTION_LOST/,
    );
    const auditsBefore = svc.db.prepare("SELECT COUNT(*) c FROM audit").get().c;
    const retry = svc.dispatch(rq(F.ST.commit_id, "import.commit", { import: F.I, expected_revision: "0" }), ADMIN);
    assert.equal(retry.ok, true);
    jeq(retry.result, F.ST.commit);
    const t = svc.db.prepare("SELECT revision FROM traces WHERE id=?").get(F.T);
    assert.equal(String(t.revision), "1");
    const auditsAfter = svc.db.prepare("SELECT COUNT(*) c FROM audit").get().c;
    assert.equal(auditsAfter - auditsBefore, 0, "retry added no audit entries");
    const committed = svc.db.prepare("SELECT COUNT(*) c FROM imports WHERE state='COMMITTED'").get().c;
    assert.equal(committed, 1);
  } finally {
    svc.close();
  }
});

test("TV-V-41 crash before commit leaves no publication", () => {
  const { svc, dir } = makeService({
    fault: (point) => {
      if (point === "afterSign") throw new Error("CRASH");
    },
  });
  try {
    svc.dispatch(rq("vlq_" + "1".repeat(21), "source.register", F.SA), ADMIN);
    svc.dispatch(rq("vlq_" + "4".repeat(21), "trace.create", { trace: F.T }), ADMIN);
    svc.dispatch(rq(F.ST.stage_id, "import.stage", F.ST.request), ADMIN);
    const auditsBefore = svc.db.prepare("SELECT COUNT(*) c FROM audit").get().c;
    const idemBefore = svc.db.prepare("SELECT COUNT(*) c FROM idempotency").get().c;
    assert.throws(
      () => svc.dispatch(rq(F.ST.commit_id, "import.commit", { import: F.I, expected_revision: "0" }), ADMIN),
      /CRASH/,
    );
    // simulate process restart over the same files (fault now spent: one-shot)
    svc.close();
    const svc2 = new WorkspaceService({
      dbPath: path.join(dir, "w.db"), stateDir: dir, artifactsDir: path.join(dir, "artifacts"),
      workspace: F.W, auditKeyId: KA.id, auditKey: KA.secret,
      limits: svc.opts.limits, retention: svc.opts.retention, recoveryPinPath: null,
    });
    try {
      const t = svc2.db.prepare("SELECT revision FROM traces WHERE id=?").get(F.T);
      assert.equal(String(t.revision), "0");
      const im = svc2.db.prepare("SELECT state FROM imports WHERE id=?").get(F.I);
      assert.equal(im.state, "STAGED");
      assert.equal(svc2.db.prepare("SELECT COUNT(*) c FROM audit").get().c, auditsBefore);
      assert.equal(svc2.db.prepare("SELECT COUNT(*) c FROM idempotency").get().c, idemBefore);
      assert.equal(svc2.db.prepare("SELECT COUNT(*) c FROM steps").get().c, 0);
    } finally {
      svc2.close();
    }
  } finally {
    try { svc.close(); } catch { /* already closed */ }
  }
});

test("TV-V-42 stale restore cannot resume writes", () => {
  const { svc, dir } = makeService();
  try {
    // replay through C's stage only → audit head at seq 10
    svc.dispatch(rq("vlq_" + "1".repeat(21), "source.register", F.SA), ADMIN);
    svc.dispatch(rq("vlq_" + "2".repeat(21), "source.register", F.SB), ADMIN);
    svc.dispatch(rq("vlq_" + "3".repeat(21), "source.register", F.SC), ADMIN);
    svc.dispatch(rq("vlq_" + "4".repeat(21), "trace.create", { trace: F.T }), ADMIN);
    svc.dispatch(rq(F.ST.stage_id, "import.stage", F.ST.request), ADMIN);
    svc.dispatch(rq(F.ST.commit_id, "import.commit", { import: F.I, expected_revision: "0" }), ADMIN);
    const bImport = "vli_" + "j".repeat(21);
    svc.dispatch(rq("vlq_" + "7".repeat(21), "import.stage",
      { import: bImport, trace: F.T, source: F.SB.id, rows: [RB], origins: [F.OB], artifacts: [] }), ADMIN);
    svc.dispatch(rq("vlq_" + "8".repeat(21), "import.commit", { import: bImport, expected_revision: "1" }), ADMIN);
    const cImport = "vli_" + "h".repeat(21);
    svc.dispatch(rq("vlq_" + "9".repeat(21), "import.stage",
      { import: cImport, trace: F.T, source: F.SC.id, rows: [RC], origins: [F.OC], artifacts: [] }), ADMIN);
    const entries = auditEntries(svc);
    assert.equal(entries.length, 10);
    assert.equal(entries[9].hash, F.bundle.audit[9].hash, "seq-10 head matches fixture audit[9]");
    svc.close();

    // external pin attests seq 11 — the restored DB lacks that suffix
    const pinPath = writePin(dir, { v: 1, workspace: F.W, seq: "11", hash: F.bundle.audit[10].hash });
    const svc2 = new WorkspaceService({
      dbPath: path.join(dir, "w.db"), stateDir: dir, artifactsDir: path.join(dir, "artifacts"),
      workspace: F.W, auditKeyId: KA.id, auditKey: KA.secret,
      limits: svc.opts.limits, retention: svc.opts.retention, recoveryPinPath: pinPath,
    });
    try {
      assert.equal(svc2.state, "READ_ONLY");
      assert.equal(svc2.readOnlyReason, "PIN_AHEAD");
      const w = svc2.dispatch(rq("vlq_" + "B".repeat(21), "import.commit",
        { import: cImport, expected_revision: "2" }), ADMIN);
      assert.equal(w.ok, false);
      assert.equal(w.error.code, "READ_ONLY");
    } finally {
      svc2.close();
    }
  } finally {
    try { svc.close(); } catch { /* already closed */ }
  }
});

// ---------- golden: full §14 replay -----------------------------------------

test("golden: replay produces F.graph_hash, F.bundle, audit head", () => {
  const { svc } = makeService();
  try {
    const out = replayF(svc);
    for (const r of out) assert.equal(r.ok, true, JSON.stringify(r));
    const entries = auditEntries(svc);
    assert.equal(entries.length, 11);
    assert.equal(entries[10].hash, "a6e7e24ea1663506055fcfe20cfaf08ed0aaf377850f5af33d4e60bb4d877bd6");
    const tg = svc.dispatch(rq("vlq_" + "f".repeat(21), "trace.get", { trace: F.T }), ADMIN);
    assert.equal(tg.result.revision, "3");
    assert.equal(tg.result.graph, F.graph_hash);
    const p = svc.dispatch(rq("vlq_" + "f".repeat(21), "path.get", F.path_request), ADMIN);
    jeq(p.result, F.path);
    const ex = svc.dispatch(rq("vlq_" + "f".repeat(21), "bundle.export",
      { path: F.path_request, attachments: "OMIT" }), ADMIN);
    jeq(ex.result.bundle, F.bundle);
    jeq(ex.result.sunlight, F.sunlight);
    const v = svc.dispatch(rq("vlq_" + "f".repeat(21), "bundle.verify",
      { bundle: F.bundle, trust: F.trust }), ADMIN);
    jeq(v.result, F.verification);
  } finally {
    svc.close();
  }
});
