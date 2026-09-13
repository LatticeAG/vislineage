"""Offline VisLineage bundle verifier (vislineage/1).

verify(bundle: dict, trust: dict) -> dict — returns the complete Verification
on well-formed input, or {ok:false,error:{code,retryable:false,details:{field}}}
on structural parse/version/limit failures. No network, no remote fallback.
"""

import base64
import hashlib
import re

from .canon import canonicalize

ZERO = "0" * 64
PROTOCOL_VERSION = 1

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_COUNTER_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_COUNTER_MAX = 9223372036854775807
_B64U_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_ID_RE = {
    "workspace": "vlw_", "source": "vls_", "trace": "vlt_", "import": "vli_",
    "request": "vlq_", "delegation": "vld_", "key": "vlk_",
}
_ID_ALPHABET = re.compile(r"^[_\-0-9a-zA-Z]{21}$")
_NS_RE = re.compile(r"^[a-z][a-z0-9.\-]{0,63}$")


class Fail(Exception):
    def __init__(self, code, field=None):
        super().__init__(code)
        self.code = code
        self.field = field


def _failure(e: Fail):
    return {"ok": False, "error": {"code": e.code, "retryable": False, "details": {"field": e.field}}}


def H(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def D(tag: str, x) -> str:
    return H(tag.encode("utf-8") + b"\x00" + canonicalize(x))


def is_obj(v):
    return isinstance(v, dict)


def is_hash(v):
    return isinstance(v, str) and bool(_HASH_RE.match(v))


def is_counter(v):
    return isinstance(v, str) and bool(_COUNTER_RE.match(v)) and int(v) <= _COUNTER_MAX


def is_id(kind, v):
    return isinstance(v, str) and v.startswith(_ID_RE[kind]) and bool(_ID_ALPHABET.match(v[len(_ID_RE[kind]):]))


def is_text(v):
    if not isinstance(v, str) or len(v) == 0 or len(v) > 256 or len(v.encode("utf-8")) > 1024:
        return False
    return all(ord(c) >= 0x20 and ord(c) != 0x7F for c in v)


def is_b64u(v, nbytes):
    if not isinstance(v, str) or not _B64U_RE.match(v):
        return False
    try:
        return len(base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))) == nbytes
    except Exception:
        return False


def is_pubkey(v):
    return is_b64u(v, 32)


def is_sig(v):
    return isinstance(v, str) and len(v) == 86 and is_b64u(v, 64)


def _keys(v, field, required, optional=()):
    allowed = set(required) | set(optional)
    for k in required:
        if k not in v:
            raise Fail("SCHEMA_INVALID", f"{field}/{k}")
    for k in v:
        if k not in allowed:
            raise Fail("SCHEMA_INVALID", f"{field}/{k}")


def _text(v, f):
    if not is_text(v):
        raise Fail("SCHEMA_INVALID", f)
    return v


def _hash(v, f):
    if not is_hash(v):
        raise Fail("SCHEMA_INVALID", f)
    return v


def _counter(v, f):
    if not is_counter(v):
        raise Fail("SCHEMA_INVALID", f)
    return v


def _id(v, kind, f):
    if not isinstance(v, str):
        raise Fail("SCHEMA_INVALID", f)
    if not is_id(kind, v):
        raise Fail("ID_INVALID", f)
    return v


def _agent(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["namespace", "subject", "principal"])
    if not isinstance(v["namespace"], str) or not _NS_RE.match(v["namespace"]):
        raise Fail("SCHEMA_INVALID", f + "/namespace")
    _text(v["subject"], f + "/subject")
    if v["principal"] is not None:
        _text(v["principal"], f + "/principal")


def _policy(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["digest", "version", "decision"])
    _hash(v["digest"], f + "/digest")
    _text(v["version"], f + "/version")
    if v["decision"] not in ("ALLOW", "REVIEW", "DENY", "UNKNOWN"):
        raise Fail("SCHEMA_INVALID", f + "/decision")


def _offer(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["id", "child_source", "child_agent", "scope"])
    _id(v["id"], "delegation", f + "/id")
    _id(v["child_source"], "source", f + "/child_source")
    _agent(v["child_agent"], f + "/child_agent")
    _hash(v["scope"], f + "/scope")


def _stepref(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["source", "record", "hash"])
    _id(v["source"], "source", f + "/source")
    _text(v["record"], f + "/record")
    _hash(v["hash"], f + "/hash")


def _accept(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["id", "parent", "scope"])
    _id(v["id"], "delegation", f + "/id")
    _stepref(v["parent"], f + "/parent")
    _hash(v["scope"], f + "/scope")


def _attref(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["digest", "format", "bytes"])
    _hash(v["digest"], f + "/digest")
    _text(v["format"], f + "/format")
    _counter(v["bytes"], f + "/bytes")


def _natparent(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["kind", "value"])
    if v["kind"] not in ("record", "span"):
        raise Fail("SCHEMA_INVALID", f + "/kind")
    _text(v["value"], f + "/value")


def _stepbody(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["v", "workspace", "trace", "source", "profile", "record", "native_trace",
                 "native_span", "parents", "agent", "policy", "offers", "accept", "attachments"])
    if v["v"] != 1:
        raise Fail("UNSUPPORTED_VERSION", f + "/v")
    _id(v["workspace"], "workspace", f + "/workspace")
    _id(v["trace"], "trace", f + "/trace")
    _id(v["source"], "source", f + "/source")
    if v["profile"] not in ("langsmith-runs/1", "langfuse-observations/1", "braintrust-spans/1"):
        raise Fail("PROFILE_MISMATCH", f + "/profile")
    _text(v["record"], f + "/record")
    _text(v["native_trace"], f + "/native_trace")
    _text(v["native_span"], f + "/native_span")
    if not isinstance(v["parents"], list) or len(v["parents"]) > 16:
        raise Fail("SCHEMA_INVALID", f + "/parents")
    for i, p in enumerate(v["parents"]):
        _natparent(p, f + f"/parents/{i}")
    if len({(p["kind"], p["value"]) for p in v["parents"]}) != len(v["parents"]):
        raise Fail("SCHEMA_INVALID", f + "/parents")
    if v["agent"] is not None:
        _agent(v["agent"], f + "/agent")
    if v["policy"] is not None:
        _policy(v["policy"], f + "/policy")
    if not isinstance(v["offers"], list) or len(v["offers"]) > 32:
        raise Fail("SCHEMA_INVALID", f + "/offers")
    for i, o in enumerate(v["offers"]):
        _offer(o, f + f"/offers/{i}")
    if len({o["id"] for o in v["offers"]}) != len(v["offers"]):
        raise Fail("SCHEMA_INVALID", f + "/offers")
    if v["accept"] is not None:
        _accept(v["accept"], f + "/accept")
    if not isinstance(v["attachments"], list) or len(v["attachments"]) > 16:
        raise Fail("SCHEMA_INVALID", f + "/attachments")
    for i, a in enumerate(v["attachments"]):
        _attref(a, f + f"/attachments/{i}")
    if len({(a["format"], a["digest"]) for a in v["attachments"]}) != len(v["attachments"]):
        raise Fail("SCHEMA_INVALID", f + "/attachments")


def _step(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["body", "hash"])
    _stepbody(v["body"], f + "/body")
    _hash(v["hash"], f + "/hash")


def _originbody(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["v", "workspace", "source", "stream", "seq", "prev", "step", "key"])
    if v["v"] != 1:
        raise Fail("UNSUPPORTED_VERSION", f + "/v")
    _id(v["workspace"], "workspace", f + "/workspace")
    _id(v["source"], "source", f + "/source")
    _text(v["stream"], f + "/stream")
    _counter(v["seq"], f + "/seq")
    if int(v["seq"]) < 1:
        raise Fail("SCHEMA_INVALID", f + "/seq")
    _hash(v["prev"], f + "/prev")
    _hash(v["step"], f + "/step")
    _id(v["key"], "key", f + "/key")


def _origin(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["body", "hash", "signature"])
    _originbody(v["body"], f + "/body")
    _hash(v["hash"], f + "/hash")
    if not is_sig(v["signature"]):
        raise Fail("SCHEMA_INVALID", f + "/signature")
    b = v["body"]
    if b["seq"] == "1" and b["prev"] != ZERO:
        raise Fail("SCHEMA_INVALID", f + "/body/prev")
    if b["seq"] != "1" and b["prev"] == ZERO:
        raise Fail("SCHEMA_INVALID", f + "/body/prev")


def _artifact(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["digest", "format", "bytes", "content"])
    _hash(v["digest"], f + "/digest")
    _text(v["format"], f + "/format")
    _counter(v["bytes"], f + "/bytes")
    if not isinstance(v["content"], str):
        raise Fail("SCHEMA_INVALID", f + "/content")


def _gap(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["code", "subject", "related"])
    if v["code"] not in (
        "PARENT_MISSING", "PARENT_AMBIGUOUS", "OFFER_MISSING", "ACCEPT_MISSING",
        "DELEGATION_MISMATCH", "PARENT_HASH_MISMATCH", "DELEGATION_REUSED",
        "SOURCE_CONFLICT", "CYCLE", "ORIGIN_GAP", "ORIGIN_FORK",
    ):
        raise Fail("SCHEMA_INVALID", f + "/code")
    _hash(v["subject"], f + "/subject")
    if not isinstance(v["related"], list) or len(v["related"]) > 100000:
        raise Fail("SCHEMA_INVALID", f + "/related")
    for i, r in enumerate(v["related"]):
        _hash(r, f + f"/related/{i}")


def _edge(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["body", "hash"])
    b = v["body"]
    if not is_obj(b):
        raise Fail("SCHEMA_INVALID", f + "/body")
    _keys(b, f + "/body", ["v", "trace", "parent", "child", "kind", "delegation", "scope"])
    if b["v"] != 1:
        raise Fail("UNSUPPORTED_VERSION", f + "/body/v")
    _id(b["trace"], "trace", f + "/body/trace")
    _hash(b["parent"], f + "/body/parent")
    _hash(b["child"], f + "/body/child")
    if b["kind"] not in ("NATIVE_PARENT", "DELEGATES"):
        raise Fail("SCHEMA_INVALID", f + "/body/kind")
    if b["delegation"] is not None:
        _id(b["delegation"], "delegation", f + "/body/delegation")
    if b["scope"] is not None:
        _hash(b["scope"], f + "/body/scope")
    _hash(v["hash"], f + "/hash")


def _manifest(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["v", "workspace", "trace", "steps", "origins", "edges", "gaps"])
    if v["v"] != 1:
        raise Fail("UNSUPPORTED_VERSION", f + "/v")
    _id(v["workspace"], "workspace", f + "/workspace")
    _id(v["trace"], "trace", f + "/trace")
    caps = {"steps": 100000, "origins": 100000, "edges": 400000, "gaps": 400000}
    for k, cap in caps.items():
        if not isinstance(v[k], list) or len(v[k]) > cap:
            raise Fail("SCHEMA_INVALID", f + "/" + k)
    for i, s in enumerate(v["steps"]):
        _hash(s, f + f"/steps/{i}")
    for i, s in enumerate(v["origins"]):
        _hash(s, f + f"/origins/{i}")
    for i, s in enumerate(v["edges"]):
        _hash(s, f + f"/edges/{i}")
    for i, g in enumerate(v["gaps"]):
        _gap(g, f + f"/gaps/{i}")


def _pathreq(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["trace", "revision", "action", "max_depth", "max_nodes"])
    _id(v["trace"], "trace", f + "/trace")
    _counter(v["revision"], f + "/revision")
    if not is_obj(v["action"]):
        raise Fail("SCHEMA_INVALID", f + "/action")
    _keys(v["action"], f + "/action", ["source", "record"])
    _id(v["action"]["source"], "source", f + "/action/source")
    _text(v["action"]["record"], f + "/action/record")
    for k, cap in (("max_depth", 256), ("max_nodes", 4096)):
        n = v[k]
        if not isinstance(n, int) or isinstance(n, bool) or n < 1 or n > cap:
            raise Fail("SCHEMA_INVALID", f + "/" + k)


def _pathres(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["trace", "revision", "graph", "action", "steps", "origins", "edges",
                 "gaps", "structural", "evidence", "disclosure"])
    _id(v["trace"], "trace", f + "/trace")
    _counter(v["revision"], f + "/revision")
    _hash(v["graph"], f + "/graph")
    _hash(v["action"], f + "/action")
    for k, cap in (("steps", 4096), ("origins", 100000), ("edges", 16384), ("gaps", 100000)):
        if not isinstance(v[k], list) or len(v[k]) > cap:
            raise Fail("SCHEMA_INVALID", f + "/" + k)
    for i, s in enumerate(v["steps"]):
        _step(s, f + f"/steps/{i}")
    for i, o in enumerate(v["origins"]):
        _origin(o, f + f"/origins/{i}")
    for i, e in enumerate(v["edges"]):
        _edge(e, f + f"/edges/{i}")
    for i, g in enumerate(v["gaps"]):
        _gap(g, f + f"/gaps/{i}")
    if v["structural"] not in ("COMPLETE_RELATIVE", "INCOMPLETE", "CONFLICTED"):
        raise Fail("SCHEMA_INVALID", f + "/structural")
    if v["evidence"] != "CLAIMED":
        raise Fail("SCHEMA_INVALID", f + "/evidence")
    if v["disclosure"] != "NORMALIZED_ONLY":
        raise Fail("SCHEMA_INVALID", f + "/disclosure")


def _invitem(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["kind", "digest", "bytes"])
    if v["kind"] not in ("step", "origin", "audit", "attachment"):
        raise Fail("SCHEMA_INVALID", f + "/kind")
    _hash(v["digest"], f + "/digest")
    _counter(v["bytes"], f + "/bytes")


def _auditdata(v, f):
    if not is_obj(v) or not isinstance(v.get("kind"), str):
        raise Fail("SCHEMA_INVALID", f)
    kind = v["kind"]
    if kind == "WorkspaceCreated":
        _keys(v, f, ["kind", "config"]); _hash(v["config"], f + "/config")
    elif kind == "SourceRegistered":
        _keys(v, f, ["kind", "source"])
        s = v["source"]
        if not is_obj(s):
            raise Fail("SCHEMA_INVALID", f + "/source")
        _keys(s, f + "/source", ["id", "profile", "namespace", "project"])
        _id(s["id"], "source", f + "/source/id")
        if s["profile"] not in ("langsmith-runs/1", "langfuse-observations/1", "braintrust-spans/1"):
            raise Fail("SCHEMA_INVALID", f + "/source/profile")
        _text(s["namespace"], f + "/source/namespace")
        _text(s["project"], f + "/source/project")
    elif kind == "TraceCreated":
        _keys(v, f, ["kind", "trace", "graph"])
        _id(v["trace"], "trace", f + "/trace"); _hash(v["graph"], f + "/graph")
    elif kind == "ImportStaged":
        _keys(v, f, ["kind", "import", "trace", "batch", "rows"])
        _id(v["import"], "import", f + "/import"); _id(v["trace"], "trace", f + "/trace")
        _hash(v["batch"], f + "/batch")
        if not isinstance(v["rows"], int) or isinstance(v["rows"], bool) or v["rows"] < 0:
            raise Fail("SCHEMA_INVALID", f + "/rows")
    elif kind == "ImportCommitted":
        _keys(v, f, ["kind", "import", "trace", "revision", "graph", "batch"])
        _id(v["import"], "import", f + "/import"); _id(v["trace"], "trace", f + "/trace")
        _counter(v["revision"], f + "/revision"); _hash(v["graph"], f + "/graph"); _hash(v["batch"], f + "/batch")
    elif kind == "ImportCancelled":
        _keys(v, f, ["kind", "import", "reason"])
        _id(v["import"], "import", f + "/import")
        if v["reason"] not in ("USER", "EXPIRED"):
            raise Fail("SCHEMA_INVALID", f + "/reason")
    elif kind == "RetentionPruned":
        _keys(v, f, ["kind", "traces", "artifacts"])
        if not isinstance(v["traces"], list) or len(v["traces"]) > 1024:
            raise Fail("SCHEMA_INVALID", f + "/traces")
        for i, t in enumerate(v["traces"]):
            if not is_obj(t):
                raise Fail("SCHEMA_INVALID", f + f"/traces/{i}")
            _keys(t, f + f"/traces/{i}", ["trace", "revisions"])
            _id(t["trace"], "trace", f + f"/traces/{i}/trace")
            if not isinstance(t["revisions"], list) or len(t["revisions"]) > 10000:
                raise Fail("SCHEMA_INVALID", f + f"/traces/{i}/revisions")
            for j, r in enumerate(t["revisions"]):
                _counter(r, f + f"/traces/{i}/revisions/{j}")
        if not isinstance(v["artifacts"], list) or len(v["artifacts"]) > 400000:
            raise Fail("SCHEMA_INVALID", f + "/artifacts")
        for i, a in enumerate(v["artifacts"]):
            _hash(a, f + f"/artifacts/{i}")
    elif kind == "KeyRotated":
        _keys(v, f, ["kind", "old", "next", "next_public"])
        _id(v["old"], "key", f + "/old"); _id(v["next"], "key", f + "/next")
        if not is_pubkey(v["next_public"]):
            raise Fail("SCHEMA_INVALID", f + "/next_public")
    else:
        raise Fail("SCHEMA_INVALID", f + "/kind")


def _audit(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["body", "hash", "signature"])
    b = v["body"]
    if not is_obj(b):
        raise Fail("SCHEMA_INVALID", f + "/body")
    _keys(b, f + "/body", ["v", "workspace", "seq", "prev", "request", "key", "data"])
    if b["v"] != 1:
        raise Fail("UNSUPPORTED_VERSION", f + "/body/v")
    _id(b["workspace"], "workspace", f + "/body/workspace")
    _counter(b["seq"], f + "/body/seq")
    _hash(b["prev"], f + "/body/prev")
    _id(b["request"], "request", f + "/body/request")
    _id(b["key"], "key", f + "/body/key")
    _auditdata(b["data"], f + "/body/data")
    _hash(v["hash"], f + "/hash")
    if not is_sig(v["signature"]):
        raise Fail("SCHEMA_INVALID", f + "/signature")


def _bundle(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["body", "hash", "steps", "origins", "audit", "attachments"])
    b = v["body"]
    if not is_obj(b):
        raise Fail("SCHEMA_INVALID", f + "/body")
    _keys(b, f + "/body", ["v", "format", "workspace", "trace", "revision", "graph",
                           "path_request", "path", "inventory", "attachment_policy",
                           "disclosure", "trust_required"])
    if b["v"] != 1:
        raise Fail("UNSUPPORTED_VERSION", f + "/body/v")
    if b["format"] != "vislineage-bundle/1":
        raise Fail("SCHEMA_INVALID", f + "/body/format")
    _id(b["workspace"], "workspace", f + "/body/workspace")
    _id(b["trace"], "trace", f + "/body/trace")
    _counter(b["revision"], f + "/body/revision")
    _manifest(b["graph"], f + "/body/graph")
    _pathreq(b["path_request"], f + "/body/path_request")
    _pathres(b["path"], f + "/body/path")
    if not isinstance(b["inventory"], list) or len(b["inventory"]) > 400000:
        raise Fail("SCHEMA_INVALID", f + "/body/inventory")
    for i, it in enumerate(b["inventory"]):
        _invitem(it, f + f"/body/inventory/{i}")
    if b["attachment_policy"] not in ("INCLUDE", "OMIT"):
        raise Fail("SCHEMA_INVALID", f + "/body/attachment_policy")
    if b["disclosure"] != "NORMALIZED_ONLY":
        raise Fail("SCHEMA_INVALID", f + "/body/disclosure")
    if b["trust_required"] is not True:
        raise Fail("SCHEMA_INVALID", f + "/body/trust_required")
    _hash(v["hash"], f + "/hash")
    for k, cap in (("steps", 100000), ("origins", 100000), ("audit", 100000), ("attachments", 100000)):
        if not isinstance(v[k], list) or len(v[k]) > cap:
            raise Fail("SCHEMA_INVALID", f + "/" + k)
    for i, s in enumerate(v["steps"]):
        _step(s, f + f"/steps/{i}")
    for i, o in enumerate(v["origins"]):
        _origin(o, f + f"/origins/{i}")
    for i, a in enumerate(v["audit"]):
        _audit(a, f + f"/audit/{i}")
    for i, a in enumerate(v["attachments"]):
        _artifact(a, f + f"/attachments/{i}")


def _keypin(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["id", "public", "role", "workspace", "source", "stream",
                 "first_seq", "last_seq", "status"])
    _id(v["id"], "key", f + "/id")
    if not is_pubkey(v["public"]):
        raise Fail("SCHEMA_INVALID", f + "/public")
    if v["role"] not in ("origin", "audit"):
        raise Fail("SCHEMA_INVALID", f + "/role")
    _id(v["workspace"], "workspace", f + "/workspace")
    if v["source"] is not None:
        _id(v["source"], "source", f + "/source")
    if v["stream"] is not None:
        _text(v["stream"], f + "/stream")
    _counter(v["first_seq"], f + "/first_seq")
    _counter(v["last_seq"], f + "/last_seq")
    if v["status"] not in ("ACTIVE", "RETIRED", "COMPROMISED"):
        raise Fail("SCHEMA_INVALID", f + "/status")


def _headpin(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["role", "source", "stream", "seq", "hash"])
    if v["role"] not in ("origin", "audit"):
        raise Fail("SCHEMA_INVALID", f + "/role")
    if v["source"] is not None:
        _id(v["source"], "source", f + "/source")
    if v["stream"] is not None:
        _text(v["stream"], f + "/stream")
    _counter(v["seq"], f + "/seq")
    _hash(v["hash"], f + "/hash")


def _trust(v, f):
    if not is_obj(v):
        raise Fail("SCHEMA_INVALID", f)
    _keys(v, f, ["v", "workspace", "keys", "heads"])
    if v["v"] != 1:
        raise Fail("UNSUPPORTED_VERSION", f + "/v")
    _id(v["workspace"], "workspace", f + "/workspace")
    if not isinstance(v["keys"], list) or not isinstance(v["heads"], list):
        raise Fail("SCHEMA_INVALID", f)
    for i, k in enumerate(v["keys"]):
        _keypin(k, f + f"/keys/{i}")
    for i, h in enumerate(v["heads"]):
        _headpin(h, f + f"/heads/{i}")
    _validate_trust(v, f)


def _validate_trust(tp, field):
    def bt(f, m):
        raise Fail("TRUST_INVALID", f)

    key_ids = set()
    pubs_roles = {}
    intervals = {}
    for k in tp["keys"]:
        if k["workspace"] != tp["workspace"]:
            bt(field + "/keys", "key pin workspace mismatch")
        if k["id"] in key_ids:
            bt(field + "/keys", "duplicate key id")
        key_ids.add(k["id"])
        if int(k["first_seq"]) < 1 or int(k["first_seq"]) > int(k["last_seq"]):
            bt(field + "/keys", "bad sequence interval")
        if k["role"] == "origin":
            if k["source"] is None or k["stream"] is None:
                bt(field + "/keys", "origin pin requires source/stream")
        elif k["source"] is not None or k["stream"] is not None:
            bt(field + "/keys", "audit pin requires null source/stream")
        pubs_roles.setdefault(k["public"], set()).add(k["role"])
        scope = (k["role"], k["source"], k["stream"])
        for lo, hi in intervals.get(scope, []):
            if int(k["first_seq"]) <= hi and lo <= int(k["last_seq"]):
                bt(field + "/keys", "overlapping key intervals")
        intervals.setdefault(scope, []).append((int(k["first_seq"]), int(k["last_seq"])))
    for roles in pubs_roles.values():
        if len(roles) > 1:
            bt(field + "/keys", "public key reused across roles")
    heads = {}
    for h in tp["heads"]:
        if int(h["seq"]) < 1:
            bt(field + "/heads", "bad head seq")
        if h["role"] == "origin":
            if h["source"] is None or h["stream"] is None:
                bt(field + "/heads", "origin head requires source/stream")
        elif h["source"] is not None or h["stream"] is not None:
            bt(field + "/heads", "audit head requires null source/stream")
        k = (h["role"], h["source"], h["stream"], h["seq"])
        if k in heads and heads[k] != h["hash"]:
            bt(field + "/heads", "conflicting head pins")
        heads[k] = h["hash"]


# --- strict Ed25519 ----------------------------------------------------------

_L = 7237005577332262213976186563042994240857116359379907606001950938285454250989
_P = 57896044618658097711785492504343953926634992332820282019728792003956564819949
_SMALL_ORDER = {
    bytes.fromhex(s)
    for s in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445c13439c656b30da05f1560c9800",
        "e00000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    )
}


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_signature(public_b64: str, message: bytes, sig_b64: str) -> bool:
    try:
        pub = _b64d(public_b64)
        sig = _b64d(sig_b64)
    except Exception:
        return False
    if len(pub) != 32 or len(sig) != 64:
        return False
    if pub in _SMALL_ORDER:
        return False
    r, s = sig[:32], sig[32:]
    if r in _SMALL_ORDER:
        return False
    if int.from_bytes(s, "little") >= _L:
        return False
    if int.from_bytes(bytes([*pub[:31], pub[31] & 0x7F]), "little") >= _P:
        return False
    if int.from_bytes(bytes([*r[:31], r[31] & 0x7F]), "little") >= _P:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise RuntimeError("cryptography package is required for verification")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
        return True
    except Exception:
        return False


def sign_message(tag: str, hash_hex: str) -> bytes:
    return tag.encode("utf-8") + b"\x00" + bytes.fromhex(hash_hex)


# --- graph reduction (port of reduce.ts) --------------------------------------

def _gap_sort_key(g):
    return (g["code"], g["subject"], canonicalize(g["related"]))


def reduce(steps, origins, workspace, trace):
    gaps = []
    by_hash = {s["hash"]: s for s in steps}

    by_record = {}
    by_nt_record = {}
    by_nt_span = {}
    for s in steps:
        b = s["body"]
        by_record.setdefault((b["source"], b["record"]), []).append(s)
        by_nt_record.setdefault((b["source"], b["native_trace"], b["record"]), []).append(s)
        by_nt_span.setdefault((b["source"], b["native_trace"], b["native_span"]), []).append(s)

    def uniq_sorted_hashes(cands):
        return sorted({c["hash"] for c in cands})

    conflicted = set()
    for rk, cands in by_record.items():
        hs = uniq_sorted_hashes(cands)
        if len(hs) > 1:
            conflicted.add(rk)
            gaps.append({"code": "SOURCE_CONFLICT", "subject": hs[0], "related": hs})

    def edge(parent, child, kind, delegation, scope):
        body = {"v": 1, "trace": trace, "parent": parent, "child": child,
                "kind": kind, "delegation": delegation, "scope": scope}
        return {"body": body, "hash": D("VL-EDGE/1", body)}

    candidate_edges = {}
    for s in steps:
        b = s["body"]
        child_conf = (b["source"], b["record"]) in conflicted
        for p in b["parents"]:
            key = (b["source"], b["native_trace"], p["value"])
            cands = (by_nt_record if p["kind"] == "record" else by_nt_span).get(key, [])
            hs = uniq_sorted_hashes(cands)
            if not hs:
                gaps.append({"code": "PARENT_MISSING", "subject": s["hash"], "related": []})
                continue
            if len(hs) > 1:
                gaps.append({"code": "PARENT_AMBIGUOUS", "subject": s["hash"], "related": hs})
                continue
            if child_conf:
                continue
            e = edge(hs[0], s["hash"], "NATIVE_PARENT", None, None)
            candidate_edges[e["hash"]] = e

    offers = {}
    accepts = {}
    for s in steps:
        for o in s["body"]["offers"]:
            offers.setdefault(o["id"], []).append((s, o))
        if s["body"]["accept"] is not None:
            a = s["body"]["accept"]
            accepts.setdefault(a["id"], []).append((s, a))

    for did in sorted(set(offers) | set(accepts)):
        ofs = offers.get(did, [])
        acs = accepts.get(did, [])
        offer_hashes = {s["hash"] for s, _ in ofs}
        accept_hashes = {s["hash"] for s, _ in acs}
        if len(offer_hashes) >= 2 or len(accept_hashes) >= 2:
            involved = sorted(offer_hashes | accept_hashes)
            gaps.append({"code": "DELEGATION_REUSED", "subject": involved[0], "related": involved})
            continue
        if not ofs:
            gaps.append({"code": "OFFER_MISSING", "subject": acs[0][0]["hash"], "related": []})
            continue
        if not acs:
            gaps.append({"code": "ACCEPT_MISSING", "subject": ofs[0][0]["hash"], "related": []})
            continue
        offer_step, offer = ofs[0]
        child_step, accept = acs[0]
        named = uniq_sorted_hashes(
            by_record.get((accept["parent"]["source"], accept["parent"]["record"]), []))
        exact = by_hash.get(accept["parent"]["hash"]) if accept["parent"]["hash"] in named else None
        if not named:
            gaps.append({"code": "DELEGATION_MISMATCH", "subject": child_step["hash"], "related": []})
            continue
        if exact is None:
            gaps.append({"code": "PARENT_HASH_MISMATCH", "subject": child_step["hash"], "related": named})
            continue
        cb = child_step["body"]
        child_agent_ok = cb["agent"] is not None and canonicalize(cb["agent"]) == canonicalize(offer["child_agent"])
        matched = (
            offer_step["hash"] == exact["hash"]
            and offer["child_source"] == cb["source"]
            and child_agent_ok
            and offer["scope"] == accept["scope"]
            and exact["body"]["source"] != cb["source"]
            and exact["body"]["trace"] == cb["trace"]
            and any(canonicalize(o) == canonicalize(offer) for o in exact["body"]["offers"])
        )
        if not matched:
            gaps.append({"code": "DELEGATION_MISMATCH", "subject": child_step["hash"], "related": named})
            continue
        e = edge(exact["hash"], child_step["hash"], "DELEGATES", did, offer["scope"])
        candidate_edges[e["hash"]] = e

    # iterative Tarjan SCC
    adj = {}
    nodes = set()
    for e in candidate_edges.values():
        nodes.add(e["body"]["parent"])
        nodes.add(e["body"]["child"])
        adj.setdefault(e["body"]["parent"], []).append(e["body"]["child"])
    index = {}
    low = {}
    onstack = set()
    stack = []
    comp_of = {}
    counter = 0
    comp_count = 0
    for start in nodes:
        if start in index:
            continue
        work = [(start, iter(adj.get(start, [])))]
        index[start] = low[start] = counter
        counter += 1
        stack.append(start)
        onstack.add(start)
        while work:
            v, it = work[-1]
            nx = next(it, None)
            if nx is not None:
                w = nx
                if w not in index:
                    index[w] = low[w] = counter
                    counter += 1
                    stack.append(w)
                    onstack.add(w)
                    work.append((w, iter(adj.get(w, []))))
                elif w in onstack:
                    low[v] = min(low[v], index[w])
                continue
            work.pop()
            if work:
                p = work[-1][0]
                low[p] = min(low[p], low[v])
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop()
                    onstack.discard(w)
                    comp.append(w)
                    comp_of[w] = comp_count
                    if w == v:
                        break
                self_loop = len(comp) == 1 and v in adj.get(v, [])
                if len(comp) > 1 or self_loop:
                    comp_sorted = sorted(comp)
                    gaps.append({"code": "CYCLE", "subject": comp_sorted[0], "related": comp_sorted})
                comp_count += 1

    edges = [
        e for e in candidate_edges.values()
        if comp_of.get(e["body"]["parent"]) != comp_of.get(e["body"]["child"])
        or e["body"]["parent"] not in comp_of
    ]

    # origin stream diagnostics over trace steps
    step_hashes = set(by_hash)
    streams = {}
    for o in origins:
        streams.setdefault((o["body"]["source"], o["body"]["stream"]), []).append(o)
    for k, lst in streams.items():
        slots = {}
        for o in lst:
            slots.setdefault(int(o["body"]["seq"]), {})[o["hash"]] = o["body"]["prev"]
        broken = set()
        for seq, hprev in slots.items():
            prev_slot = slots.get(seq - 1)
            for prev in hprev.values():
                if seq == 1:
                    if prev != ZERO:
                        broken.add(seq)
                elif prev_slot is None or prev not in prev_slot:
                    broken.add(seq)
        forks = {seq: sorted(hp) for seq, hp in slots.items() if len(hp) >= 2}
        attest = {}
        for o in lst:
            if o["body"]["step"] in step_hashes:
                attest.setdefault(o["body"]["step"], []).append(int(o["body"]["seq"]))
        for sh, positions in attest.items():
            if any(any(p >= b for p in positions) for b in broken):
                gaps.append({"code": "ORIGIN_GAP", "subject": sh, "related": []})
            for f, hashes in forks.items():
                if any(p >= f for p in positions):
                    gaps.append({"code": "ORIGIN_FORK", "subject": sh, "related": hashes})

    seen = set()
    uniq = []
    for g in gaps:
        k = (g["code"], g["subject"], canonicalize(g["related"]))
        if k not in seen:
            seen.add(k)
            uniq.append(g)
    uniq.sort(key=_gap_sort_key)

    manifest = {
        "v": 1,
        "workspace": workspace,
        "trace": trace,
        "steps": sorted(by_hash),
        "origins": sorted({o["hash"] for o in origins}),
        "edges": sorted(e["hash"] for e in edges),
        "gaps": uniq,
    }
    return {"manifest": manifest, "edges": edges, "gaps": uniq}


# --- path recomputation --------------------------------------------------------

_CONFLICT_CODES = {"SOURCE_CONFLICT", "PARENT_AMBIGUOUS", "DELEGATION_REUSED", "CYCLE", "ORIGIN_FORK"}


class _PathLimit(Exception):
    pass


def compute_path(steps, edges, origins, gaps, graph_hash, req):
    cands = [s for s in steps
             if s["body"]["source"] == req["action"]["source"]
             and s["body"]["record"] == req["action"]["record"]]
    if not cands:
        raise Fail("NOT_FOUND")
    if len(cands) > 1:
        raise Fail("ACTION_CONFLICT")
    action = cands[0]

    incoming = {}
    for e in edges:
        incoming.setdefault(e["body"]["child"], []).append(e)
    depth = {action["hash"]: 0}
    wl = [action["hash"]]
    while wl:
        v = wl.pop()
        for e in incoming.get(v, []):
            p = e["body"]["parent"]
            if p in depth:
                continue
            if depth[v] + 1 > req["max_depth"]:
                raise _PathLimit()
            depth[p] = depth[v] + 1
            wl.append(p)
    if len(depth) > req["max_nodes"]:
        raise _PathLimit()
    returned = set(depth)
    pedges = [e for e in edges if e["body"]["parent"] in returned and e["body"]["child"] in returned]
    if len(pedges) > 16384:
        raise _PathLimit()

    indeg = {h: 0 for h in returned}
    out = {}
    for e in pedges:
        indeg[e["body"]["child"]] += 1
        out.setdefault(e["body"]["parent"], []).append(e["body"]["child"])
    ready = sorted(h for h in returned if indeg[h] == 0)
    order = []
    while ready:
        v = ready.pop(0)
        order.append(v)
        new = []
        for w in out.get(v, []):
            indeg[w] -= 1
            if indeg[w] == 0:
                new.append(w)
        if new:
            ready.extend(new)
            ready.sort()
    by_hash = {s["hash"]: s for s in steps}
    psteps = [by_hash[h] for h in order]

    pgaps = [g for g in gaps if g["subject"] in returned or any(r in returned for r in g["related"])]
    if any(g["code"] in _CONFLICT_CODES for g in pgaps):
        structural = "CONFLICTED"
    elif pgaps:
        structural = "INCOMPLETE"
    else:
        structural = "COMPLETE_RELATIVE"

    by_stream = {}
    attest_seq = {}
    for o in origins:
        k = (o["body"]["source"], o["body"]["stream"])
        by_stream.setdefault(k, []).append(o)
        if o["body"]["step"] in returned:
            attest_seq[k] = max(attest_seq.get(k, 0), int(o["body"]["seq"]))
    porigins = []
    for o in origins:
        k = (o["body"]["source"], o["body"]["stream"])
        if o["body"]["step"] in returned or int(o["body"]["seq"]) <= attest_seq.get(k, -1):
            porigins.append(o)
    porigins.sort(key=lambda o: canonicalize(o))
    pedges.sort(key=lambda e: e["hash"])

    return {
        "trace": req["trace"], "revision": req["revision"], "graph": graph_hash,
        "action": action["hash"], "steps": psteps, "origins": porigins,
        "edges": pedges, "gaps": pgaps, "structural": structural,
        "evidence": "CLAIMED", "disclosure": "NORMALIZED_ONLY",
    }


# --- chain trust evaluation (port of trust.ts) ---------------------------------

def _eval_chains(role, envelopes, required_steps, step_of, trust):
    reasons = set()
    integrity = "VALID"
    covered = set()
    explained = set()

    key_pins = {}
    for k in trust["keys"]:
        key_pins.setdefault(k["id"], []).append(k)
    heads = [h for h in trust["heads"] if h["role"] == role]

    streams = {}
    for e in envelopes:
        k = (e["body"]["source"], e["body"]["stream"]) if role == "origin" else "audit"
        streams.setdefault(k, []).append(e)

    for _, lst in streams.items():
        slot_map = {}
        for e in lst:
            slot_map.setdefault(int(e["body"]["seq"]), {})[e["hash"]] = e["body"]["prev"]
        seqs = sorted(slot_map)
        earliest, latest = seqs[0], seqs[-1]
        src = lst[0]["body"]["source"]
        stm = lst[0]["body"]["stream"]
        stream_heads = [h for h in heads if h["source"] == src and h["stream"] == stm]
        head_at = {int(h["seq"]): h for h in stream_heads}

        def is_broken(e):
            seq = int(e["body"]["seq"])
            if seq == 1:
                return e["body"]["prev"] != ZERO
            ps = slot_map.get(seq - 1)
            return ps is None or e["body"]["prev"] not in ps

        def anchor_covered(e):
            pin = head_at.get(int(e["body"]["seq"]) - 1)
            return pin is not None and pin["hash"] == e["body"]["prev"]

        if any(is_broken(e) and not anchor_covered(e) for e in lst):
            reasons.add("ORIGIN_GAP" if role == "origin" else "AUDIT_GAP")

        if any(len(h) >= 2 for h in slot_map.values()):
            reasons.add("ORIGIN_FORK" if role == "origin" else "AUDIT_FORK")

        for h in stream_heads:
            seq = int(h["seq"])
            if seq < earliest:
                if seq == earliest - 1:
                    prevs = set(slot_map.get(earliest, {}).values())
                    if h["hash"] not in prevs:
                        reasons.add("PIN_MISMATCH")
                continue
            slot = slot_map.get(seq)
            if slot is not None:
                if h["hash"] not in slot:
                    reasons.add("PIN_MISMATCH")
            else:
                reasons.add("PIN_AHEAD")

        envs = {}
        for e in lst:
            envs.setdefault((int(e["body"]["seq"]), e["hash"]), []).append(e)
        memo = {}

        def anchored(e):
            key = id(e)
            if key in memo:
                return memo[key]
            memo[key] = False
            seq = int(e["body"]["seq"])
            ok = False
            if seq == 1:
                ok = e["body"]["prev"] == ZERO
            else:
                pin = head_at.get(seq - 1)
                if pin is not None and pin["hash"] == e["body"]["prev"]:
                    ok = True
                else:
                    prev_slot = slot_map.get(seq - 1)
                    if prev_slot is not None and e["body"]["prev"] in prev_slot:
                        ok = any(anchored(p) for p in envs.get((seq - 1, e["body"]["prev"]), []))
            memo[key] = ok
            return ok

        for e in lst:
            step_hash = step_of(e)
            pins = key_pins.get(e["body"]["key"]) or []
            role_pins = [p for p in pins if p["role"] == role]
            scoped = [p for p in role_pins
                      if p["source"] == e["body"]["source"] and p["stream"] == e["body"]["stream"]]

            def fail(reason):
                reasons.add(reason)
                if step_hash:
                    explained.add(step_hash)

            if not pins or not role_pins:
                fail("ORIGIN_KEY_UNKNOWN" if role == "origin" else "AUDIT_KEY_UNKNOWN")
                continue
            if not scoped:
                fail("ORIGIN_SCOPE_MISMATCH" if role == "origin" else "AUDIT_SCOPE_MISMATCH")
                continue
            covering = [p for p in scoped
                        if int(p["first_seq"]) <= int(e["body"]["seq"]) <= int(p["last_seq"])]
            if not covering:
                fail("ORIGIN_KEY_UNKNOWN" if role == "origin" else "AUDIT_KEY_UNKNOWN")
                continue
            if any(p["status"] == "COMPROMISED" for p in covering):
                fail("KEY_COMPROMISED")
                continue
            msg = sign_message(
                "VL-ORIGIN-SIGN/1" if role == "origin" else "VL-AUDIT-SIGN/1", e["hash"])
            if not any(verify_signature(p["public"], msg, e["signature"]) for p in covering):
                fail("SIGNATURE_INVALID")
                integrity = "INVALID"
                continue
            if anchored(e):
                if step_hash:
                    covered.add(step_hash)
            elif step_hash:
                explained.add(step_hash)

    if required_steps and envelopes:
        if any(s not in covered and s not in explained for s in required_steps):
            reasons.add("ORIGIN_COVERAGE_MISSING")

    def has(*rs):
        return any(r in reasons for r in rs)

    if role == "origin" and has("ORIGIN_FORK", "PIN_MISMATCH"):
        verdict = "CONFLICTED"
    elif has("AUDIT_FORK", "PIN_MISMATCH", "SIGNATURE_INVALID", "ORIGIN_KEY_UNKNOWN",
             "AUDIT_KEY_UNKNOWN", "ORIGIN_SCOPE_MISMATCH", "AUDIT_SCOPE_MISMATCH",
             "KEY_COMPROMISED"):
        verdict = "UNTRUSTED"
    elif has("ORIGIN_GAP", "AUDIT_GAP", "PIN_AHEAD", "ORIGIN_COVERAGE_MISSING"):
        verdict = "INCOMPLETE"
    elif not envelopes:
        verdict = "UNSIGNED" if role == "origin" else "INCOMPLETE"
    elif required_steps and any(s not in covered for s in required_steps):
        verdict = "INCOMPLETE"
    else:
        verdict = "TRUSTED_AT_PIN"

    if not envelopes and role == "origin":
        reasons.add("ORIGIN_UNSIGNED")
    if not envelopes and role == "audit":
        reasons.add("AUDIT_GAP")

    return {"integrity": integrity, "verdict": verdict, "reasons": sorted(reasons)}


# --- verify --------------------------------------------------------------------

def verify(bundle, trust):
    try:
        _bundle(bundle, "/bundle")
        _trust(trust, "/trust")
    except Fail as e:
        return _failure(e)
    except Exception:
        return _failure(Fail("SCHEMA_INVALID", "/bundle"))

    if trust["workspace"] != bundle["body"]["workspace"]:
        return _failure(Fail("TRUST_INVALID", "/trust/workspace"))

    def conservative(reasons):
        return {
            "integrity": "INVALID", "structural": "INCOMPLETE", "origin": "UNTRUSTED",
            "audit": "UNTRUSTED", "disclosure": "NORMALIZED_ONLY",
            "semantics": "NOT_VERIFIED", "current_authority": "UNKNOWN",
            "reasons": sorted(set(reasons)),
        }

    def done(integrity, structural, origin, audit, reasons):
        return {
            "integrity": integrity, "structural": structural, "origin": origin,
            "audit": audit, "disclosure": "NORMALIZED_ONLY",
            "semantics": "NOT_VERIFIED", "current_authority": "UNKNOWN",
            "reasons": sorted(set(reasons)),
        }

    # inventory + content hashes
    bad_inv = False
    seen_env = {"step": set(), "origin": set(), "audit": set(), "attachment": set()}
    for kind, envs, tag in (
        ("step", bundle["steps"], "VL-STEP/1"),
        ("origin", bundle["origins"], "VL-ORIGIN/1"),
        ("audit", bundle["audit"], "VL-AUDIT/1"),
    ):
        for e in envs:
            if e["hash"] != D(tag, e["body"]):
                bad_inv = True
            dig = H(canonicalize(e))
            if dig in seen_env[kind]:
                bad_inv = True
            seen_env[kind].add(dig)
    if bundle["hash"] != D("VL-BUNDLE/1", bundle["body"]):
        bad_inv = True

    refs = {}
    for s in bundle["steps"]:
        for r in s["body"]["attachments"]:
            refs[r["digest"]] = r
    supplied_art = set()
    for a in bundle["attachments"]:
        try:
            raw = _b64d(a["content"])
        except Exception:
            bad_inv = True
            continue
        if H(raw) != a["digest"] or int(a["bytes"]) != len(raw):
            bad_inv = True
        if a["digest"] in supplied_art:
            bad_inv = True
        supplied_art.add(a["digest"])
        ref = refs.get(a["digest"])
        if not ref or ref["format"] != a["format"] or int(ref["bytes"]) != len(raw):
            bad_inv = True
        seen_env["attachment"].add(a["digest"])
    if bundle["body"]["attachment_policy"] == "OMIT" and bundle["attachments"]:
        bad_inv = True
    if bundle["body"]["attachment_policy"] == "INCLUDE":
        if any(d not in supplied_art for d in refs):
            bad_inv = True

    expected_inv = {}
    for it in bundle["body"]["inventory"]:
        k = (it["kind"], it["digest"])
        if k in expected_inv:
            bad_inv = True
        expected_inv[k] = it["bytes"]
    actual_inv = {}
    for kind, envs in (("step", bundle["steps"]), ("origin", bundle["origins"]),
                       ("audit", bundle["audit"])):
        for e in envs:
            b = canonicalize(e)
            actual_inv[(kind, H(b))] = str(len(b))
    for d, ref in refs.items():
        actual_inv[("attachment", d)] = ref["bytes"]
    if len(actual_inv) != len(expected_inv) or any(
        expected_inv.get(k) != v for k, v in actual_inv.items()
    ):
        bad_inv = True
    if bad_inv:
        return conservative(["INVENTORY_MISMATCH"])

    # scope
    step_hashes = {s["hash"] for s in bundle["steps"]}
    for s in bundle["steps"]:
        if s["body"]["workspace"] != bundle["body"]["workspace"] or s["body"]["trace"] != bundle["body"]["trace"]:
            return conservative(["INVENTORY_MISMATCH"])
    by_stream = {}
    for o in bundle["origins"]:
        if o["body"]["workspace"] != bundle["body"]["workspace"]:
            return conservative(["INVENTORY_MISMATCH"])
        by_stream.setdefault((o["body"]["source"], o["body"]["stream"]), []).append(o)
    for o in bundle["origins"]:
        stream = by_stream[(o["body"]["source"], o["body"]["stream"])]
        if not any(p["body"]["step"] in step_hashes and int(p["body"]["seq"]) >= int(o["body"]["seq"])
                   for p in stream):
            return conservative(["INVENTORY_MISMATCH"])

    # graph reduction equality
    red = reduce(bundle["steps"], bundle["origins"], bundle["body"]["workspace"], bundle["body"]["trace"])
    if canonicalize(red["manifest"]) != canonicalize(bundle["body"]["graph"]):
        return conservative(["GRAPH_MISMATCH"])
    graph_hash = D("VL-GRAPH/1", bundle["body"]["graph"])

    # path recomputation equality
    req = bundle["body"]["path_request"]
    try:
        recomputed = compute_path(bundle["steps"], red["edges"], bundle["origins"],
                                  red["manifest"]["gaps"], graph_hash, req)
    except Exception:
        return {**conservative(["PATH_MISMATCH"]), "structural": "INCOMPLETE"}
    if (req["trace"] != bundle["body"]["trace"] or req["revision"] != bundle["body"]["revision"]
            or canonicalize(recomputed) != canonicalize(bundle["body"]["path"])):
        return {**conservative(["PATH_MISMATCH"]), "structural": recomputed["structural"]}

    # audit binding + chain
    audits = sorted(bundle["audit"], key=lambda a: int(a["body"]["seq"]))
    last = audits[-1] if audits else None
    bind_ok = False
    if last is not None:
        d = last["body"]["data"]
        if bundle["body"]["revision"] == "0":
            bind_ok = (d["kind"] == "TraceCreated" and d["trace"] == bundle["body"]["trace"]
                       and d["graph"] == graph_hash)
        else:
            bind_ok = (d["kind"] == "ImportCommitted" and d["trace"] == bundle["body"]["trace"]
                       and d["revision"] == bundle["body"]["revision"] and d["graph"] == graph_hash)
    if not bind_ok:
        return {**conservative(["AUDIT_BINDING_MISMATCH"]), "structural": recomputed["structural"]}
    for a in audits:
        if a["body"]["workspace"] != bundle["body"]["workspace"]:
            return {**conservative(["AUDIT_BINDING_MISMATCH"]), "structural": recomputed["structural"]}

    audit_eval = _eval_chains(
        "audit",
        [{"body": {"source": None, "stream": None, "seq": a["body"]["seq"],
                   "prev": a["body"]["prev"], "key": a["body"]["key"]},
          "hash": a["hash"], "signature": a["signature"]} for a in audits],
        None, lambda e: None, trust)
    if audit_eval["integrity"] == "INVALID":
        return {**conservative(audit_eval["reasons"]), "structural": recomputed["structural"]}
    audit_out = audit_eval["verdict"]
    if audit_out == "CONFLICTED":
        audit_out = "UNTRUSTED"
    if audit_out == "UNSIGNED":
        audit_out = "INCOMPLETE"

    # origin signatures + pins
    required = {s["hash"] for s in recomputed["steps"]}
    origin_eval = _eval_chains("origin", bundle["origins"], required,
                               lambda e: e["body"]["step"], trust)
    if origin_eval["integrity"] == "INVALID":
        return done("INVALID", recomputed["structural"], origin_eval["verdict"],
                    audit_out, origin_eval["reasons"])

    return done("VALID", recomputed["structural"], origin_eval["verdict"],
                audit_out, audit_eval["reasons"] + origin_eval["reasons"])
