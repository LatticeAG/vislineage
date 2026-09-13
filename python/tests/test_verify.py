"""Python verifier parity tests: canon KATs, golden bundle verify, mutations."""

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vislineage import canonicalize, strict_json_loads, verify, verify_signature, H, D  # noqa: E402
from vislineage.verify import _eval_chains, sign_message  # noqa: E402

FIX = json.loads(Path(__file__).resolve().parents[2].joinpath("tests/fixtures.json").read_text())
F = {**FIX, **FIX["F"]}
ZERO = "0" * 64
ONE = "1" * 64


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ---- canon KATs (TV-V-01..04 equivalents) ------------------------------------

def test_canon_member_order():
    assert canonicalize(strict_json_loads(b'{"b":2,"a":1}')) == b'{"a":1,"b":2}'


def test_canon_duplicate_members_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        strict_json_loads(b'{"a":1,"a":2}')


def test_canon_unsafe_integer_and_neg_zero():
    with pytest.raises(ValueError, match="unsafe"):
        strict_json_loads(b'{"n":9007199254740992}')
    with pytest.raises(ValueError, match="negative zero"):
        strict_json_loads(b'{"n":-0}')


def test_canon_unicode_not_normalized():
    a = canonicalize(strict_json_loads('{"s":"é"}'.encode()))
    b = canonicalize(strict_json_loads(b'{"s":"e\\u0301"}'))
    assert a == '{"s":"é"}'.encode()
    assert b == '{"s":"é"}'.encode()
    assert a != b
    assert len(a) == 10 and len(b) == 11


def test_canon_bom_and_bad_utf8():
    with pytest.raises(ValueError):
        strict_json_loads(b'\xef\xbb\xbf{}')
    with pytest.raises(Exception):
        strict_json_loads(b'{"x":"\xff"}')


# ---- Ed25519 known-answer: Python signature equals fixture's ------------------

def test_ed25519_kat_matches_fixture_signature():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)  # K1
    msg = sign_message("VL-ORIGIN-SIGN/1", F["OA"]["hash"])
    sig = b64u(key.sign(msg))
    assert sig == F["OA"]["signature"], "python Ed25519 signature diverges from TS fixture"
    assert verify_signature(F["OA"]["body"]["key"] and F["trust"]["keys"][1]["public"], msg, sig)
    # strictness: small-order pubkey / non-canonical encodings rejected
    assert not verify_signature(b64u(b"\x00" * 32), msg, sig)
    assert not verify_signature(F["trust"]["keys"][1]["public"], msg, b64u(b"\x00" * 64))


# ---- golden bundle (TV-V-24 parity) ------------------------------------------

def test_verify_golden_bundle():
    out = verify(F["bundle"], F["trust"])
    assert out == F["verification"]
    assert out["semantics"] == "NOT_VERIFIED"
    assert out["current_authority"] == "UNKNOWN"


def test_verify_bundle_hash_matches_spec():
    assert F["bundle"]["hash"] == "d0297474ddc9c378f7e0b16537fa1d702bd2cb160fceaa75832cb4937578ecfa"
    assert D("VL-BUNDLE/1", F["bundle"]["body"]) == F["bundle"]["hash"]


# ---- mutation detection -------------------------------------------------------

def _mutated(fn):
    b = json.loads(json.dumps(F["bundle"]))
    fn(b)
    return verify(b, F["trust"])


def test_verify_detects_step_body_mutation():
    def m(b):
        b["steps"][0]["body"]["record"] = "tampered"
    out = _mutated(m)
    assert out["integrity"] == "INVALID"
    assert "INVENTORY_MISMATCH" in out["reasons"]


def test_verify_detects_hash_swap():
    def m(b):
        b["steps"][0]["hash"] = ONE
    out = _mutated(m)
    assert out["integrity"] == "INVALID"


def test_verify_detects_path_substitution():
    def m(b):
        b["body"]["path"]["structural"] = "COMPLETE_RELATIVE"
        b["body"]["path"]["steps"] = []
        b["hash"] = D("VL-BUNDLE/1", b["body"])
    out = _mutated(m)
    assert out["integrity"] == "INVALID"
    assert "PATH_MISMATCH" in out["reasons"] or "INVENTORY_MISMATCH" in out["reasons"]


def test_verify_detects_graph_substitution():
    def m(b):
        b["body"]["graph"]["steps"] = []
        b["hash"] = D("VL-BUNDLE/1", b["body"])
    out = _mutated(m)
    assert out["integrity"] == "INVALID"
    assert "GRAPH_MISMATCH" in out["reasons"]


def test_verify_detects_audit_removal():
    def m(b):
        removed = b["audit"][-1]
        b["audit"] = b["audit"][:-1]
        # keep inventory honest: drop only the removed entry's item so the
        # remaining failure is specifically the missing binding entry
        rdigest = H(canonicalize(removed))
        b["body"]["inventory"] = [
            i for i in b["body"]["inventory"]
            if not (i["kind"] == "audit" and i["digest"] == rdigest)
        ]
        b["hash"] = D("VL-BUNDLE/1", b["body"])
    out = _mutated(m)
    assert out["integrity"] == "INVALID"
    assert "AUDIT_BINDING_MISMATCH" in out["reasons"]


def test_verify_rejects_trust_workspace_mismatch():
    t = json.loads(json.dumps(F["trust"]))
    t["workspace"] = "vlw_" + "x" * 21
    out = verify(F["bundle"], t)
    assert out["ok"] is False
    assert out["error"]["code"] == "TRUST_INVALID"


def test_verify_schema_failure_returns_failure_object():
    out = verify({"v": 1}, F["trust"])
    assert out["ok"] is False
    assert out["error"]["retryable"] is False


# ---- eval_chains parity (TV-V-22..31 equivalents) ------------------------------

def _o(step_hash, key_id, pub_check=None, seq="1", prev=ZERO, source=None, sig=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    body = {"v": 1, "workspace": F["W"], "source": source or F["SA"]["id"],
            "stream": "main", "seq": seq, "prev": prev, "step": step_hash, "key": key_id}
    h = D("VL-ORIGIN/1", body)
    return {"body": body, "hash": h,
            "signature": sig or b64u(Ed25519PrivateKey.from_private_bytes(b"\x11" * 32).sign(
                sign_message("VL-ORIGIN-SIGN/1", h)))}


K1_PIN = next(k for k in F["trust"]["keys"] if k["id"].endswith("l" * 21))


def _origin_eval(origins, required, keys, heads):
    envs = origins  # origins already carry body.source/stream/seq/prev/key + hash + signature
    r = _eval_chains("origin", envs, set(required), lambda e: e["body"]["step"],
                     {"v": 1, "workspace": F["W"], "keys": keys, "heads": heads})
    return r


def test_origin_gap_incomplete():
    oa2 = _o(F["A"]["hash"], K1_PIN["id"], seq="2", prev=ONE)
    key = {**K1_PIN, "last_seq": "2"}
    r = _origin_eval([oa2], [F["A"]["hash"]], [key], [])
    assert r["verdict"] == "INCOMPLETE" and r["integrity"] == "VALID"
    assert "ORIGIN_GAP" in r["reasons"]


def test_origin_unknown_key_untrusted():
    r = _origin_eval([F["OA"]], [F["A"]["hash"]], [], [])
    assert r["verdict"] == "UNTRUSTED" and r["integrity"] == "VALID"
    assert "ORIGIN_KEY_UNKNOWN" in r["reasons"]


def test_origin_invalid_signature():
    bad = dict(F["OA"], signature=b64u(b"\x00" * 64))
    r = _origin_eval([bad], [F["A"]["hash"]], [K1_PIN], [])
    assert r["verdict"] == "UNTRUSTED" and r["integrity"] == "INVALID"
    assert "SIGNATURE_INVALID" in r["reasons"]


def test_origin_compromised_key():
    kc = {**K1_PIN, "status": "COMPROMISED"}
    r = _origin_eval([F["OA"]], [F["A"]["hash"]], [kc], [])
    assert r["verdict"] == "UNTRUSTED" and r["integrity"] == "VALID"
    assert "KEY_COMPROMISED" in r["reasons"]


def test_origin_pin_mismatch_conflicted():
    h = {"role": "origin", "source": F["SA"]["id"], "stream": "main", "seq": "1", "hash": ONE}
    r = _origin_eval([F["OA"]], [F["A"]["hash"]], [K1_PIN], [h])
    assert r["verdict"] == "CONFLICTED" and "PIN_MISMATCH" in r["reasons"]


def test_origin_fork_conflicted():
    # same key/source/stream/seq, distinct hash — a signed fork
    other = _o(F["A"]["hash"][:-1] + ("0" if F["A"]["hash"][-1] != "0" else "1"), K1_PIN["id"])
    r = _origin_eval([F["OA"], other], [F["A"]["hash"]], [K1_PIN], [])
    assert r["verdict"] == "CONFLICTED" and "ORIGIN_FORK" in r["reasons"]


def test_audit_chain_trusted():
    audits = [{"body": {"source": None, "stream": None, "seq": a["body"]["seq"],
                        "prev": a["body"]["prev"], "key": a["body"]["key"]},
               "hash": a["hash"], "signature": a["signature"]} for a in F["bundle"]["audit"]]
    r = _eval_chains("audit", audits, None, lambda e: None, F["trust"])
    assert r["verdict"] == "TRUSTED_AT_PIN" and r["integrity"] == "VALID"
