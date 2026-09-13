"""CLI: python -m vislineage verify --bundle PATH --trust PATH [--json]"""

import argparse
import json
import sys

from .canon import strict_json_loads
from .verify import verify

BUNDLE_CAP = 64 * 1024 * 1024 + 4 * 1024 * 1024
TRUST_CAP = 4 * 1024 * 1024


def _load(path: str, cap: int):
    with open(path, "rb") as fh:
        raw = fh.read()
    if len(raw) > cap:
        print(json.dumps({"ok": False, "error": {"code": "BODY_LIMIT", "retryable": False}}))
        sys.exit(2)
    try:
        return strict_json_loads(raw, cap)
    except Exception:
        print(json.dumps({"ok": False, "error": {"code": "SCHEMA_INVALID", "retryable": False}}))
        sys.exit(2)


def main() -> int:
    p = argparse.ArgumentParser(prog="vislineage")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify a bundle offline")
    v.add_argument("--bundle", required=True)
    v.add_argument("--trust", required=True)
    v.add_argument("--json", action="store_true")
    sub.add_parser("version")
    args = p.parse_args()

    if args.cmd == "version":
        from . import __version__

        print(f"vislineage {__version__} (vislineage/1)")
        return 0

    bundle = _load(args.bundle, BUNDLE_CAP)
    trust = _load(args.trust, TRUST_CAP)
    out = verify(bundle, trust)
    if isinstance(out, dict) and out.get("ok") is False:
        print(json.dumps(out))
        return 2
    # §10 exit precedence: integrity INVALID→3; structural/origin conflict→5;
    # nontrusted origin/audit or incomplete structure→4; otherwise 0.
    print(json.dumps(out, sort_keys=False))
    if out.get("integrity") == "INVALID":
        return 3
    if out.get("structural") == "CONFLICTED" or out.get("origin") == "CONFLICTED":
        return 5
    if (
        out.get("structural") != "COMPLETE_RELATIVE"
        or out.get("origin") != "TRUSTED_AT_PIN"
        or out.get("audit") != "TRUSTED_AT_PIN"
    ):
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
