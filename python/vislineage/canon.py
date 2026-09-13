"""RFC 8785 (JCS) canonicalization: canonicalize(value) -> bytes.

Pure function: UTF-16 code-unit key ordering, ECMAScript number
serialization, no Unicode normalization. Mirrors the TS core J().
"""

import math
import struct

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def _escape(s: str) -> str:
    out = []
    for ch in s:
        e = _ESCAPES.get(ch)
        if e is not None:
            out.append(e)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _es_number(n) -> str:
    """ECMAScript Number::toString for JSON numbers (base 10)."""
    if isinstance(n, bool):
        raise TypeError("bool is not a number")
    if isinstance(n, int):
        if n < 0 or n > 9007199254740991:
            raise ValueError("core protocol permits safe integers 0..2^53-1")
        return str(n)
    f = float(n)
    if not math.isfinite(f):
        raise ValueError("non-finite number")
    if f == 0:
        return "0"
    if f == int(f) and abs(f) < 1e21:
        return str(int(f))
    # shortest round-trip digits via repr
    r = repr(f)
    if "e" in r or "E" in r:
        mant, ex = r.lower().split("e")
        e = int(ex)
    else:
        mant, e = r, 0
    sign = ""
    if mant.startswith("-"):
        sign, mant = "-", mant[1:]
    if "." in mant:
        ip, fp = mant.split(".")
        digits = ip + fp
        e += -len(fp)  # value = digits * 10^e ... after int shift below
    else:
        digits = mant
    digits = digits.lstrip("0") or "0"
    # value = int(digits) * 10^e ; express as d1.d2..dk * 10^(n-1)
    k = len(digits)
    nexp = k + e  # value = 0.digits * 10^nexp
    if -6 < nexp <= 21:
        if e >= 0:
            s = digits + "0" * e
        elif nexp > 0:
            s = digits[:nexp] + "." + digits[nexp:]
        else:
            s = "0." + "0" * (-nexp) + digits
        return sign + s
    if k == 1:
        m = digits
    else:
        m = digits[0] + "." + digits[1:]
    return f"{sign}{m}e{'+' if nexp - 1 >= 0 else '-'}{abs(nexp - 1)}"


def _canon(v, out) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, (int, float)) and not isinstance(v, bool):
        out.append(_es_number(v))
    elif isinstance(v, str):
        out.append(_escape(v))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _canon(x, out)
        out.append("]")
    elif isinstance(v, dict):
        keys = sorted(v.keys(), key=_utf16_key)
        out.append("{")
        for i, k in enumerate(keys):
            if i:
                out.append(",")
            if not isinstance(k, str):
                raise TypeError("object keys must be strings")
            out.append(_escape(k))
            out.append(":")
            _canon(v[k], out)
        out.append("}")
    else:
        raise TypeError(f"unsupported type: {type(v)}")


def canonicalize(value) -> bytes:
    out: list[str] = []
    _canon(value, out)
    return "".join(out).encode("utf-8")


def strict_json_loads(raw: bytes, max_bytes: int = 256 * 1024 * 1024):
    """Strict JSON parse: no BOM, strict UTF-8, no duplicate members."""
    import json

    if len(raw) > max_bytes:
        raise ValueError("BODY_LIMIT")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("JSON_INVALID: BOM")
    text = raw.decode("utf-8", "strict")

    def no_dupes(pairs):
        seen = set()
        obj = {}
        for k, v in pairs:
            if k in seen:
                raise ValueError("JSON_INVALID: duplicate member")
            seen.add(k)
            obj[k] = v
        return obj

    def reject_num(x):
        f = float(x)
        if not math.isfinite(f):
            raise ValueError("JSON_INVALID: non-finite number")
        if x.startswith("-0") and not x.startswith("-0."):
            # "-0" integer token is a negative zero → schema-invalid in core
            raise ValueError("SCHEMA_INVALID: negative zero")
        if "." in x or "e" in x.lower():
            return f
        iv = int(x)
        if iv < 0 or iv > 9007199254740991:
            raise ValueError("SCHEMA_INVALID: unsafe integer")
        return iv

    return json.loads(text, object_pairs_hook=no_dupes, parse_int=reject_num, parse_float=reject_num)
