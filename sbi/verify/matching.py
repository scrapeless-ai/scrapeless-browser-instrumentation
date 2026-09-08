"""Comparison modes for the oracle.

Exact equality is the default because it should be: a reimplementation that
returns '1' for 1 is wrong. But real targets produce nonce- and
time-dependent outputs (rotating signatures, timestamps, random session ids)
where the *structure* is the invariant. These modes let verify() accept a
structural match without loosening what counts as a mismatch anywhere else.
"""

import re
from datetime import datetime, timezone

_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?")


def mode_names():
    return ["exact", "loose_string", "numeric", "time_tolerant"]


def compare(expected, got, mode="exact", tol=0.0, rel=0.0, seconds=60.0):
    """-> {"match": bool, "mode": str, "detail": str|None}."""
    if mode == "exact":
        ok = _exact(expected, got)
        return {"match": ok, "mode": mode, "detail": None if ok else "values differ (strict)"}
    if mode == "loose_string":
        return _loose_string(expected, got)
    if mode == "numeric":
        return _numeric(expected, got, tol, rel)
    if mode == "time_tolerant":
        return _time_tolerant(expected, got, seconds)
    raise ValueError(f"unknown mode {mode!r}; known: {mode_names()}")


def _exact(a, b):
    """Same semantics as oracle._equal: bool/int and str/int never match."""
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_exact(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_exact(x, y) for x, y in zip(a, b))
    return a == b and type(a) == type(b)


def _char_class(ch):
    if ch.isdigit():
        return "d"
    if ch.isalpha():
        return "a"
    return "s"


def _loose_string(expected, got):
    if not (isinstance(expected, str) and isinstance(got, str)):
        ok = _exact(expected, got)
        return {"match": ok, "mode": "loose_string",
                "detail": None if ok else "non-strings compared strictly and differ"}
    if len(expected) != len(got):
        return {"match": False, "mode": "loose_string",
                "detail": f"length {len(expected)} vs {len(got)}"}
    for i, (x, y) in enumerate(zip(expected.lower(), got.lower())):
        cx, cy = _char_class(x), _char_class(y)
        if cx != cy:
            return {"match": False, "mode": "loose_string",
                    "detail": f"index {i}: class {cx!r} vs {cy!r} ({x!r} vs {y!r})"}
    return {"match": True, "mode": "loose_string", "detail": None}


def _numeric(expected, got, tol, rel):
    def num(v):
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if not (num(expected) and num(got)):
        ok = _exact(expected, got)
        return {"match": ok, "mode": "numeric",
                "detail": None if ok else "non-numbers compared strictly and differ"}
    diff = abs(expected - got)
    allowed = tol + rel * max(abs(expected), abs(got))
    ok = diff <= allowed
    return {"match": ok, "mode": "numeric",
            "detail": None if ok else f"|{expected}-{got}|={diff} > {allowed}"}


def _parse_ts(token):
    t = token.replace(" ", "T", 1) if len(token) > 10 and token[10] == " " else token
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    m = re.match(r"^(.*?)([+-]\d{2})(\d{2})$", t)   # +HHMM -> +HH:MM
    if m:
        t = m.group(1) + m.group(2) + ":" + m.group(3)
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _time_tolerant(expected, got, seconds):
    if not (isinstance(expected, str) and isinstance(got, str)):
        ok = _exact(expected, got)
        return {"match": ok, "mode": "time_tolerant",
                "detail": None if ok else "non-strings compared strictly and differ"}
    ts_a, ts_b = _TS_RE.findall(expected), _TS_RE.findall(got)
    if len(ts_a) != len(ts_b):
        return {"match": False, "mode": "time_tolerant",
                "detail": f"{len(ts_a)} vs {len(ts_b)} timestamps"}
    rest_a = _TS_RE.sub("\x00", expected)
    rest_b = _TS_RE.sub("\x00", got)
    if rest_a != rest_b:
        return {"match": False, "mode": "time_tolerant", "detail": "non-timestamp text differs"}
    for ta, tb in zip(_TS_RE.finditer(expected), _TS_RE.finditer(got)):
        da, db = _parse_ts(ta.group(0)), _parse_ts(tb.group(0))
        if da is None or db is None:
            return {"match": False, "mode": "time_tolerant",
                    "detail": f"unparseable timestamp {ta.group(0)!r}"}
        if abs((da - db).total_seconds()) > seconds:
            return {"match": False, "mode": "time_tolerant",
                    "detail": f"{ta.group(0)} vs {tb.group(0)} beyond {seconds}s"}
    return {"match": True, "mode": "time_tolerant", "detail": None}
