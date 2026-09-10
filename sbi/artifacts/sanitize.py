"""Secret redaction for sbi trace artifacts.

Trace artifacts produced by the ``sbi`` runtime embed live credentials: bearer
tokens in authorization headers, ``token=`` style query parameters, session
cookies, API keys, and personal emails. Sharing a raw artifact with an issue
tracker, another engineer, or an LLM leaks those secrets, so run artifacts
through this module first.

``sanitize_doc(doc, extra_patterns=())`` treats the artifact as JSON-shaped
data (dicts, lists, and str/int/float/bool/None leaves; anything else is
passed through untouched) and returns ``(new_doc, report)``: a brand-new
redacted document plus per-rule counts. The input document is never mutated.
``sanitize_file(path, out_path=None)`` is a JSON round-trip wrapper that
writes ``<name>.sanitized.<ext>`` by default and returns ``(out_path,
report)``.

Default rules and their report keys under ``report["doc"]``:

* ``query_param`` -- values of ``token``/``api_key``/``key``/``apikey``/
  ``access_key``/``secret``/``password`` parameters in any ``?a=b&c=d``
  query string become ``***REDACTED***`` (the URL itself survives).
* ``auth`` -- ``Bearer <cred>`` and ``Basic <b64>`` keep the scheme word,
  the credential becomes ``***REDACTED***``.
* ``cookie`` -- ``name=value`` pairs after ``cookie:`` in free text, and
  the values of header-map keys ``cookie``/``set-cookie``, become
  ``name=***REDACTED***`` (attributes such as ``Path``/``HttpOnly`` stay).
* ``email`` -- addresses become ``***EMAIL***``.
* ``high_entropy`` -- standalone 20+ char tokens over
  ``[A-Za-z0-9_\\-./+=]`` that mix digits and letters or look base64ish
  (contain ``/``/``+``/``=`` or are 32+ chars) become ``***REDACTED***``.
  Scanned inside pair ``input``/``inputs``/``output``/``outputs``, network
  ``post_data``/``payload``/``body``/``bodies``, and ``headers`` subtrees --
  never inside ``stack``/``script``/``fn`` fields -- and URLs, domains, and
  hex-only ids shorter than 32 chars are always left alone.

``extra_patterns`` is a sequence of ``(rule_name, pattern)`` pairs (pattern
may be a regex string or precompiled); matches become ``***REDACTED***``
and count under ``rule_name``. ``report`` also carries ``total`` (all
redactions) and ``fields_seen`` (string values scanned).
"""

import json
import os
import re

__all__ = ["EMAIL_REPLACEMENT", "REDACTED", "sanitize_doc", "sanitize_file"]

REDACTED = "***REDACTED***"
EMAIL_REPLACEMENT = "***EMAIL***"

_DEFAULT_RULES = ("query_param", "auth", "cookie", "email", "high_entropy")

# Rule 1: credential-ish query parameter names (exact match, case-insensitive).
_QUERY_PARAM_RE = re.compile(
    r"([?&])(api_key|apikey|access_key|token|secret|password|key)=([^&#\s]+)",
    re.IGNORECASE,
)

# Rule 2: HTTP auth schemes -- keep the scheme word, drop the credential.
_BEARER_RE = re.compile(r"(?i)(bearer\s+)\S+")
_BASIC_RE = re.compile(r"(?i)(basic\s+)[A-Za-z0-9+/=]+")

# Rule 3: cookies in free text and under header-map keys.
_COOKIE_HEADER_KEYS = frozenset({"cookie", "set-cookie"})
_COOKIE_TEXT_RE = re.compile(r"(?i)(cookie\s*:\s*)([^\r\n]*)")
_COOKIE_PAIR_RE = re.compile(r"(?i)([A-Za-z0-9_.%$-]+)=([^;]*)")
_COOKIE_ATTRS = frozenset({
    "comment", "domain", "expires", "httponly", "max-age", "partitioned",
    "path", "priority", "samesite", "secure",
})

# Rule 4: high-entropy standalone tokens. ':' is excluded from the token
# alphabet and from valid start positions, so URL bodies never form tokens.
_ENTROPY_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_\-./+=:])[A-Za-z0-9_\-./+=]{20,}(?![A-Za-z0-9_\-./+=])"
)
_DOMAINISH_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
    r"\.[A-Za-z]{2,24}(?:/.*)?$"
)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# Rule 5: email addresses.
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
)

# Subtrees scanned (or never scanned) by the high-entropy rule; any other
# key inherits the entropy flag of its enclosing context.
_ENTROPY_ON_KEYS = frozenset({
    "input", "inputs", "output", "outputs",
    "post_data", "postdata", "payload", "body", "bodies",
    # request/response header maps carry signed tokens and custom auth
    # (x-*-signature, x-api-*, etc.); scan their values too. Bearer/Basic and
    # cookie header values already have dedicated rules above.
    "headers", "header",
})
_ENTROPY_OFF_KEYS = frozenset({
    "fn", "function", "script", "stack", "stacktrace", "stack_trace",
})


def sanitize_doc(doc, extra_patterns=()):
    """Return ``(new_doc, report)`` with secrets redacted from ``doc``.

    ``doc`` is a JSON-shaped artifact (dicts, lists, scalars; other values
    pass through untouched); it is never mutated -- a parallel structure is
    built. See the module docstring for the rule set and report format.
    """
    counts = dict.fromkeys(_DEFAULT_RULES, 0)
    extras = []
    for entry in extra_patterns:
        try:
            name, pattern = entry
        except (TypeError, ValueError):
            raise ValueError(
                "extra_patterns entries must be (name, pattern) pairs"
            ) from None
        if not isinstance(pattern, re.Pattern):
            pattern = re.compile(pattern)
        extras.append((name, pattern))
        counts.setdefault(name, 0)
    stats = {"counts": counts, "fields_seen": 0, "extras": extras}
    new_doc = _sanitize_node(doc, False, stats)
    report = {
        "doc": counts,
        "total": sum(counts.values()),
        "fields_seen": stats["fields_seen"],
    }
    return new_doc, report


def sanitize_file(path, out_path=None):
    """Redact the JSON artifact at ``path``; return ``(out_path, report)``.

    ``out_path`` defaults to ``path`` with ``.sanitized`` inserted before
    the extension (``trace.json`` -> ``trace.sanitized.json``).
    """
    path = os.fspath(path)
    if out_path is None:
        root, ext = os.path.splitext(path)
        out_path = root + ".sanitized" + ext
    else:
        out_path = os.fspath(out_path)
    with open(path, "r", encoding="utf-8") as handle:
        doc = json.load(handle)
    sanitized, report = sanitize_doc(doc)
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(sanitized, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return out_path, report


def _sanitize_node(node, entropy_ok, stats):
    """Build the redacted parallel of ``node`` for the given context."""
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            k = key.lower() if isinstance(key, str) else ""
            child_entropy = entropy_ok
            if k in _ENTROPY_ON_KEYS:
                child_entropy = True
            elif k in _ENTROPY_OFF_KEYS:
                child_entropy = False
            if isinstance(value, str) and k in _COOKIE_HEADER_KEYS:
                value = _redact_cookie_pairs(value, stats["counts"])
            out[key] = _sanitize_node(value, child_entropy, stats)
        return out
    if isinstance(node, list):
        return [_sanitize_node(item, entropy_ok, stats) for item in node]
    if isinstance(node, str):
        return _sanitize_string(node, entropy_ok, stats)
    return node  # int / float / bool / None / anything else: untouched


def _sanitize_string(text, entropy_ok, stats):
    counts = stats["counts"]
    stats["fields_seen"] += 1

    def _query(m):
        return m.group(1) + m.group(2) + "=" + REDACTED

    text, n = _QUERY_PARAM_RE.subn(_query, text)
    counts["query_param"] += n

    text, n1 = _BEARER_RE.subn(r"\g<1>" + REDACTED, text)
    text, n2 = _BASIC_RE.subn(r"\g<1>" + REDACTED, text)
    counts["auth"] += n1 + n2

    text = _COOKIE_TEXT_RE.sub(
        lambda m: m.group(1) + _redact_cookie_pairs(m.group(2), counts), text)

    text, n = _EMAIL_RE.subn(EMAIL_REPLACEMENT, text)
    counts["email"] += n

    if entropy_ok:
        hits = 0

        def _entropy(m):
            nonlocal hits
            token = m.group(0)
            if _is_high_entropy(token):
                hits += 1
                return REDACTED
            return token

        text = _ENTROPY_TOKEN_RE.sub(_entropy, text)
        counts["high_entropy"] += hits

    for name, pattern in stats["extras"]:
        text, n = pattern.subn(REDACTED, text)
        counts[name] += n

    return text


def _redact_cookie_pairs(value, counts):
    """Redact ``name=value`` pairs in a cookie header value; count them."""
    hits = 0

    def _pair(m):
        nonlocal hits
        name, val = m.group(1), m.group(2)
        if not val or name.lower() in _COOKIE_ATTRS:
            return m.group(0)
        hits += 1
        return name + "=" + REDACTED

    new_value = _COOKIE_PAIR_RE.sub(_pair, value)
    counts["cookie"] += hits
    return new_value


def _is_high_entropy(token):
    """True if a standalone 20+ char token should be treated as a secret."""
    if "://" in token or token.startswith(("/", ".")):
        return False  # URLs and path-like tokens
    if _DOMAINISH_RE.match(token):
        return False  # bare domains / domains with paths
    has_digit = any(ch.isdigit() for ch in token)
    has_alpha = any(ch.isascii() and ch.isalpha() for ch in token)
    looks_base64 = ("/" in token or "+" in token or "=" in token
                    or len(token) >= 32)
    if not ((has_digit and has_alpha) or looks_base64):
        return False
    if len(token) < 32 and not (set(token) - _HEX_DIGITS):
        return False  # short hex-only ids (uuids, checksums)
    return True
