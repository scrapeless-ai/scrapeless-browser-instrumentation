"""Replay: rebuild a saved trace's instrumentation on a fresh session.

A trace artifact is a complete recipe — where the page was, which functions
were hooked, which corpora were captured. `plan` distills it, `apply`
re-establishes it on a live session (pages drift between runs, so individual
hook failures are collected, not raised), and `verify_saved` reloads the
ground-truth corpus so a candidate can be re-verified without re-capturing.
"""

from . import trace as trace_mod

HOOK_FIELDS = ("expression", "label", "returns", "target_url")


def plan(doc):
    """Distill a loaded trace into what a fresh session needs: where to go,
    what to hook, which corpora exist, how much network was seen. Pure."""
    return {"url": _target_url(doc),
            "hooks": _planned_hooks(doc),
            "corpus_labels": list((doc.get("pairs") or {}).keys()),
            "network_events": len(doc.get("network") or [])}


def apply(session, doc):
    """Replay a plan on a live session: navigate if the trace names a page,
    then re-hook every planned hook. A page that changed shape fails its own
    hook and lands in "failed" — the rest of the instrumentation still goes up."""
    p = plan(doc)
    if p["url"]:
        session.navigate(p["url"])
    hooked, failed = [], []
    for h in p["hooks"]:
        try:
            session.hook(h["expression"], target_url=h["target_url"],
                         capture_returns=h["returns"], label=h["label"])
            hooked.append(h["label"])
        except Exception as e:
            failed.append({"expression": h["expression"], "error": str(e)})
    return {"url": p["url"], "hooked": hooked, "failed": failed}


def verify_saved(session, doc, label, candidate, fresh_inputs=None, fn_expr=None):
    """Verify a candidate against a trace's saved corpus, online.

    The pairs are loaded into the oracle under `label`, the hooked expression
    is recovered from the trace (or taken from `fn_expr` when the label has no
    hook record), and `session.verify` runs as usual — no re-capture needed.
    """
    session.oracle.load_corpus(label, (doc.get("pairs") or {}).get(label) or [])
    expr = fn_expr
    if expr is None:
        for h in doc.get("hooks") or []:
            if h.get("label") == label and h.get("expression"):
                expr = h["expression"]
                break
    if expr is None:
        raise ValueError(f"no hook expression for label {label!r} in trace; "
                         "pass fn_expr=...")
    return session.verify(expr, candidate, label=label, fresh_inputs=fresh_inputs)


def from_path(path):
    """Load a trace artifact from disk (sbi.trace.load)."""
    return trace_mod.load(path)


def _target_url(doc):
    """First saved target's url, when it is a real page we can revisit."""
    targets = (doc.get("meta") or {}).get("targets") or []
    first = targets[0] if targets else None
    url = first[2] if isinstance(first, (list, tuple)) and len(first) > 2 else None
    if isinstance(url, str) and url.startswith(("http://", "https://")) and url != "about:blank":
        return url
    return None


def _planned_hooks(doc):
    """Hook records trimmed to the serializable fields a replay re-sends,
    deduplicated — the same expression hooked twice plans once."""
    planned, seen = [], set()
    for h in doc.get("hooks") or []:
        hook = {f: h.get(f) for f in HOOK_FIELDS}
        if not hook["expression"]:
            continue
        key = tuple(hook[f] for f in HOOK_FIELDS)
        if key not in seen:
            seen.add(key)
            planned.append(hook)
    return planned
