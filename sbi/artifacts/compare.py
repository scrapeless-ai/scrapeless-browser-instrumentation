"""Diff two trace artifacts: what changed between captures.

Point the same instrumentation at two versions of a site (or two runs) and
this answers the regression questions: which corpus pairs changed outputs,
which hooks appeared or moved from args-only to args+returns, which endpoints
appeared, which captured functions went away. Pure functions over the doc
dicts — no session needed, deterministic output.
"""

import json


def _key(value):
    return json.dumps(value, sort_keys=True, default=str)


def _hook_mode(h):
    return "args+returns" if h.get("returns") else "args"


def compare_docs(a, b):
    pairs = {}
    for label in sorted(set(a.get("pairs") or {}) | set(b.get("pairs") or {})):
        pa = (a.get("pairs") or {}).get(label) or []
        pb = (b.get("pairs") or {}).get(label) or []
        ia = {_key(p.get("input")): p for p in pa}
        ib = {_key(p.get("input")): p for p in pb}
        entry = {"only_in_a": [ia[k]["input"] for k in sorted(set(ia) - set(ib))],
                 "only_in_b": [ib[k]["input"] for k in sorted(set(ib) - set(ia))],
                 "output_changed": []}
        for k in sorted(set(ia) & set(ib)):
            ea, eb = ia[k].get("output"), ib[k].get("output")
            if ea != eb:
                entry["output_changed"].append({"input": ia[k]["input"], "a": ea, "b": eb})
        pairs[label] = entry

    ha = {h.get("label"): h for h in (a.get("hooks") or [])}
    hb = {h.get("label"): h for h in (b.get("hooks") or [])}
    hooks = {
        "only_in_a": sorted(set(ha) - set(hb)),
        "only_in_b": sorted(set(hb) - set(ha)),
        "mode_changed": [{"label": l, "a": _hook_mode(ha[l]), "b": _hook_mode(hb[l])}
                         for l in sorted(set(ha) & set(hb))
                         if _hook_mode(ha[l]) != _hook_mode(hb[l])],
    }

    def urls(doc):
        return {r.get("url") for r in (doc.get("network") or []) if r.get("url")}
    network = {"new_urls": sorted(urls(b) - urls(a)),
               "dropped_urls": sorted(urls(a) - urls(b))}

    def fn_counts(doc):
        out = {}
        for r in (doc.get("captures") or []):
            out[r.get("fn")] = out.get(r.get("fn"), 0) + 1
        return out
    fa, fb = fn_counts(a), fn_counts(b)
    captures = {"a": fa, "b": fb,
                "new_fns": sorted(set(fb) - set(fa)),
                "gone_fns": sorted(set(fa) - set(fb))}

    total_a = sum(len(v) for v in (a.get("pairs") or {}).values())
    total_b = sum(len(v) for v in (b.get("pairs") or {}).values())
    changed_labels = sum(1 for e in pairs.values()
                         if e["output_changed"] or e["only_in_a"] or e["only_in_b"])
    return {"pairs": pairs, "hooks": hooks, "network": network, "captures": captures,
            "summary": {"corpus_a": total_a, "corpus_b": total_b,
                        "changed_labels": changed_labels}}


def changed_only(diff):
    """Flattened [{'label','input','a','b'}] from a compare_docs result."""
    out = []
    for label, entry in (diff.get("pairs") or {}).items():
        for c in entry.get("output_changed", []):
            out.append({"label": label, **c})
    return out
