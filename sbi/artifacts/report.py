"""Markdown report from a trace artifact — the deliverable after a session.

Takes the dict `Session.save()` wrote and renders what a human reviewer
needs: targets, hooks, corpus samples, counterexamples from any verify runs
stored in `extra`, and a network summary. Deterministic, dependency-free.
"""

import json


def markdown(doc, pair_samples=5, capture_samples=10):
    meta = doc.get("meta") or {}
    targets = ", ".join(f"`{u or 'n/a'}`" for _, _, u in meta.get("targets", []))
    lines = ["# Instrumentation report",
             "",
             f"- endpoint: `{meta.get('ws_endpoint', 'n/a')}`",
             f"- targets: {targets or 'n/a'}",
             ""]

    hooks = doc.get("hooks") or []
    lines += ["## Hooks", ""]
    if hooks:
        for h in hooks:
            mode = "args+returns" if h.get("returns") else "args"
            lines.append(f"- `{h.get('label')}` ({mode}) on `{h.get('expression')}`")
    else:
        lines.append("- none")
    lines.append("")

    pairs = doc.get("pairs") or {}
    lines += ["## Ground-truth corpora", ""]
    if pairs:
        for label, plist in pairs.items():
            lines.append(f"### `{label}` — {len(plist)} pairs")
            for p in plist[:pair_samples]:
                lines.append(f"    {json.dumps(p.get('input'), default=str)} -> "
                             f"{json.dumps(p.get('output'), default=str)}")
            if len(plist) > pair_samples:
                lines.append(f"    ... {len(plist) - pair_samples} more")
            lines.append("")
    else:
        lines += ["- none", ""]

    caps = doc.get("captures") or []
    lines += ["## Hook captures", "", f"{len(caps)} records", ""]
    for rec in caps[:capture_samples]:
        lines.append(f"- `{rec.get('fn')}({json.dumps(rec.get('args'), default=str)})` "
                     f"stack: {' <- '.join(rec.get('stack') or [])}")
    lines.append("")

    network = doc.get("network") or []
    urls = {}
    for r in network:
        if r.get("url"):
            urls[r["url"]] = urls.get(r["url"], 0) + 1
    lines += ["## Network", "", f"{len(network)} events, {len(urls)} distinct urls", ""]
    for url, n in sorted(urls.items(), key=lambda kv: -kv[1])[:15]:
        lines.append(f"- ({n}) `{url[:160]}`")
    lines.append("")

    extra = doc.get("extra") or {}
    console = extra.get("console") or doc.get("console") or []
    if console:
        lines += ["## Console / exceptions", ""]
        for r in console[:20]:
            lines.append(f"- [{r.get('level')}] {str(r.get('text'))[:200]}")
        lines.append("")

    dialogs = extra.get("dialogs") or doc.get("dialogs") or []
    if dialogs:
        lines += ["## JS dialogs", ""]
        for r in dialogs[:20]:
            lines.append(f"- [{r.get('type')}] {str(r.get('message'))[:160]} -> {r.get('action')}")
        lines.append("")

    if extra.get("verify"):
        lines += ["## Verify runs", ""]
        for v in extra["verify"]:
            lines.append(f"- `{v.get('candidate', '')[:120]}` -> verified={v.get('verified')} "
                         f"({v.get('matched')}/{v.get('tested')})")
        lines.append("")

    return "\n".join(lines)
