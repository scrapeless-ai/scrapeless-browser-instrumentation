"""Trace artifacts: save / load captures, corpora, network records.

Everything observed is savable to one JSON file that reloads into the oracle
for re-verification. With Node.js available, `offline_verify` re-runs a
candidate against the saved corpus without any browser session at all.
"""

import json
import shutil
import subprocess
import tempfile


def save(path, meta, tracer, network=None, extra=None):
    doc = {
        "tool": "scrapeless-browser-instrumentation",
        "meta": meta,
        "hooks": tracer.hooks if tracer else [],
        "captures": tracer.captures if tracer else [],
        "pairs": tracer.pairs if tracer else {},
        "network": network.drain() if network else [],
        "extra": extra or {},
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, default=str)
    return doc


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def offline_verify(trace, label, candidate, sample=200, max_mismatches=5):
    """Re-verify a candidate against a saved corpus, offline, using Node.

    `trace` is a path or an already-loaded dict. The candidate runs in a bare
    Node process — no page, no network: if it secretly calls home to the live
    target, it fails here rather than passing.
    """
    doc = load(trace) if isinstance(trace, str) else trace
    pairs = (doc.get("pairs") or {}).get(label, [])
    if not pairs:
        return {"verified": False, "tested": 0, "matched": 0, "mismatches": [],
                "coverage_notes": f"no saved corpus under label {label!r}"}
    pairs = pairs[:sample]
    node = shutil.which("node")
    if not node:
        raise RuntimeError("offline_verify needs Node.js on PATH (or use Oracle.verify online)")
    results = _run_node(node, candidate, [p.get("input") for p in pairs])
    matched, mismatches = 0, []
    from ..verify.oracle import _equal
    for p, got in zip(pairs, results):
        if isinstance(got, dict) and got.get("__error__") and p.get("unserialized"):
            continue  # unserializable expected output can't be compared offline
        value = got.get("value") if isinstance(got, dict) and "value" in got else got
        if _equal(p.get("output"), value):
            matched += 1
        elif len(mismatches) < max_mismatches:
            mismatches.append({"input": p.get("input"), "expected": p.get("output"), "got": value})
    notes = [f"{len(pairs)} saved corpus pairs; candidate ran in bare Node (no browser)"]
    skipped = sum(1 for p in pairs if p.get("output") is None and p.get("unserialized"))
    if skipped:
        notes.append(f"{skipped} unserializable pairs skipped")
    return {"verified": matched == len(pairs) - skipped and (len(pairs) - skipped) > 0,
            "tested": len(pairs) - skipped, "matched": matched,
            "mismatches": mismatches, "coverage_notes": "; ".join(notes)}


def _run_node(node, candidate, inputs):
    script = """
const [raw] = process.argv.slice(2);
const cand = (%s);
const inputs = JSON.parse(raw);
(async () => {
  const out = [];
  for (const a of inputs) {
    try { out.push({ value: await cand.apply(null, a == null ? [] : a) }); }
    catch (e) { out.push({ __error__: String(e && e.message || e) }); }
  }
  process.stdout.write(JSON.stringify(out));
})();
""" % candidate
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(script)
        path = f.name
    try:
        proc = subprocess.run([node, path, json.dumps(inputs or [])],
                              capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise RuntimeError(f"node failed: {proc.stderr[:400]}")
        return json.loads(proc.stdout or "[]")
    finally:
        import os
        try:
            os.unlink(path)
        except OSError:
            pass
