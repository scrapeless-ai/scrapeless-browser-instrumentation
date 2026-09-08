"""The oracle: nothing inferred is trusted until the diff is empty.

A reimplementation candidate is run in an isolated page that cannot see the
instrumented target — it only gets the code you wrote. It is checked against
the captured ground-truth corpus (hooked input -> output pairs) and against
the live target for fresh inputs. The result is a structured diff with
concrete counterexamples; iterate until `verified` is true.
"""

import json

from .matching import compare as _compare


class Oracle:
    def __init__(self, engine, tracer):
        self.engine = engine
        self.tracer = tracer
        self.scratch = None

    # -- ground truth --------------------------------------------------------

    def corpus(self, label):
        with self.tracer.lock:
            return list(self.tracer.pairs.get(label, []))

    def corpora(self):
        """Label -> pair count (sizes; the full lists live in corpus())."""
        with self.tracer.lock:
            return {k: len(v) for k, v in self.tracer.pairs.items()}

    def load_corpus(self, label, pairs):
        """Inject pairs restored from a saved trace so verify() works without re-capturing."""
        with self.tracer.lock:
            self.tracer.pairs.setdefault(label, []).extend(pairs)

    # -- execution -----------------------------------------------------------

    def query_live(self, fn_expr, inputs, target_url=None):
        """Drive the real function with fresh inputs; observe actual behaviour."""
        sid = self.engine.resolve_session(target_url)
        out = []
        for inp in inputs:
            args = inp if isinstance(inp, list) else [inp]
            try:
                r = self.engine.cdp.send(
                    "Runtime.evaluate",
                    {"expression": f"({fn_expr}).apply(null, {json.dumps(args)})",
                     "returnByValue": True, "awaitPromise": True, "silent": True},
                    session_id=sid)
            except Exception as e:
                out.append({"__error__": f"cdp: {e}"})
                continue
            out.append({"__error__": _exc(r["exceptionDetails"])} if r.get("exceptionDetails")
                       else r.get("result", {}).get("value"))
        return out

    def run_candidate(self, candidate, inputs):
        """Run the candidate in the isolated scratch page, where the real
        function does not exist — a candidate that cheats by calling it fails."""
        if self.scratch is None:
            self.scratch = self.engine.open_isolated_page()
        out = []
        for inp in inputs:
            args = inp if isinstance(inp, list) else [inp]
            try:
                r = self.engine.cdp.send(
                    "Runtime.evaluate",
                    {"expression": f"({candidate}).apply(null, {json.dumps(args)})",
                     "returnByValue": True, "awaitPromise": True, "silent": True},
                    session_id=self.scratch)
            except Exception as e:
                out.append({"__error__": f"cdp: {e}"})
                continue
            out.append({"__error__": _exc(r["exceptionDetails"])} if r.get("exceptionDetails")
                       else r.get("result", {}).get("value"))
        return out

    # -- verify ----------------------------------------------------------------

    def verify(self, fn_expr, candidate, label=None, fresh_inputs=None,
               target_url=None, sample=200, max_mismatches=5,
               mode="exact", tol=0.0, rel=0.0, seconds=60.0):
        """mode: exact (default) | loose_string | numeric | time_tolerant —
        see sbi.matching; non-exact modes exist for nonce/time-dependent
        outputs and are always named in coverage_notes."""
        tests, skipped = [], 0
        for p in (self.corpus(label)[:sample] if label else []):
            if p.get("output") is None and p.get("unserialized"):
                skipped += 1
                continue
            tests.append((p["input"], p.get("output"), "corpus"))

        live_errors = 0
        if fresh_inputs:
            for inp, expected in zip(fresh_inputs, self.query_live(fn_expr, fresh_inputs, target_url)):
                if isinstance(expected, dict) and "__error__" in expected:
                    live_errors += 1
                else:
                    tests.append((inp, expected, "live"))

        got = self.run_candidate(candidate, [t[0] for t in tests])
        matched, mismatches = 0, []
        for (inp, expected, source), result in zip(tests, got):
            if _compare(expected, result, mode, tol=tol, rel=rel,
                        seconds=seconds)["match"]:
                matched += 1
            elif len(mismatches) < max_mismatches:
                mismatches.append({"input": inp, "expected": expected, "got": result, "source": source})

        corpus_n = sum(1 for t in tests if t[2] == "corpus")
        notes = [f"{corpus_n} corpus + {len(tests) - corpus_n} live inputs; candidate ran isolated"]
        if mode != "exact":
            notes.append(f"comparison mode={mode} (structural, not exact)")
        if skipped:
            notes.append(f"{skipped} corpus pairs unverifiable (non-serializable output)")
        if live_errors:
            notes.append(f"{live_errors} fresh inputs errored on the live function")
        if not tests:
            notes.append("NO ground truth — capture a corpus first or pass fresh_inputs")
        return {"verified": bool(tests) and matched == len(tests), "tested": len(tests),
                "matched": matched, "mismatches": mismatches, "coverage_notes": "; ".join(notes)}

    def close(self):
        if self.scratch is not None:
            self.engine.close_target(self.scratch)
            self.scratch = None


def _exc(details):
    exc = details.get("exception") or {}
    return exc.get("description") or details.get("text") or "exception"


def _equal(a, b):
    """Strict equality: bool vs int and '1' vs 1 must not pass."""
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    return a == b and type(a) == type(b)
