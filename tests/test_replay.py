"""Pure tests for sbi.replay: plan / apply / verify_saved / from_path against
an in-memory trace document and fake sessions. No browser, no network."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbi.artifacts import replay


def sample_doc():
    """A trace in the exact shape sbi.trace.save writes (tracer.hook records
    included verbatim, with their non-serializable-for-replay extras)."""
    return {
        "tool": "scrapeless-browser-instrumentation",
        "meta": {"ws_endpoint": "wss://browser.example/api",
                 "targets": [["SID1", "page", "https://target.example/product"],
                             ["SID2", "iframe", "https://cdn.example/frame"]]},
        "hooks": [
            {"label": "sign", "expression": "window.sign", "session": "SID1",
             "target_url": None, "returns": True, "ret_set": True,
             "signature": "function sign(a, b)", "own_props": 3},
            {"label": "sign", "expression": "window.sign", "session": "SID1",
             "target_url": None, "returns": True, "ret_set": True,
             "signature": "function sign(a, b)", "own_props": 3},
            {"label": "hash", "expression": "obj.hash", "session": "SID2",
             "target_url": "cdn.example", "returns": False, "ret_set": False,
             "signature": "function hash(s)", "own_props": 2},
        ],
        "captures": [{"session": "SID1", "fn": "sign", "args": ["a", "b"],
                      "stack": ["sign", "onsubmit"]}],
        "pairs": {"sign": [{"input": ["u", "p"], "output": "c2ln", "output_type": "string"}],
                  "hash": [{"input": ["x"], "output": 7, "output_type": "number"}]},
        "network": [{"url": "https://target.example/api"},
                    {"url": "https://cdn.example/x.js"}],
        "extra": {},
    }


class FakeSession:
    """Records navigate()/hook() calls; raises on one poisoned expression."""

    def __init__(self, poison=None):
        self.poison = poison
        self.navigated = []
        self.hooked = []

    def navigate(self, url):
        self.navigated.append(url)
        return url

    def hook(self, expression, target_url=None, capture_returns=False, label=None):
        if expression == self.poison:
            raise RuntimeError(f"{expression!r} is not a function in page: undefined")
        self.hooked.append({"expression": expression, "target_url": target_url,
                            "capture_returns": capture_returns, "label": label})
        return self


class FakeOracle:
    def __init__(self):
        self.loaded = []

    def load_corpus(self, label, pairs):
        self.loaded.append((label, list(pairs)))


class EchoSession:
    """Its verify() echoes its arguments back, for assertion."""

    def __init__(self):
        self.oracle = FakeOracle()
        self.verify_calls = []

    def verify(self, fn_expr, candidate, label=None, fresh_inputs=None, **kw):
        call = {"fn_expr": fn_expr, "candidate": candidate,
                "label": label, "fresh_inputs": fresh_inputs}
        self.verify_calls.append(call)
        return call


class PlanTests(unittest.TestCase):
    def test_extracts_url_from_first_target(self):
        self.assertEqual(replay.plan(sample_doc())["url"],
                         "https://target.example/product")

    def test_about_blank_and_non_http_yield_none(self):
        doc = sample_doc()
        doc["meta"]["targets"] = [["S1", "page", "about:blank"]]
        self.assertIsNone(replay.plan(doc)["url"])
        doc["meta"]["targets"] = [["S1", "page", "devtools://devtools"]]
        self.assertIsNone(replay.plan(doc)["url"])

    def test_hooks_keep_serializable_fields_and_dedup(self):
        hooks = replay.plan(sample_doc())["hooks"]
        self.assertEqual([h["label"] for h in hooks], ["sign", "hash"])
        for h in hooks:
            self.assertEqual(set(h), set(replay.HOOK_FIELDS))
        self.assertEqual(hooks[0], {"expression": "window.sign", "label": "sign",
                                    "returns": True, "target_url": None})
        self.assertEqual(hooks[1]["target_url"], "cdn.example")
        self.assertIs(hooks[1]["returns"], False)

    def test_corpus_labels_and_network_count(self):
        p = replay.plan(sample_doc())
        self.assertEqual(p["corpus_labels"], ["sign", "hash"])
        self.assertEqual(p["network_events"], 2)

    def test_tolerates_sparse_doc(self):
        p = replay.plan({"hooks": [], "pairs": {}, "network": []})
        self.assertIsNone(p["url"])
        self.assertEqual(p["hooks"], [])
        self.assertEqual(p["corpus_labels"], [])
        self.assertEqual(p["network_events"], 0)


class ApplyTests(unittest.TestCase):
    def test_navigates_and_rehooks_every_planned_hook(self):
        s = FakeSession()
        out = replay.apply(s, sample_doc())
        self.assertEqual(s.navigated, ["https://target.example/product"])
        self.assertEqual(out, {"url": "https://target.example/product",
                               "hooked": ["sign", "hash"], "failed": []})
        self.assertEqual(s.hooked[0], {"expression": "window.sign", "target_url": None,
                                       "capture_returns": True, "label": "sign"})
        self.assertEqual(s.hooked[1]["target_url"], "cdn.example")

    def test_poisoned_hook_collected_not_raised(self):
        doc = sample_doc()
        doc["hooks"].append({"label": "gone", "expression": "window.boom",
                             "target_url": None, "returns": False})
        s = FakeSession(poison="window.boom")
        out = replay.apply(s, doc)
        self.assertEqual(out["hooked"], ["sign", "hash"])
        self.assertEqual(len(out["failed"]), 1)
        self.assertEqual(out["failed"][0]["expression"], "window.boom")
        self.assertIn("not a function", out["failed"][0]["error"])

    def test_no_url_no_navigation(self):
        doc = sample_doc()
        doc["meta"]["targets"] = [["S1", "page", "about:blank"]]
        s = FakeSession()
        out = replay.apply(s, doc)
        self.assertEqual(s.navigated, [])
        self.assertIsNone(out["url"])
        self.assertEqual(out["hooked"], ["sign", "hash"])


class VerifySavedTests(unittest.TestCase):
    def test_loads_corpus_under_label_and_resolves_expression_from_doc(self):
        s = EchoSession()
        out = replay.verify_saved(s, sample_doc(), "sign", "(u,p)=>btoa(u+':'+p)")
        self.assertEqual(s.oracle.loaded, [("sign", sample_doc()["pairs"]["sign"])])
        (call,) = s.verify_calls
        self.assertEqual(call["fn_expr"], "window.sign")  # from doc["hooks"]
        self.assertEqual(call["candidate"], "(u,p)=>btoa(u+':'+p)")
        self.assertEqual(call["label"], "sign")
        self.assertIsNone(call["fresh_inputs"])
        self.assertIs(out, call)  # session.verify's result passes through

    def test_fresh_inputs_passed_through(self):
        s = EchoSession()
        replay.verify_saved(s, sample_doc(), "sign", "c", fresh_inputs=[["a", "b"]])
        self.assertEqual(s.verify_calls[0]["fresh_inputs"], [["a", "b"]])

    def test_fn_expr_fallback_and_missing_expression_raises(self):
        s = EchoSession()
        replay.verify_saved(s, sample_doc(), "nolabel", "c", fn_expr="window.other")
        self.assertEqual(s.verify_calls[0]["fn_expr"], "window.other")
        with self.assertRaises(ValueError):
            replay.verify_saved(s, sample_doc(), "nolabel", "c")


class FromPathTests(unittest.TestCase):
    def test_round_trip_through_json_file(self):
        doc = sample_doc()
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2, default=str)
            loaded = replay.from_path(path)
            self.assertEqual(loaded, doc)
            self.assertEqual(replay.plan(loaded), replay.plan(doc))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
