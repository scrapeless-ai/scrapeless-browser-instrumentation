"""Offline tests for sbi.compare artifact diffing."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbi.artifacts.compare import changed_only, compare_docs


def doc(pairs=None, hooks=None, network=None, captures=None):
    return {"tool": "scrapeless-browser-instrumentation", "meta": {},
            "hooks": hooks or [], "pairs": pairs or {},
            "network": network or [], "captures": captures or []}


A = doc(
    pairs={"sign": [{"input": ["zoe", 0], "output": "s1"},
                    {"input": ["ana", 3], "output": "s2"},
                    {"input": ["gone", 1], "output": "sX"}],
           "old": [{"input": [1], "output": 1}]},
    hooks=[{"label": "sign", "expression": "window.sign", "returns": False},
           {"label": "gone", "expression": "window.gone", "returns": False}],
    network=[{"kind": "request", "url": "https://t/a"},
             {"kind": "request", "url": "https://t/b"}],
    captures=[{"fn": "sign", "args": []}, {"fn": "sign", "args": []},
              {"fn": "gone", "args": []}])

B = doc(
    pairs={"sign": [{"input": ["zoe", 0], "output": "s1"},
                    {"input": ["ana", 3], "output": "CHANGED"},
                    {"input": ["new", 9], "output": "s9"}]},
    hooks=[{"label": "sign", "expression": "window.sign", "returns": True},
           {"label": "fresh", "expression": "window.fresh", "returns": False}],
    network=[{"kind": "request", "url": "https://t/a"},
             {"kind": "request", "url": "https://t/c"}],
    captures=[{"fn": "sign", "args": []}, {"fn": "fresh", "args": []}])


class TestCompareDocs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.diff = compare_docs(A, B)

    def test_pair_changes(self):
        sign = self.diff["pairs"]["sign"]
        self.assertEqual([c["a"] for c in sign["output_changed"]], ["s2"])
        self.assertEqual([c["b"] for c in sign["output_changed"]], ["CHANGED"])
        self.assertEqual(sign["only_in_a"], [["gone", 1]])
        self.assertEqual(sign["only_in_b"], [["new", 9]])

    def test_label_only_in_a(self):
        old = self.diff["pairs"]["old"]
        self.assertEqual(old["only_in_a"], [[1]])
        self.assertEqual(old["only_in_b"], [])

    def test_hooks(self):
        h = self.diff["hooks"]
        self.assertEqual(h["only_in_a"], ["gone"])
        self.assertEqual(h["only_in_b"], ["fresh"])
        self.assertEqual(h["mode_changed"],
                         [{"label": "sign", "a": "args", "b": "args+returns"}])

    def test_network(self):
        self.assertEqual(self.diff["network"]["new_urls"], ["https://t/c"])
        self.assertEqual(self.diff["network"]["dropped_urls"], ["https://t/b"])

    def test_captures(self):
        c = self.diff["captures"]
        self.assertEqual(c["a"], {"sign": 2, "gone": 1})
        self.assertEqual(c["b"], {"sign": 1, "fresh": 1})
        self.assertEqual(c["new_fns"], ["fresh"])
        self.assertEqual(c["gone_fns"], ["gone"])

    def test_summary(self):
        s = self.diff["summary"]
        self.assertEqual(s["corpus_a"], 4)
        self.assertEqual(s["corpus_b"], 3)
        self.assertEqual(s["changed_labels"], 2)   # sign + old

    def test_deterministic(self):
        self.assertEqual(compare_docs(A, B), compare_docs(A, B))

    def test_changed_only(self):
        flat = changed_only(self.diff)
        self.assertEqual(flat, [{"label": "sign", "input": ["ana", 3],
                                 "a": "s2", "b": "CHANGED"}])

    def test_identical_docs(self):
        d = compare_docs(A, A)
        self.assertEqual(d["summary"]["changed_labels"], 0)
        self.assertEqual(changed_only(d), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
