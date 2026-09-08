"""Offline tests for sbi.artifacts ArtifactStore."""

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbi.artifacts import ArtifactStore


def doc(label, output, url):
    return {"tool": "scrapeless-browser-instrumentation",
            "meta": {"targets": [["s", "page", url]]},
            "hooks": [], "captures": [],
            "pairs": {label: [{"input": ["zoe"], "output": output}]},
            "network": [{"kind": "request", "url": url}], "extra": {}}


class TestArtifactStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ArtifactStore(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_save_list_load_roundtrip(self):
        p1 = self.store.save(doc("sign", "tok_9f27", "https://t/1"), name="run one")
        time.sleep(0.05)
        p2 = self.store.save(doc("enc", "QQ==", "https://t/2"))
        self.assertTrue(p1.endswith("run_one.json"), p1)
        self.assertNotEqual(os.path.basename(p1), os.path.basename(p2))
        entries = self.store.list()
        self.assertEqual({e["name"] for e in entries},
                         {"run_one.json", os.path.basename(p2)})
        self.assertGreater(entries[0]["mtime"], entries[1]["mtime"])   # newest first
        loaded = self.store.load("run_one.json")
        self.assertEqual(loaded["pairs"]["sign"][0]["output"], "tok_9f27")
        self.assertIn("saved_at", loaded["meta"])

    def test_search_substring_and_regex(self):
        self.store.save(doc("sign", "tok_9f27aa", "https://t/1"), name="a.json")
        self.store.save(doc("enc", "QQ==", "https://api.example/v2"), name="b.json")
        hits = self.store.search("tok_9f27")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["label"], "sign")
        self.assertEqual(hits[0]["where"], "pairs")
        rx = self.store.search(r"api\.example", regex=True)
        self.assertEqual(rx[0]["where"], "network")
        self.assertEqual(len(self.store.search("nothing-here")), 0)

    def test_latest(self):
        self.store.save(doc("a", "1", "https://t/1"), name="a.json")
        time.sleep(0.05)
        self.store.save(doc("b", "2", "https://t/2"), name="b.json")
        self.assertEqual(self.store.latest()["pairs"], {"b": [{"input": ["zoe"], "output": "2"}]})

    def test_latest_empty(self):
        self.assertIsNone(self.store.latest())

    def test_prune(self):
        for i in range(4):
            self.store.save(doc(f"l{i}", str(i), f"https://t/{i}"), name=f"t{i}.json")
            time.sleep(0.02)
        removed = self.store.prune(keep=2)
        self.assertEqual(len(removed), 2)
        names = {e["name"] for e in self.store.list()}
        self.assertEqual(names, {"t2.json", "t3.json"})   # two newest survive

    def test_name_sanitization(self):
        path = self.store.save(doc("x", "1", "https://t"), name="my/trace!!")
        self.assertTrue(os.path.basename(path).startswith("my_trace__"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
