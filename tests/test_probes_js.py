"""Node-executed tests for the page-side recorder snippets in sbi.probes.

The sources built by build_sources() target browsers, but they only need a
`window` (an alias of globalThis), TextEncoder and btoa — all available in
Node 22 — so each test writes a temp .mjs that runs a probe source, triggers
it, and prints a single JSON line combining behaviour results with the drained
recorder buffer. Tests skip gracefully when node is not on PATH.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbi.hooks.probes import build_sources

NODE = shutil.which("node")

_PRELUDE = "globalThis.window = globalThis;\n"

# Appended after the test body: the body must set `result`, we add the drain.
_EMIT = """
console.log("SBI_OUT=" + JSON.stringify({
  result: result,
  records: JSON.parse(window.__sbi__.drain()),
}));
"""


def run_node(body, source, pre=""):
    """Write shims + optional pre-js + probe source + body to a temp .mjs and
    run node on it. `pre` executes BEFORE the probe source installs (for fake
    fetch/XHR shims the wrappers must exist at install time). Returns the
    parsed {result, records} object from the single SBI_OUT= line."""
    if not NODE:
        raise RuntimeError("node is required for run_node()")
    with tempfile.TemporaryDirectory(prefix="sbi_probes_") as tmp:
        path = os.path.join(tmp, "probe_test.mjs")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_PRELUDE)
            fh.write(pre)
            fh.write(source)
            fh.write("\n")
            fh.write(body)
            fh.write(_EMIT)
        proc = subprocess.run([NODE, path], capture_output=True,
                              encoding="utf-8", timeout=60)
    line = next((l for l in proc.stdout.splitlines() if l.startswith("SBI_OUT=")), None)
    if proc.returncode != 0 or line is None:
        raise AssertionError(
            "node run failed (rc=%s)\nstdout:\n%s\nstderr:\n%s"
            % (proc.returncode, proc.stdout, proc.stderr))
    return json.loads(line[len("SBI_OUT="):])


class TestProbesJS(unittest.TestCase):
    def setUp(self):
        if not NODE:
            self.skipTest("node not available")

    def test_build_sources_combines(self):
        srcs = build_sources(["eval", "net"])
        self.assertEqual(len(srcs), 1)
        self.assertIn("__sbi__", srcs[0])
        self.assertIn("probe: 'eval'", srcs[0])
        self.assertIn("probe: 'fetch'", srcs[0])
        self.assertEqual(build_sources(["nope"]), [])

    def test_eval_probe_records_and_preserves_behaviour(self):
        (src,) = build_sources(["eval"])
        out = run_node("""
const result = {
  evalResult: window.eval("6*7"),
  fnResult: new Function("return 21")(),
};
""", src)
        self.assertEqual(out["result"]["evalResult"], 42)
        self.assertEqual(out["result"]["fnResult"], 21)
        recs = out["records"]
        self.assertIn({"probe": "eval", "src": "6*7"}, recs)
        fn = [r for r in recs if r.get("probe") == "Function"]
        self.assertTrue(fn, recs)
        self.assertIn("return 21", fn[0]["src"])

    def test_eval_masquerade_tostring(self):
        (src,) = build_sources(["eval"])
        out = run_node("""
const result = {
  evalString: String(window.eval),
  evalName: window.eval.name,
  functionString: String(window.Function),
  functionName: window.Function.name,
};
""", src)
        r = out["result"]
        # masq copies the original native toString / name, wrapper stays hidden
        self.assertIn("native code", r["evalString"])
        self.assertIn("native code", r["functionString"])
        self.assertNotIn("__sbi__", r["evalString"] + r["functionString"])
        self.assertEqual(r["evalName"], "eval")
        self.assertEqual(r["functionName"], "Function")

    def test_net_fetch_in_and_out_records(self):
        (src,) = build_sources(["net"])
        out = run_node("""
const res = await window.fetch("https://t/x", { method: "POST", body: '{"a":1}' });
const result = { status: res.status };
""", src, pre="""
window.fetch = (u, init) => Promise.resolve({ status: 200, url: String(u) });
""")
        self.assertEqual(out["result"]["status"], 200)
        recs = out["records"]
        ins = [r for r in recs if r.get("probe") == "fetch" and r.get("phase") == "in"]
        self.assertTrue(ins, recs)
        self.assertEqual(ins[0]["url"], "https://t/x")
        self.assertEqual(ins[0]["method"], "POST")
        self.assertEqual(ins[0]["body"], '{"a":1}')
        outs = [r for r in recs if r.get("probe") == "fetch" and r.get("phase") == "out"]
        self.assertTrue(outs, recs)
        self.assertEqual(outs[0]["status"], 200)
        self.assertEqual(outs[0]["url"], "https://t/x")

    def test_net_xhr_records_open_and_send(self):
        (src,) = build_sources(["net"])
        out = run_node("""
const xhr = new window.XMLHttpRequest();
xhr.open("GET", "https://t/y");
xhr.send("hello=1");
const result = { sent: xhr._sent, opened: xhr._opened };
""", src, pre="""
class FakeXHR {
  open(method, url) { this._opened = [method, url]; }
  send(body) { this._sent = body; }
}
window.XMLHttpRequest = FakeXHR;
""")
        self.assertEqual(out["result"]["opened"], ["GET", "https://t/y"])
        self.assertEqual(out["result"]["sent"], "hello=1")
        xhr = [r for r in out["records"] if r.get("probe") == "xhr"]
        self.assertTrue(xhr, out["records"])
        self.assertEqual(xhr[0]["method"], "GET")
        self.assertEqual(xhr[0]["url"], "https://t/y")
        self.assertEqual(xhr[0]["body"], "hello=1")

    def test_crypto_digest_records_and_passes_through(self):
        (src,) = build_sources(["crypto"])
        out = run_node("""
const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("abc"));
const result = { byteLength: digest.byteLength };
""", src)
        self.assertEqual(out["result"]["byteLength"], 32)  # behaviour preserved
        recs = out["records"]
        ins = [r for r in recs if r.get("probe") == "crypto"
               and r.get("op") == "digest" and r.get("phase") == "in"]
        self.assertTrue(ins, recs)
        # typed-array arg serialised as base64; b64("abc") == "YWJj"
        self.assertEqual(ins[0]["args"], ["SHA-256", {"b64": "YWJj"}])
        outs = [r for r in recs if r.get("probe") == "crypto"
                and r.get("op") == "digest" and r.get("phase") == "out"]
        self.assertTrue(outs, recs)
        self.assertEqual(len(outs[0]["out"]), 44)  # b64 of 32 bytes
        self.assertEqual(base64.b64decode(outs[0]["out"]),
                         hashlib.sha256(b"abc").digest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
