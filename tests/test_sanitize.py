"""Tests for sbi.sanitize: secret redaction of trace artifacts.

Pure tests against an in-memory artifact shaped like sbi.trace.save output,
plus a tempfile round-trip for sanitize_file. No browser, no network."""

import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbi.artifacts import sanitize
from sbi.artifacts.sanitize import sanitize_doc, sanitize_file


def make_artifact():
    """A trace artifact in the shape sbi.trace.save writes, seeded with
    secrets (bearer, token= param, set-cookie, high-entropy key, emails)
    and with values that must survive redaction."""
    return {
        "tool": "scrapeless-browser-instrumentation",
        "meta": {
            "ws_endpoint": "wss://127.0.0.1:9222/devtools/page/abc123def456"
                           "?token=s3cr3tT0k3nVa1u3",
            "targets": [["SID1", "page", "https://target.example/product"]],
        },
        "hooks": [
            {"label": "sign", "expression": "window.sign",
             "signature": "function sign(a, b)", "own_props": 3},
        ],
        "captures": [
            {"session": "SID1", "fn": "eval",
             "args": ["tokenization", "abc123"],
             "stack": ["eval",
                       "at run (https://cdn.example.org/js/"
                       "main-a1b2c3d4e5f6g7h8i9j0.bundle.js:8:42)"]},
        ],
        "pairs": {
            "sign": [
                {"input": ["https://api.example.com/v1/session"
                           "?token=Zx9Qm4Kb7Vn2Jr5Tt8Ww&verbose=1"],
                 "output": "secret a1B2c3D4e5F6g7H8i9J0k1L2 done "
                           "user@example.com",
                 "output_type": "string"},
                {"input": [42, True, None, ["nested", "abc123"]],
                 "output": 7, "output_type": "number"},
            ],
        },
        "network": [
            {"url": "https://api.example.com/v1/session"
                    "?token=Zx9Qm4Kb7Vn2Jr5Tt8Ww&verbose=1",
             "method": "POST",
             "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIs"
                                          "InR5cCI6IkpXVCJ9",
                         "set-cookie": "session=0f1e2d3c4b5a6978; Path=/; "
                                       "HttpOnly",
                         "x-request-id": "abc123"},
             "post_data": "{\"user\":\"diego@example.com\","
                          "\"secret\":\"Zx8Ky6Pq4Wv2Rm9Tb3Nc5Jd\","
                          "\"ref\":\"abc123\"}"},
        ],
        "extra": {"note": "email ops@example.com for details",
                  "flags": [True, False, None], "score": 0.5},
    }


class TestSanitizeDoc(unittest.TestCase):

    def test_input_doc_is_not_mutated(self):
        doc = make_artifact()
        snapshot = copy.deepcopy(doc)
        new_doc, _report = sanitize_doc(doc)
        self.assertEqual(doc, snapshot)          # nothing changed in place
        self.assertIsNot(new_doc, doc)
        self.assertIsNot(new_doc["pairs"], doc["pairs"])
        self.assertIsNot(new_doc["meta"], doc["meta"])
        self.assertIsNot(new_doc["pairs"]["sign"], doc["pairs"]["sign"])

    def test_query_params_bearer_cookie_email_entropy_redacted(self):
        new_doc, _report = sanitize_doc(make_artifact())
        # query params: ws_endpoint host/page kept, token value gone
        self.assertEqual(
            new_doc["meta"]["ws_endpoint"],
            "wss://127.0.0.1:9222/devtools/page/abc123def456"
            "?token=***REDACTED***")
        self.assertEqual(
            new_doc["pairs"]["sign"][0]["input"][0],
            "https://api.example.com/v1/session"
            "?token=***REDACTED***&verbose=1")
        self.assertEqual(new_doc["network"][0]["url"],
                         new_doc["pairs"]["sign"][0]["input"][0])
        # bearer: scheme kept, credential gone
        self.assertEqual(new_doc["network"][0]["headers"]["Authorization"],
                         "Bearer ***REDACTED***")
        # set-cookie: value redacted, attributes survive
        self.assertEqual(new_doc["network"][0]["headers"]["set-cookie"],
                         "session=***REDACTED***; Path=/; HttpOnly")
        # pair output: high-entropy secret + email
        self.assertEqual(new_doc["pairs"]["sign"][0]["output"],
                         "secret ***REDACTED*** done ***EMAIL***")
        # post_data: email + secret redacted, short ref survives
        self.assertEqual(new_doc["network"][0]["post_data"],
                         '{"user":"***EMAIL***",'
                         '"secret":"***REDACTED***","ref":"abc123"}')
        # email in extra
        self.assertEqual(new_doc["extra"]["note"],
                         "email ***EMAIL*** for details")

    def test_safe_values_survive(self):
        new_doc, _report = sanitize_doc(make_artifact())
        self.assertEqual(new_doc["tool"],
                         "scrapeless-browser-instrumentation")
        self.assertEqual(new_doc["captures"][0]["args"],
                         ["tokenization", "abc123"])
        # stacks are excluded from the high-entropy rule: long identifier kept
        self.assertEqual(
            new_doc["captures"][0]["stack"][1],
            "at run (https://cdn.example.org/js/"
            "main-a1b2c3d4e5f6g7h8i9j0.bundle.js:8:42)")
        # scalars, bools, None and nested lists pass through
        self.assertEqual(new_doc["pairs"]["sign"][1],
                         {"input": [42, True, None, ["nested", "abc123"]],
                          "output": 7, "output_type": "number"})
        self.assertEqual(new_doc["extra"]["flags"], [True, False, None])
        self.assertEqual(new_doc["extra"]["score"], 0.5)
        self.assertEqual(new_doc["meta"]["targets"],
                         [["SID1", "page", "https://target.example/product"]])
        self.assertEqual(new_doc["network"][0]["headers"]["x-request-id"],
                         "abc123")

    def test_header_secret_values_are_redacted(self):
        # signed/custom auth headers (what observed_requests() captures) carry
        # secrets a Bearer/cookie rule won't catch; header values are scanned
        # for high-entropy tokens, while UAs and URLs survive.
        doc = {"network": [{"headers": {
            "x-dq7hy5l1-a": "Kx9Pq4Wm7Tb3Nc5Jd8Le2fA1b2C3d4E5",   # signature
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "referer": "https://target.example/checkout",
            "x-request-id": "abc123",
        }}]}
        new_doc, report = sanitize_doc(doc)
        h = new_doc["network"][0]["headers"]
        self.assertEqual(h["x-dq7hy5l1-a"], sanitize.REDACTED)     # redacted
        self.assertEqual(h["user-agent"],
                         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
        self.assertEqual(h["referer"], "https://target.example/checkout")
        self.assertEqual(h["x-request-id"], "abc123")             # short id kept
        self.assertGreaterEqual(report["doc"]["high_entropy"], 1)

    def test_report_counts(self):
        _new_doc, report = sanitize_doc(make_artifact())
        self.assertEqual(report["doc"], {"query_param": 3, "auth": 1,
                                         "cookie": 1, "email": 3,
                                         "high_entropy": 2})
        self.assertEqual(report["total"], 10)
        self.assertEqual(report["fields_seen"], 27)

    def test_high_entropy_boundaries(self):
        probe = {"pairs": {"p": [
            {"input": ["hex 0123456789abcdef01234567 end"], "output": None},
            {"input": ["sig_v2_Kx9Pq4Wm7Tb3Nc5Jd8Le2f"], "output": None},
            {"input": ["hash 0123456789abcdef0123456789abcdef01 end"],
             "output": None},
            {"input": ["url https://app.example.com/deep/path/segments kept"],
             "output": None},
            {"input": ["cdn static.cdn.example.com/assets/main.css ok"],
             "output": None},
            {"input": ["words internationalization tokenization_processing"],
             "output": None},
        ]}}
        new_doc, report = sanitize_doc(probe)
        inputs = [p["input"][0] for p in new_doc["pairs"]["p"]]
        self.assertEqual(inputs[0], "hex 0123456789abcdef01234567 end")
        self.assertEqual(inputs[1], "***REDACTED***")
        self.assertEqual(inputs[2], "hash ***REDACTED*** end")
        self.assertEqual(inputs[3],
                         "url https://app.example.com/deep/path/segments kept")
        self.assertEqual(inputs[4],
                         "cdn static.cdn.example.com/assets/main.css ok")
        self.assertEqual(inputs[5],
                         "words internationalization tokenization_processing")
        self.assertEqual(report["doc"]["high_entropy"], 2)

    def test_cookie_text_after_header_colon(self):
        doc = {"extra": {"raw": "set-cookie: session=deadbeefcafe987; "
                                "Path=/; HttpOnly\nx-frame: sameorigin"}}
        new_doc, report = sanitize_doc(doc)
        self.assertEqual(
            new_doc["extra"]["raw"],
            "set-cookie: session=***REDACTED***; Path=/; HttpOnly\n"
            "x-frame: sameorigin")
        self.assertEqual(report["doc"]["cookie"], 1)

    def test_basic_auth_scheme_kept(self):
        doc = {"network": [{"headers": {"proxy-authorization":
                                        "Basic dXNlcjpwYXNz"}}]}
        new_doc, report = sanitize_doc(doc)
        self.assertEqual(new_doc["network"][0]["headers"]
                         ["proxy-authorization"], "Basic ***REDACTED***")
        self.assertEqual(report["doc"]["auth"], 1)

    def test_extra_patterns(self):
        doc = {"extra": {"host": "connecting to houston-77 primary"}}
        new_doc, report = sanitize_doc(
            doc, extra_patterns=(("internal_host", r"houston-\d+"),))
        self.assertEqual(new_doc["extra"]["host"],
                         "connecting to ***REDACTED*** primary")
        self.assertEqual(report["doc"]["internal_host"], 1)
        self.assertEqual(report["total"], 1)

    def test_non_json_values_pass_through_untouched(self):
        opaque = object()
        doc = {"extra": {"opaque": opaque, "frozen": (1, 2),
                         "sneaky": {"nested": "Bearer abc"}}}
        new_doc, _report = sanitize_doc(doc)
        self.assertIs(new_doc["extra"]["opaque"], opaque)
        self.assertIs(new_doc["extra"]["frozen"], doc["extra"]["frozen"])
        self.assertEqual(new_doc["extra"]["sneaky"]["nested"],
                         "Bearer ***REDACTED***")

    def test_empty_doc(self):
        new_doc, report = sanitize_doc({})
        self.assertEqual(new_doc, {})
        self.assertEqual(report,
                         {"doc": {"query_param": 0, "auth": 0, "cookie": 0,
                                  "email": 0, "high_entropy": 0},
                          "total": 0, "fields_seen": 0})


class TestSanitizeFile(unittest.TestCase):

    def test_default_name_and_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "artifact.json")
            with open(src, "w", encoding="utf-8") as fh:
                json.dump(make_artifact(), fh)
            out_path, report = sanitize_file(src)
            self.assertEqual(out_path,
                             os.path.join(tmp, "artifact.sanitized.json"))
            self.assertTrue(os.path.exists(out_path))
            with open(out_path, "r", encoding="utf-8") as fh:
                on_disk = fh.read()
                reloaded = json.loads(on_disk)
            # secrets are gone from the written file
            self.assertNotIn("s3cr3tT0k3nVa1u3", on_disk)
            self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", on_disk)
            self.assertNotIn("Zx9Qm4Kb7Vn2Jr5Tt8Ww", on_disk)
            self.assertNotIn("user@example.com", on_disk)
            # redacted values reload correctly
            self.assertEqual(reloaded["network"][0]["headers"]
                             ["Authorization"], "Bearer ***REDACTED***")
            self.assertEqual(reloaded["meta"]["ws_endpoint"],
                             "wss://127.0.0.1:9222/devtools/page/"
                             "abc123def456?token=***REDACTED***")
            self.assertEqual(reloaded["pairs"]["sign"][0]["output"],
                             "secret ***REDACTED*** done ***EMAIL***")
            # report matches the in-memory run on the same doc
            _doc, expected = sanitize_doc(make_artifact())
            self.assertEqual(report, expected)

    def test_explicit_out_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "trace.json")
            with open(src, "w", encoding="utf-8") as fh:
                json.dump({"extra": {"who": "diego@example.com"}}, fh)
            explicit = os.path.join(tmp, "shared.json")
            out_path, report = sanitize_file(src, explicit)
            self.assertEqual(out_path, explicit)
            with open(explicit, "r", encoding="utf-8") as fh:
                self.assertEqual(json.load(fh),
                                 {"extra": {"who": "***EMAIL***"}})
            self.assertEqual(report["doc"]["email"], 1)


if __name__ == "__main__":
    unittest.main()
