"""Tests for sbi.doctor: pre-flight environment/endpoint reporting.

Everything runs offline: SCRAPELESS_* env vars are removed around each test,
the unreachable endpoint is a guaranteed-refused local port
(http://127.0.0.1:1), and wss resolution is pure string formatting — so no
browser, real token or network access is ever needed."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import sbi
from sbi import doctor

SCRAPELESS_VARS = ("SCRAPELESS_API_TOKEN", "SCRAPELESS_CDP_URL")


class EnvClearedCase(unittest.TestCase):
    """Base class: run every check with SCRAPELESS_* env vars removed."""

    def setUp(self):
        self._saved = {}
        for key in SCRAPELESS_VARS:
            if key in os.environ:
                self._saved[key] = os.environ.pop(key)

    def tearDown(self):
        for key, value in self._saved.items():
            os.environ[key] = value


class TestCheckBaseline(EnvClearedCase):
    def test_missing_token_and_cdp_reports_error_not_ok(self):
        r = doctor.check(probe_browser=False)
        self.assertIsNone(r["endpoint"])
        self.assertTrue(r.get("error"))
        self.assertFalse(r["ok"])
        self.assertEqual(r["python"], sys.version.split()[0])
        self.assertEqual(r["sbi"], sbi.__version__)
        self.assertIsNone(r["cdp_env"])
        self.assertFalse(r["token_env"])

    def test_optional_deps_reported_not_raised(self):
        r = doctor.check(probe_browser=False)
        self.assertIsInstance(r["mcp"], bool)
        self.assertTrue(r["node"] is None or isinstance(r["node"], str))
        self.assertTrue(r["websockets"] is None
                        or isinstance(r["websockets"], str))

    def test_probe_browser_false_leaves_browser_key_absent(self):
        r = doctor.check(probe_browser=False)
        self.assertNotIn("browser", r)


class TestHttpProbe(EnvClearedCase):
    def test_unreachable_http_endpoint_fails_probe_and_overall(self):
        r = doctor.check(cdp="http://127.0.0.1:1", probe_browser=True)
        self.assertFalse(r["browser"]["ok"])
        self.assertTrue(r["browser"].get("error"))
        self.assertFalse(r["ok"])
        self.assertTrue(r.get("error"))  # resolution also failed: endpoint()
        # itself fetches /json/version for http inputs

    def test_probe_failure_shape_has_no_browser_field(self):
        r = doctor.check(cdp="http://127.0.0.1:1", probe_browser=True)
        self.assertNotIn("browser", r["browser"])


class TestWssSkip(EnvClearedCase):
    def test_wss_endpoint_resolves_without_probe(self):
        r = doctor.check(token="dummy-token", probe_browser=True)
        self.assertTrue(r["endpoint"].startswith("wss://"))
        self.assertEqual(r["browser"],
                         {"ok": None, "note": "wss endpoint not probed"})
        self.assertTrue(r["ok"])
        self.assertNotIn("error", r)


class TestEnvReporting(EnvClearedCase):
    def test_env_vars_reported_and_token_picked_up(self):
        with mock.patch.dict(os.environ, {"SCRAPELESS_API_TOKEN": "tok",
                                          "SCRAPELESS_CDP_URL":
                                              "wss://example.test/cdp"}):
            r = doctor.check(probe_browser=False)
        self.assertTrue(r["token_env"])
        self.assertEqual(r["cdp_env"], "wss://example.test/cdp")
        self.assertTrue(r["endpoint"].startswith("wss://"))
        self.assertTrue(r["ok"])

    def test_garbage_cdp_does_not_raise(self):
        r = doctor.check(cdp="not-a-url", probe_browser=True)
        self.assertEqual(r["endpoint"], "not-a-url")  # unknown scheme: passed
        self.assertTrue(r["ok"])                      # through by endpoint()
        self.assertNotIn("browser", r)                # neither http nor wss


class TestPrintReport(unittest.TestCase):
    def test_returns_string_with_plain_markers(self):
        text = doctor.print_report(doctor.check(probe_browser=False))
        self.assertIsInstance(text, str)
        for marker in ("OK", "FAIL", "--"):
            self.assertIn(marker, text)
        self.assertNotIn("\u2713", text)  # no unicode check marks
        self.assertNotIn("\u2717", text)

    def test_wss_report_is_green_and_redacts_token(self):
        text = doctor.print_report(doctor.check(token="dummy-token",
                                                probe_browser=True))
        self.assertIn("OK", text)
        self.assertIn("wss endpoint not probed", text)
        self.assertNotIn("FAIL", text)
        self.assertNotIn("dummy-token", text)

    def test_empty_report_does_not_raise(self):
        text = doctor.print_report({})
        self.assertIsInstance(text, str)
        self.assertIn("FAIL", text)  # nothing resolved -> overall FAIL


if __name__ == "__main__":
    unittest.main()


class TestDoctorCLI(unittest.TestCase):
    def test_cli_doctor_exits_zero_without_token(self):
        import subprocess
        import sys
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = dict(os.environ)
        env.pop("SCRAPELESS_API_TOKEN", None)
        env.pop("SCRAPELESS_CDP_URL", None)
        proc = subprocess.run([sys.executable, "-m", "sbi", "--doctor"], cwd=root,
                              env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr[-300:])
        self.assertIn("overall", proc.stdout)
        self.assertIn("FAIL", proc.stdout)   # no endpoint configured -> browser FAIL
