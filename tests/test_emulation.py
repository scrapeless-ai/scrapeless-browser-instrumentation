"""Offline tests for sbi.emulation overrides — exact CDP method + payload."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbi.page.emulation import (clear_device, set_device, set_locale,
                           set_script_execution, set_timezone,
                           set_user_agent)


class StubCDP:
    """Records send() calls; returns {} like a quiet CDP target."""

    def __init__(self):
        self.calls = []

    def send(self, method, params=None, session_id=None, timeout=None):
        self.calls.append((method, params, session_id))
        return {}


SID = "sess-1"


class TestEmulation(unittest.TestCase):
    def setUp(self):
        self.cdp = StubCDP()

    def last(self):
        return self.cdp.calls[-1]

    def test_set_user_agent_string_only(self):
        set_user_agent(self.cdp, SID, "Mozilla/5.0 Custom")
        self.assertEqual(self.last(), (
            "Network.setUserAgentOverride",
            {"userAgent": "Mozilla/5.0 Custom"},
            SID))

    def test_set_user_agent_with_metadata(self):
        meta = {"brands": [{"brand": "Chromium", "version": "131"}],
                "platform": "Windows"}
        set_user_agent(self.cdp, SID, "Mozilla/5.0 Custom", metadata=meta)
        method, params, _ = self.last()
        self.assertEqual(method, "Network.setUserAgentOverride")
        self.assertEqual(params, {"userAgent": "Mozilla/5.0 Custom",
                                  "userAgentMetadata": meta})

    def test_set_locale(self):
        set_locale(self.cdp, SID, "de-DE")
        self.assertEqual(self.last(),
                         ("Emulation.setLocaleOverride", {"locale": "de-DE"}, SID))

    def test_set_timezone(self):
        set_timezone(self.cdp, SID, "Europe/Berlin")
        self.assertEqual(self.last(), (
            "Emulation.setTimezoneOverride",
            {"timezoneId": "Europe/Berlin"},
            SID))

    def test_set_device_defaults(self):
        set_device(self.cdp, SID, 390, 844)
        self.assertEqual(self.last(), (
            "Emulation.setDeviceMetricsOverride",
            {"width": 390, "height": 844,
             "deviceScaleFactor": 1.0, "mobile": False},
            SID))

    def test_set_device_mobile_scale(self):
        set_device(self.cdp, SID, 390, 844, mobile=True, scale=3)
        method, params, _ = self.last()
        self.assertEqual(method, "Emulation.setDeviceMetricsOverride")
        self.assertEqual(params, {"width": 390, "height": 844,
                                  "deviceScaleFactor": 3.0, "mobile": True})
        self.assertIsInstance(params["deviceScaleFactor"], float)
        self.assertIsInstance(params["mobile"], bool)

    def test_clear_device(self):
        clear_device(self.cdp, SID)
        self.assertEqual(self.last(),
                         ("Emulation.clearDeviceMetricsOverride", None, SID))

    def test_script_execution_enabled_sends_false(self):
        # Inverted on the wire: enabled=True -> setScriptExecutionDisabled
        # value=False. Assert the inversion explicitly.
        set_script_execution(self.cdp, SID, True)
        self.assertEqual(self.last(), (
            "Emulation.setScriptExecutionDisabled", {"value": False}, SID))

    def test_script_execution_disabled_sends_true(self):
        set_script_execution(self.cdp, SID, False)
        self.assertEqual(self.last(), (
            "Emulation.setScriptExecutionDisabled", {"value": True}, SID))

    def test_session_id_always_forwarded(self):
        set_locale(self.cdp, "other-sid", "ja-JP")
        set_script_execution(self.cdp, "other-sid", False)
        self.assertTrue(all(call[2] == "other-sid" for call in self.cdp.calls))


if __name__ == "__main__":
    unittest.main(verbosity=2)
