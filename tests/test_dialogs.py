"""Dialogs suite: a stub CDP records handler registrations and sends — no
websocket needed. Covers record-only vs auto-accept/dismiss, policy
validation, drain/pending accounting, cap behaviour on alert storms, and that
a failing send never escapes the handler."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbi.page.dialogs import Dialogs, MAX_RECORDS


class StubCDP:
    def __init__(self, fail_send=False):
        self.handlers = {}
        self.sent = []
        self.fail_send = fail_send

    def on(self, method, handler):
        self.handlers[method] = handler

    def send(self, method, params=None, session_id=None):
        if self.fail_send:
            raise ConnectionError("socket gone")
        self.sent.append((method, params, session_id))
        return {}


DIALOG = {"url": "https://hostile/x", "message": "gotcha", "type": "alert"}


def fire(dialogs, params=None, session_id="s-1"):
    dialogs._opening(params or DIALOG, session_id)


class TestDialogs(unittest.TestCase):
    def test_record_only_never_sends(self):
        cdp = StubCDP()
        d = Dialogs(cdp)
        fire(d)
        self.assertEqual(cdp.sent, [])
        self.assertEqual(d.pending(), 1)
        rec = d.drain()[0]
        self.assertEqual(rec["type"], "alert")
        self.assertEqual(rec["message"], "gotcha")
        self.assertEqual(rec["url"], "https://hostile/x")
        self.assertEqual(rec["session"], "s-1")
        self.assertIsNone(rec["action"])
        self.assertEqual(d.pending(), 0)

    def test_auto_accept_answers_with_prompt_text(self):
        cdp = StubCDP()
        d = Dialogs(cdp, auto="accept")
        fire(d, {"url": "u", "message": "?", "type": "prompt",
                 "defaultPrompt": "yes"}, session_id="s-7")
        self.assertEqual(cdp.sent, [("Page.handleJavaScriptDialog",
                                     {"accept": True, "promptText": "yes"}, "s-7")])

    def test_auto_dismiss_answers_false_and_defaults_prompt(self):
        cdp = StubCDP()
        d = Dialogs(cdp, auto="dismiss")
        fire(d)
        self.assertEqual(cdp.sent, [("Page.handleJavaScriptDialog",
                                     {"accept": False, "promptText": ""}, "s-1")])

    def test_set_policy_validates_and_takes_effect(self):
        d = Dialogs(StubCDP())
        with self.assertRaises(ValueError):
            d.set_policy("ok")
        with self.assertRaises(ValueError):
            d.set_policy(42)
        fire(d)
        d.set_policy("accept")
        fire(d)
        actions = [r["action"] for r in d.drain()]
        self.assertEqual(actions, [None, "accept"])

    def test_drain_clears_and_pending_counts(self):
        d = Dialogs(StubCDP(), auto="accept")
        fire(d)
        fire(d)
        self.assertEqual(d.pending(), 2)
        out = d.drain()
        self.assertEqual(len(out), 2)
        self.assertEqual(d.pending(), 0)
        self.assertEqual(d.drain(), [])

    def test_burst_capped_at_max_records(self):
        d = Dialogs(StubCDP())
        for i in range(600):
            fire(d, {"url": "u", "message": f"m{i}", "type": "alert"})
        recs = d.drain()
        self.assertEqual(len(recs), MAX_RECORDS)
        self.assertEqual(recs[0]["message"], "m100")   # oldest kept, newest intact
        self.assertEqual(recs[-1]["message"], "m599")

    def test_send_failure_never_raises_from_handler(self):
        d = Dialogs(StubCDP(fail_send=True), auto="accept")
        fire(d)                        # must not raise
        self.assertEqual(d.pending(), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
