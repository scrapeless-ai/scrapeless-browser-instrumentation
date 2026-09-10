"""Interceptor observation: Fetch.requestPaused carries the real request
headers and body, so a passthrough rule must double as an observer. These
cover the capture path that recovers request-side values a Network-domain
grep can't see (the gateway-strips-headers case), driven through a stub CDP
with no websocket.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbi.page.intercept import Interceptor, MAX_OBSERVED, MAX_BODY


class StubCDP:
    def __init__(self, post_data=None):
        self.handlers = {}
        self.sent = []
        self.post_data = post_data          # answer for Fetch.getRequestPostData

    def on(self, method, handler):
        self.handlers[method] = handler

    def send(self, method, params=None, session_id=None, timeout=None):
        self.sent.append((method, params, session_id))
        if method == "Fetch.getRequestPostData":
            if self.post_data is None:
                raise RuntimeError("no post data")
            return {"postData": self.post_data}
        return {}

    def sent_methods(self):
        return [m for m, _p, _s in self.sent]


def paused(url="https://target/api/sign", method="POST", headers=None,
           post_data=None, has_post=False, rid="r1", response=False):
    req = {"url": url, "method": method, "headers": headers or {}}
    if post_data is not None:
        req["postData"] = post_data
    if has_post:
        req["hasPostData"] = True
    p = {"requestId": rid, "request": req, "resourceType": "XHR"}
    if response:
        p["responseStatusCode"] = 200
    return p


class TestInterceptorObservation(unittest.TestCase):
    def test_records_headers_and_body_and_still_forwards(self):
        cdp = StubCDP()
        ic = Interceptor(cdp)
        ic.add("s-1", "*", passthrough=True)
        cdp.sent.clear()
        ic._paused(paused(headers={"x-dq7hy5l1-a": "sig", "content-type": "text/plain"},
                          post_data="X-DQ7Hy5L1-f1=abc&a0=def"), session_id="s-1")
        # forwarded untouched
        self.assertEqual(cdp.sent_methods(), ["Fetch.continueRequest"])
        rec = ic.drain_observed()
        self.assertEqual(len(rec), 1)
        rec = rec[0]
        self.assertEqual(rec["session"], "s-1")
        self.assertEqual(rec["stage"], "request")
        self.assertEqual(rec["method"], "POST")
        self.assertEqual(rec["headers"]["x-dq7hy5l1-a"], "sig")
        self.assertIn("a0=def", rec["post_data"])

    def test_records_even_with_no_matching_rule(self):
        # a pause can fire for an armed pattern with no specific rule; still observe
        cdp = StubCDP()
        ic = Interceptor(cdp)
        ic._paused(paused(post_data="k=v"), session_id="s-9")
        self.assertEqual(cdp.sent_methods(), ["Fetch.continueRequest"])
        self.assertEqual(len(ic.observed), 1)

    def test_recovers_body_when_only_flagged(self):
        cdp = StubCDP(post_data="X-DQ7Hy5L1-f2=recovered")
        ic = Interceptor(cdp)
        ic._paused(paused(post_data=None, has_post=True), session_id="s-1")
        self.assertIn("Fetch.getRequestPostData", cdp.sent_methods())
        self.assertEqual(ic.drain_observed()[0]["post_data"], "X-DQ7Hy5L1-f2=recovered")

    def test_recovery_failure_is_swallowed(self):
        cdp = StubCDP(post_data=None)             # getRequestPostData raises
        ic = Interceptor(cdp)
        ic._paused(paused(post_data=None, has_post=True), session_id="s-1")
        rec = ic.drain_observed()
        self.assertEqual(len(rec), 1)
        self.assertIsNone(rec[0]["post_data"])    # no body, but request still observed

    def test_drain_clears(self):
        ic = Interceptor(StubCDP())
        ic._paused(paused(post_data="a=1"), session_id="s-1")
        self.assertEqual(len(ic.drain_observed()), 1)
        self.assertEqual(ic.drain_observed(), [])

    def test_grep_finds_body_and_header_nondestructively(self):
        ic = Interceptor(StubCDP())
        ic._paused(paused(headers={"x-dq7hy5l1-z": "tok_9f27"},
                          post_data="a0=tok_zoe"), session_id="s-1")
        self.assertEqual(len(ic.grep_observed("tok_zoe")), 1)      # body
        self.assertEqual(len(ic.grep_observed("tok_9f27")), 1)     # header value
        self.assertEqual(ic.grep_observed("nope"), [])
        self.assertEqual(len(ic.grep_observed(r"tok_\w+", regex=True)), 1)
        self.assertEqual(len(ic.observed), 1)                      # grep did not drain

    def test_body_truncated_at_cap(self):
        ic = Interceptor(StubCDP())
        big = "x" * (MAX_BODY + 50)
        ic._paused(paused(post_data=big), session_id="s-1")
        body = ic.drain_observed()[0]["post_data"]
        self.assertTrue(body.endswith("truncated]"))
        self.assertLessEqual(len(body), MAX_BODY + 40)

    def test_tape_capped(self):
        ic = Interceptor(StubCDP())
        for i in range(MAX_OBSERVED + 120):
            ic._paused(paused(post_data=f"n={i}"), session_id="s-1")
        recs = ic.observed
        self.assertEqual(len(recs), MAX_OBSERVED)
        self.assertEqual(recs[-1]["post_data"], f"n={MAX_OBSERVED + 119}")  # newest kept

    def test_record_failure_never_breaks_interception(self):
        # malformed headers make _record raise internally; request must still forward
        cdp = StubCDP()
        ic = Interceptor(cdp)
        bad = paused()
        bad["request"]["headers"] = ["not-a-mapping"]     # dict([...]) raises
        ic._paused(bad, session_id="s-1")
        self.assertEqual(cdp.sent_methods(), ["Fetch.continueRequest"])
        self.assertEqual(ic.observed, [])                  # nothing recorded, no crash


if __name__ == "__main__":
    unittest.main(verbosity=2)
