"""Capture tapes must stay bounded. Long/chatty sessions would otherwise grow
the network and console records forever — and network bodies (up to 256KB
each) and the requestId->meta map are never freed by drain(), so those need
their own eviction. Driven through stub CDP objects, no websocket.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbi.page.network import Network
from sbi.page.console import Console, MAX_RECORDS as CONSOLE_MAX


class StubCDP:
    def on(self, method, handler):
        pass

    def send(self, method, params=None, session_id=None, timeout=None):
        if method == "Network.getResponseBody":
            return {"body": "body-" + str((params or {}).get("requestId")),
                    "base64Encoded": False}
        return {}


class StubEngine:
    def __init__(self):
        self.cdp = StubCDP()


class NetworkCaps(unittest.TestCase):
    def test_records_capped_newest_kept(self):
        net = Network(StubEngine())
        for i in range(Network.MAX_RECORDS + 300):
            net._add({"kind": "x", "n": i})
        self.assertEqual(len(net.records), Network.MAX_RECORDS)
        self.assertEqual(net.records[-1]["n"], Network.MAX_RECORDS + 299)
        self.assertEqual(net.records[0]["n"], 300)             # oldest evicted

    def test_bodies_capped_and_freed(self):
        net = Network(StubEngine())
        for i in range(Network.MAX_BODIES + 120):
            net._finished({"requestId": f"r{i}"}, session_id="s")
        self.assertEqual(len(net.bodies), Network.MAX_BODIES)
        self.assertIn(f"r{Network.MAX_BODIES + 119}", net.bodies)   # newest kept
        self.assertNotIn("r0", net.bodies)                          # oldest evicted

    def test_meta_capped(self):
        net = Network(StubEngine())
        for i in range(Network.MAX_META + 120):
            net._req({"requestId": f"r{i}",
                      "request": {"url": f"u{i}", "method": "GET"},
                      "type": "XHR"}, session_id="s")
        self.assertEqual(len(net.meta), Network.MAX_META)
        self.assertLessEqual(len(net.records), Network.MAX_RECORDS)


class ConsoleCaps(unittest.TestCase):
    def test_records_capped_newest_kept(self):
        c = Console(StubCDP())
        for i in range(CONSOLE_MAX + 300):
            c._add({"text": str(i)})
        self.assertEqual(len(c.records), CONSOLE_MAX)
        self.assertEqual(c.records[-1]["text"], str(CONSOLE_MAX + 299))
        self.assertEqual(c.records[0]["text"], str(300))


if __name__ == "__main__":
    unittest.main(verbosity=2)
