"""Transport regression tests: a dead connection must fail fast, not hang.

`_connected` is set by the reader's finally block as well as on success, so it
only means "connect() finished". If `send()` trusts it after the loop has
exited, the command is scheduled onto a stopped loop, never runs, and the
caller blocks for the entire command timeout — 300s for a heap snapshot. That
deadlock reproduced as a 40s test timeout on CI (py3.12 / Windows) before the
`_closed` guard in `CDP.send` and the bail-out in `CDP._await_reply`.
"""

import asyncio
import json
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from websockets.asyncio.server import serve

from sbi.core.cdp import CDP


class DroppingServer:
    """Answers commands until `drop` is set, then closes the connection."""

    def __init__(self):
        self.port = None
        self.drop = False
        self._ready = threading.Event()

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()
        if not self._ready.wait(10):
            raise RuntimeError("fake CDP server never bound a port")

    def _run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def handler(ws):
            async for raw in ws:
                if self.drop:
                    await ws.close()
                    return
                msg = json.loads(raw)
                await ws.send(json.dumps({"id": msg["id"], "result": {}}))

        async def main():
            async with serve(handler, "127.0.0.1", 0) as server:
                self.port = server.sockets[0].getsockname()[1]
                self._ready.set()
                await asyncio.Future()

        loop.run_until_complete(main())


class DeadTransportFailsFast(unittest.TestCase):
    def setUp(self):
        self.server = DroppingServer()
        self.server.start()
        self.cdp = CDP(f"ws://127.0.0.1:{self.server.port}").connect()

    def tearDown(self):
        # close the transport so in-flight _send tasks are not left pending
        # when the loop is torn down ("Task was destroyed but it is pending!")
        try:
            self.cdp.close()
        except Exception:                      # noqa: BLE001 - already gone is fine
            pass

    def _kill_connection(self):
        self.server.drop = True
        try:
            self.cdp.send("Test.provokeClose", timeout=5)
        except Exception:                      # noqa: BLE001 - the close is the point
            pass
        deadline = time.time() + 10
        while not self.cdp._closed.is_set() and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(self.cdp._closed.is_set(), "reader thread never reported closure")

    def test_send_on_live_connection_still_works(self):
        self.assertEqual(self.cdp.send("Test.ping"), {})

    def test_heap_snapshot_on_dead_loop_raises_instead_of_hanging(self):
        # takeHeapSnapshot forces the timeout to >= 300s; before the fix this
        # blocked for all of it, tripping the suite's 40s watchdog.
        self._kill_connection()
        started = time.time()
        with self.assertRaises(ConnectionError):
            self.cdp.send("HeapProfiler.takeHeapSnapshot")
        self.assertLess(time.time() - started, 5,
                        "send() blocked on a dead loop instead of failing fast")

    def test_ordinary_send_on_dead_loop_raises_instead_of_hanging(self):
        self._kill_connection()
        started = time.time()
        with self.assertRaises(ConnectionError):
            self.cdp.send("Runtime.evaluate", {"expression": "1"})
        self.assertLess(time.time() - started, 5,
                        "send() blocked on a dead loop instead of failing fast")


if __name__ == "__main__":
    unittest.main()
