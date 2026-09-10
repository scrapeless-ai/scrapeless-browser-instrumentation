"""CDP transport: speak the Chrome DevTools Protocol over a WebSocket.

The Scrapeless Scraping Browser exposes plain CDP on

    wss://browser.scrapeless.com/api/v2/browser?token=...&sessionTTL=300&proxyCountry=ANY

so everything here is protocol-level: no browser is launched, no debugging
port is ever opened, and the page has nothing local to discover. Any other CDP
websocket (including local Chrome via its /json/version webSocketDebuggerUrl)
works as well.

Threading model: a background thread runs the asyncio receive loop; events are
dispatched in order on a second dedicated thread so an event handler may issue
blocking CDP calls (the usual hook pattern: read the frame, then resume)
without deadlocking the reader. Public API is synchronous.
"""

import asyncio
import itertools
import json
import queue
import threading
import time
from concurrent.futures import TimeoutError as _FutureTimeout

import websockets

_DEFAULT_TIMEOUT = 30.0


class CDPError(Exception):
    """A CDP command returned an error response."""

    def __init__(self, code, message, data=None):
        super().__init__(f"CDP error {code}: {message}" + (f" ({data})" if data else ""))
        self.code = code
        self.message = message
        self.data = data


class CDP:
    """Synchronous CDP client over one WebSocket connection."""

    def __init__(self, ws_url, max_size=2**27):
        self.ws_url = ws_url
        self._max_size = max_size
        self._pending = {}
        self._handlers = {}
        self._ids = itertools.count(1)
        self._loop = None
        self._ws = None
        self._thread = None
        self._pump = None          # thread that runs event handlers, in order
        self._events = queue.Queue()
        self._connected = threading.Event()
        self._connect_error = None
        self._closed = threading.Event()
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------

    def connect(self, timeout=30.0):
        self._thread = threading.Thread(target=self._run_loop, name="sbi-cdp", daemon=True)
        self._thread.start()
        if not self._connected.wait(timeout):
            err = self._connect_error or "timed out"
            raise ConnectionError(f"CDP websocket connect failed: {err}")
        self._pump = threading.Thread(target=self._pump_events, name="sbi-events", daemon=True)
        self._pump.start()
        return self

    def close(self):
        # Scheduling onto a loop that has already exited leaves the close()
        # coroutine un-awaited (and can block waking a dead loop), so only ask
        # for a graceful close while the reader is actually running.
        if self._closed.is_set():
            return
        if self._loop is not None and self._ws is not None and self._loop.is_running():
            try:
                asyncio.run_coroutine_threadsafe(self._ws.close(), self._loop)
            except RuntimeError:               # loop stopped between check and call
                pass
        self._closed.wait(10)

    # -- API ---------------------------------------------------------------

    def on(self, method, handler):
        """handler(params: dict, session_id: str|None) — may block."""
        self._handlers[method] = handler

    def off(self, method):
        self._handlers.pop(method, None)

    def flush_events(self, timeout=30):
        """Block until every event already received from the wire has been
        dispatched. The reader enqueues events before resolving the response
        that follows them, so after send() returns, flush_events() guarantees
        all preceding events (e.g. heap snapshot chunks) were handled."""
        end = time.time() + timeout
        while self._events.unfinished_tasks and time.time() < end:
            time.sleep(0.01)

    def send(self, method, params=None, session_id=None, timeout=None):
        """Send a command, return the `result` object. Raises CDPError on error."""
        # `_connected` is set in the reader's finally block too, so it means
        # "connect() finished", not "the transport is alive". `_closed` is the
        # one that says the loop has exited — without this check a command
        # scheduled onto a dead loop blocks for the full timeout (up to 300s
        # for a heap snapshot) instead of failing immediately.
        if self._closed.is_set() or not self._connected.is_set() or self._loop is None:
            raise ConnectionError("CDP not connected")
        msg = {"id": next(self._ids), "method": method, "params": params or {}}
        if session_id:
            msg["sessionId"] = session_id
        fut = asyncio.run_coroutine_threadsafe(self._send(msg), self._loop)
        timeout = _DEFAULT_TIMEOUT if timeout is None else timeout
        # slow commands (heap snapshots, big evals) legitimately take minutes
        if method == "HeapProfiler.takeHeapSnapshot":
            timeout = max(timeout, 300)
        reply = self._await_reply(fut, timeout)
        if "error" in reply:
            e = reply["error"]
            raise CDPError(e.get("code", -1), e.get("message", "unknown"), e.get("data"))
        return reply.get("result", {})

    # -- internals ---------------------------------------------------------

    def _await_reply(self, fut, timeout):
        """Wait for a reply, but give up as soon as the transport dies.

        A coroutine handed to run_coroutine_threadsafe before the loop stopped
        may never run at all, so it is never registered in `_pending` and never
        gets the "connection closed" exception the reader hands out. Waiting on
        it naively would block for the whole timeout; poll instead and bail the
        moment the reader thread reports the loop has exited.
        """
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                fut.cancel()
                raise TimeoutError(f"CDP command timed out after {timeout}s")
            try:
                return fut.result(min(remaining, 0.5))
            except _FutureTimeout:
                if self._closed.is_set():
                    fut.cancel()
                    raise ConnectionError("CDP connection closed while awaiting response") from None

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def main():
            try:
                async with websockets.connect(self.ws_url, max_size=self._max_size) as ws:
                    self._ws = ws
                    self._connected.set()
                    async for raw in ws:
                        self._dispatch_raw(raw)
            except Exception as e:                       # noqa: BLE001 - surfaced to connect()/send()
                self._connect_error = str(e)
            finally:
                self._connected.set()
                self._closed.set()

        try:
            self._loop.run_until_complete(main())
        finally:
            for fut in list(self._pending.values()):
                if not fut.done():
                    fut.set_exception(ConnectionError("CDP connection closed"))
                fut.exception()      # mark retrieved: the waiting caller may already be gone
            self._pending.clear()

    async def _send(self, msg):
        fut = self._loop.create_future()
        self._pending[msg["id"]] = fut
        try:
            await self._ws.send(json.dumps(msg))
            return await fut
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # the socket went away under us (a close or drop mid-send): resolve
            # to an error result instead of letting this task finish with an
            # exception no one retrieves — asyncio otherwise logs that as a
            # loud traceback on every normal close. send() turns it into a
            # CDPError for the caller, same as any other error reply.
            self._pending.pop(msg["id"], None)
            return {"error": {"code": -1, "message": f"CDP connection closed: {e}"}}

    def _dispatch_raw(self, raw):
        try:
            msg = json.loads(raw)
        except Exception:
            return
        if "id" in msg:
            with self._lock:
                fut = self._pending.pop(msg["id"], None)
            if fut and not fut.done():
                if "error" in msg:
                    fut.set_result({"error": msg["error"]})
                else:
                    fut.set_result(msg)
            return
        if "method" in msg:
            # never block the reader: handlers run on the pump thread, in order
            self._events.put((msg["method"], msg.get("params") or {}, msg.get("sessionId")))

    def _pump_events(self):
        while not self._closed.is_set() or not self._events.empty():
            try:
                method, params, session_id = self._events.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                handler = self._handlers.get(method)
                if handler:
                    try:
                        handler(params, session_id)
                    except Exception as e:               # noqa: BLE001 - hooks must not kill the pump
                        print(f"[sbi] handler error for {method}: {e!r}")
            finally:
                self._events.task_done()
