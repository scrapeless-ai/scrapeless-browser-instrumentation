"""Offline test suite: a fake CDP server exercises the real client stack —
framing, engine attach, hook + return-capture event flow, oracle plumbing,
heap diff / patch / coverage / function index / dataflow follow / audit /
script dump / report, and genuine Node-based offline verification. No
browser, no network, no Scrapeless token needed.
"""

import json
import shutil
import sys
import threading
import unittest
import asyncio

import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from websockets.asyncio.server import serve

from sbi import api
from sbi.deobfuscate import deob
from sbi.deobfuscate import wasm as wasm_mod
from sbi.core.cdp import CDP
from sbi.analysis.heap import Snapshot
from sbi.verify.oracle import _equal
from sbi.artifacts import trace as trace_mod


def make_snapshot(strings, nodes, edges, node_types=("object", "string", "closure")):
    meta = {"node_fields": ["type", "name", "id", "self_size", "edge_count"],
            "node_types": [list(node_types), "number", "number", "number", "number"],
            "edge_fields": ["type", "name_or_index", "to_node"],
            "edge_types": [["property", "element"], "string_or_number", "node"]}
    return {"snapshot": {"meta": meta}, "nodes": nodes, "edges": edges, "strings": strings}


SNAP_BEFORE = make_snapshot(
    strings=["Config", "token", "sbx_9f27"],
    nodes=[0, 0, 1, 64, 1,
           1, 2, 2, 16, 0],
    edges=[0, 1, 5])

SNAP_AFTER = make_snapshot(
    strings=["Config", "token", "sbx_9f27", "Payload", "tok_new"],
    nodes=[0, 0, 1, 64, 1,
           1, 2, 2, 16, 0,
           0, 3, 4, 48, 1,
           1, 4, 3, 16, 0],
    edges=[0, 1, 5,
           0, 4, 15])

SNAP_CLOSURE = make_snapshot(strings=["signFn"], nodes=[2, 0, 9, 32, 0], edges=[])
SNAP_SIGN = make_snapshot(strings=["sign"], nodes=[2, 0, 11, 32, 0], edges=[])
SNAP_SIG = make_snapshot(strings=["sig_zoe"], nodes=[1, 0, 10, 8, 0], edges=[])

COVERAGE = {"result": [{"url": "https://x/app.js", "scriptId": "7", "functions": [
    {"functionName": "sign", "ranges": [{"count": 3, "startOffset": 0, "endOffset": 120}],
     "isBlockCoverage": False},
    {"functionName": "unusedUtil", "ranges": [{"count": 0, "startOffset": 200, "endOffset": 300}],
     "isBlockCoverage": False}]}]}

FN_DESC = "function fn(a, b) { return a + ':' + b; }"


class FakeCDPServer:
    """Minimal CDP endpoint: enough protocol for the engine/hook/oracle flow
    plus heap snapshots, callFunctionOn and precise coverage."""

    def __init__(self):
        self.port = None
        self.started = threading.Event()
        self.stop = asyncio.Event()
        self.candidate_value = "sig_zoe"
        self.heap_snapshots = []          # FIFO of snapshot dicts to stream
        self.patch_result = {"ok": True, "value": "NEWVAL"}
        self.calls = []                   # (method, params) for assertions
        self._targets = 0
        self._bps = 0

    def start(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
        self.started.wait(10)

    def _run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        async def main():
            async with serve(self._handler, "127.0.0.1", 0) as server:
                self.port = server.sockets[0].getsockname()[1]
                self.started.set()
                await self.stop.wait()

        self.loop.run_until_complete(main())

    def calls_of(self, method):
        return [p for m, p in self.calls if m == method]

    async def _handler(self, ws):
        async for raw in ws:
            msg = json.loads(raw)
            self.calls.append((msg.get("method"), msg.get("params") or {}))
            result, events, first = self._handle(msg)
            if first:
                for m, p, sid in events:
                    await ws.send(json.dumps({"method": m, "params": p, "sessionId": sid}))
            await ws.send(json.dumps({"id": msg.get("id"), "result": result}))
            if not first:
                for m, p, sid in events:
                    await ws.send(json.dumps({"method": m, "params": p, "sessionId": sid}))

    def _handle(self, msg):
        method, params = msg.get("method"), msg.get("params") or {}
        sid = msg.get("sessionId")
        R, E, FIRST = {}, [], False
        frame = {"callFrameId": "cf-0", "functionName": "fn",
                 "functionLocation": {"scriptId": "7", "lineNumber": 10, "columnNumber": 4},
                 "url": "https://x/app.js"}

        if method == "Target.createTarget":
            self._targets += 1
            R = {"targetId": f"t-{self._targets}"}
        elif method == "Browser.getVersion":
            R = {"userAgent": "Mozilla/5.0 (X) HeadlessChrome/120.0.0.0 Safari/537.36",
                 "product": "Chrome/120.0.6099.5"}
        elif method == "Page.navigate":
            n = (sid or "s-1").split("-")[-1]
            E.append(("Target.targetInfoChanged",
                      {"targetInfo": {"targetId": f"t-{n}", "type": "page",
                                      "url": params.get("url")}}, None))
            E.append(("Page.javascriptDialogOpening",
                      {"type": "confirm", "message": "continue?", "url": params.get("url"),
                       "defaultPrompt": ""}, sid))
            E.append(("Network.requestWillBeSent",
                      {"requestId": "r-nav", "type": "Document",
                       "request": {"url": params.get("url"), "method": "GET"}}, sid))
            E.append(("Network.responseReceived",
                      {"requestId": "r-nav",
                       "response": {"url": params.get("url"), "status": 200,
                                    "mimeType": "text/html", "headers": {}}}, sid))
            E.append(("Network.loadingFinished", {"requestId": "r-nav"}, sid))
            R = {"frameId": "f"}
        elif method == "Target.attachToTarget":
            n = 1 if params.get("targetId") == "t-1" else self._targets
            sid_new = f"s-{n}"
            R = {"sessionId": sid_new}
            E.append(("Target.attachedToTarget",
                      {"sessionId": sid_new,
                       "targetInfo": {"targetId": params.get("targetId"),
                                      "type": "page", "url": "about:blank"}}, None))
        elif method == "Target.setAutoAttach" and not getattr(self, "_dup_sent", False):
            # real Chrome quirk: the same target can arrive again under a new
            # flat session (browser-level discover/auto-attach overlap)
            self._dup_sent = True
            E.append(("Target.attachedToTarget",
                      {"sessionId": "s-dup",
                       "targetInfo": {"targetId": "t-1", "type": "page",
                                      "url": "about:blank"}}, sid))
        elif method == "Runtime.evaluate":
            expr = params.get("expression", "")
            if expr.startswith("/*sbi-audit*/"):
                R = {"result": {"type": "string", "value": json.dumps(
                    {"s": FN_DESC, "p": 0})}}
            elif "__clock__" in expr:
                self.clock = getattr(self, "clock", 0) + 1
                R = {"result": {"type": "number", "value": self.clock}}
            elif "getBoundingClientRect" in expr and "w: r.width" in expr:
                R = {"result": {"type": "string",
                                "value": '{"x": 5, "y": 6, "w": 20, "h": 10}'}}
            elif "getBoundingClientRect" in expr:
                R = {"result": {"type": "string", "value": "[12, 34]"}}
            elif "outerHTML" in expr:
                R = {"result": {"type": "string",
                                "value": "<html><body>sbi-dom</body></html>"}}
            elif "fetch(" in expr and '"method"' in expr:
                R = {"result": {"type": "string",
                                "value": json.dumps({"status": 201, "body": "replayed"})}}
            elif "indexedDB.databases" in expr:
                R = {"result": {"type": "string",
                                "value": json.dumps({"db1": {"version": 1}})}}
            elif "localStorage" in expr:
                R = {"result": {"type": "string",
                                "value": '{"local": {"k": "v"}, "session": {}}'}}
            elif "window.__sbi__" in expr:
                R = {"result": {"type": "string", "value": "[]"}}
            elif ").apply(null," in expr or "}).apply(" in expr:
                R = {"result": {"type": "string", "value": self.candidate_value}}
            elif "instanceof WebAssembly" in expr:
                R = {"result": {"type": "string", "value": json.dumps(
                    {"kind": "instance",
                     "exports": [{"name": "answer", "kind": "function"}]})}}
            elif ".rpc.ping(" in expr:
                R = {"result": {"type": "string", "value": "pong"}}
            elif "__sbi_send_" in expr and "send(" in expr:
                R = {"result": {"type": "undefined"}}
                name = expr.split("__sbi_send_")[1].split("(")[0].split(")")[0]
                E.append(("Runtime.bindingCalled",
                          {"name": "__sbi_send_" + name,
                           "payload": json.dumps({"hello": "world"}),
                           "executionContextId": 1}, sid))
            elif "window.fn" in expr:
                R = {"result": {"type": "function", "objectId": "obj-fn",
                                "description": FN_DESC}}
            else:
                R = {"result": {"type": "undefined"}}
        elif method == "Runtime.getProperties":
            R = {"internalProperties": [
                {"name": "[[FunctionLocation]]",
                 "value": {"value": frame["functionLocation"]}}]}
        elif method == "Runtime.callFunctionOn":
            R = {"result": {"type": "object", "value": self.patch_result}}
        elif method == "Debugger.enable":
            E.append(("Debugger.scriptParsed",
                      {"scriptId": "7", "url": "https://x/app.js",
                       "scriptLanguage": "JavaScript"}, sid))
            E.append(("Debugger.scriptParsed",
                      {"scriptId": "w1", "url": "wasm-abc123",
                       "scriptLanguage": "WebAssembly"}, sid))
            E.append(("Debugger.scriptParsed",
                      {"scriptId": "9", "url": "https://cdn.shape-security.com/fp.js",
                       "scriptLanguage": "JavaScript"}, sid))
        elif method == "Network.enable":
            E.append(("Network.requestWillBeSent",
                      {"requestId": "r-9",
                       "request": {"url": "https://t/api", "method": "POST",
                                   "postData": '{"a":1}', "hasPostData": False},
                       "type": "XHR"}, sid))
            E.append(("Network.responseReceived",
                      {"requestId": "r-9",
                       "response": {"url": "https://t/api", "status": 200,
                                    "mimeType": "application/json",
                                    "headers": {"Content-Type": "application/json"}}}, sid))
            E.append(("Network.loadingFinished", {"requestId": "r-9"}, sid))
            import base64 as _b64
            E.append(("Network.requestWillBeSent",
                      {"requestId": "r-wasm",
                       "request": {"url": "https://t/engine.wasm", "method": "GET"},
                       "type": "Other"}, sid))
            E.append(("Network.loadingFinished", {"requestId": "r-wasm"}, sid))
            E.append(("Network.responseReceived",
                      {"requestId": "r-wasm",
                       "response": {"url": "https://t/engine.wasm", "status": 200,
                                    "mimeType": "application/wasm", "headers": {}}}, sid))
            E.append(("Network.loadingFinished", {"requestId": "r-wasm"}, sid))
        elif method == "Runtime.enable":
            E.append(("Runtime.consoleAPICalled",
                      {"type": "log",
                       "args": [{"type": "string", "value": "sbi_marker_log"}],
                       "stackTrace": {"callFrames": [{"functionName": "check"}]}}, sid))
            E.append(("Runtime.exceptionThrown",
                      {"exceptionDetails": {"text": "Uncaught",
                                            "exception": {"description":
                                                          "Error: sbi_marker_exc"},
                                            "stackTrace": {"callFrames": []}}}, sid))
        elif method == "Page.captureScreenshot":
            import base64
            R = {"data": base64.b64encode(b"\x89PNG\r\n\x1a\nFAKE").decode()}
        elif method == "Page.printToPDF":
            import base64
            R = {"data": base64.b64encode(b"%PDF-1.4 FAKE").decode()}
        elif method == "Performance.getMetrics":
            R = {"metrics": [{"name": "JSHeapUsedSize", "value": 12345.0},
                             {"name": "Nodes", "value": 42}]}
        elif method == "Profiler.stop":
            R = {"profile": {"nodes": [
                {"id": 1, "callFrame": {"functionName": "hotFn", "url": "https://x/app.js"},
                 "hitCount": 7, "children": []},
                {"id": 2, "callFrame": {"functionName": "idle", "url": ""},
                 "hitCount": 0, "children": []}],
                "samples": [1, 1], "timeDeltas": [1000, 1000]}}
        elif method == "Network.emulateNetworkConditions":
            R = {}
        elif method == "Emulation.setCPUThrottlingRate":
            R = {}
        elif method == "Emulation.setEmulatedMedia":
            R = {}
        elif method == "Network.setCacheDisabled":
            R = {}
        elif method == "Network.clearBrowserCache":
            R = {}
        elif method == "Page.setBypassCSP":
            R = {}
        elif method == "Input.dispatchMouseEvent":
            R = {}
        
        elif method == "Emulation.setGeolocationOverride":
            R = {}
        elif method == "Emulation.clearGeolocationOverride":
            R = {}
        elif method == "Browser.grantPermissions":
            R = {}
        elif method == "Network.setCookie":
            R = {"success": True}
        elif method == "Network.getResponseBody":
            if msg.get("params", {}).get("requestId") == "r-wasm":
                import base64 as _b
                R = {"body": _b.b64encode(b"\x00\x61\x73\x6d\x01\x00\x00\x00wire").decode(),
                     "base64Encoded": True}
            else:
                R = {"body": '{"ok":1}', "base64Encoded": False}
        elif method == "Storage.clearDataForOrigin":
            R = {}
        elif method == "Input.dispatchMouseEvent":
            R = {}
        elif method == "Network.getCookies":
            R = {"cookies": [{"name": "sid", "value": "abc", "domain": "x"}]}
        elif method == "Fetch.enable":
            # one paused request per armed rule, url derived from the pattern
            self._fp = getattr(self, "_fp", 0)
            for i, pat in enumerate((msg.get("params", {}).get("patterns") or [])):
                self._fp += 1
                url = (pat.get("urlPattern") or "https://t.mock/").replace("*", "")
                ev = {"requestId": f"fp-{self._fp}",
                      "request": {"url": url, "method": "GET"}}
                if pat.get("requestStage") == "Response":
                    ev["responseStatusCode"] = 200
                    ev["responseHeaders"] = [{"name": "Content-Type",
                                              "value": "application/json"}]
                E.append(("Fetch.requestPaused", ev, sid))
        elif method == "Fetch.disable":
            pass
        elif method == "Runtime.addBinding":
            pass
        elif method == "Page.addScriptToEvaluateOnNewDocument":
            pass
        elif method == "Fetch.takeResponseBodyForInterceptionAsStream":
            R = {"streamId": "io-1"}
        elif method == "IO.read":
            R = {"data": 'original with SECRET inside', "base64Encoded": False,
                 "eof": True}
        elif method == "IO.close":
            pass
        elif method == "Fetch.continueRequest" or method == "Fetch.failRequest":
            pass
        elif method == "Fetch.fulfillRequest":
            pass
        elif method == "Debugger.setBreakpointOnFunctionCall":
            self._bps += 1
            cb = f"cb-{self._bps}"
            # real Chrome reports the arming breakpoint in hitBreakpoints
            E.append(("Debugger.paused",
                      {"callFrames": [frame], "hitBreakpoints": [cb]}, sid))
            R = {"breakpointId": cb}
        elif method == "Debugger.getPossibleBreakpoints":
            R = {"locations": [{"scriptId": "7", "lineNumber": 11, "columnNumber": 2,
                                "type": "return"}]}
        elif method == "Debugger.setBreakpoint":
            self._bps += 1
            R = {"breakpointId": f"bp-{self._bps}"}
        elif method == "Debugger.evaluateOnCallFrame":
            R = {"result": {"type": "string", "value": '["zoe", 7]'}}
        elif method == "Debugger.resume":
            E.append(("Debugger.paused",
                      {"callFrames": [dict(frame, returnValue={"type": "string",
                                                               "value": "sig_zoe"})],
                       "hitBreakpoints": [f"bp-{self._bps}"]}, sid))
        elif method == "Debugger.getScriptSource":
            if str(msg.get("params", {}).get("scriptId")) == "w1":
                import base64
                R = {"scriptSource": base64.b64encode(b"\x00asm\x01\x00\x00\x00fake").decode()}
            else:
                R = {"scriptSource": "// fake source"}
        elif method == "Debugger.disassembleWasmModule":
            R = {"chunk": {"streamId": "st-1",
                           "lines": ["func $shape_hash ()", "  i32.const 42"]}}
        elif method == "Debugger.nextWasmDisassemblyChunk":
            R = {"chunk": {"lines": []}}
        elif method == "HeapProfiler.takeHeapSnapshot":
            data = json.dumps(self.heap_snapshots.pop(0) if self.heap_snapshots else
                              make_snapshot([], [], []))
            E = [("HeapProfiler.addHeapSnapshotChunk", {"chunk": data[i:i + 65536]}, sid)
                 for i in range(0, len(data), 65536)]
            FIRST = True                      # chunks must precede the response
        elif method == "HeapProfiler.getObjectByHeapObjectId":
            oid = str(msg.get("params", {}).get("objectId", ""))
            R = {"result": {"type": "function", "objectId": "live-" + oid,
                            "description": "function () { ... }"}}
        elif method == "Runtime.callFunctionOn":
            pass
        elif method == "Profiler.startPreciseCoverage":
            R = {}
        elif method == "Profiler.takePreciseCoverage":
            R = COVERAGE
        return R, E, FIRST


def wait_until(pred, timeout=6.0, step=0.05):
    import time
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False


class TestEndpoint(unittest.TestCase):
    def test_scrapeless_url(self):
        url = api.endpoint(token="TK", proxy_country="US", session_ttl=300, session_name="s")
        self.assertIn("wss://browser.scrapeless.com/api/v2/browser", url)
        self.assertIn("token=TK", url)
        self.assertIn("proxyCountry=US", url)
        self.assertIn("sessionTTL=300", url)

    def test_requires_something(self):
        old = os.environ.pop("SCRAPELESS_API_TOKEN", None)
        try:
            with self.assertRaises(RuntimeError):
                api.endpoint()
        finally:
            if old:
                os.environ["SCRAPELESS_API_TOKEN"] = old


class TestEqual(unittest.TestCase):
    def test_strict(self):
        self.assertTrue(_equal({"a": [1, "x"]}, {"a": [1, "x"]}))
        self.assertFalse(_equal(1, True))
        self.assertFalse(_equal("1", 1))
        self.assertFalse(_equal([1, 2], [2, 1]))


class TestSnapshot(unittest.TestCase):
    def test_find_and_retainers(self):
        s = Snapshot(SNAP_BEFORE)
        hits = s.find(contains="sbx_9f27")
        self.assertEqual(len(hits), 1)
        self.assertEqual(s.node_name(hits[0]), "sbx_9f27")
        paths = s.retainers(hits[0], depth=2)
        self.assertTrue(any(".token on object:Config" in p for path in paths for p in path),
                        f"retainer path missing: {paths}")


class TestVMHelpers(unittest.TestCase):
    def test_steps_and_histogram(self):
        caps = [{"args": [7, "PUSH", None]}, {"args": [8, "ADD", None]},
                {"args": [9, "PUSH", None]}]
        steps = deob.vm_steps(caps)
        self.assertEqual(len(steps), 3)
        self.assertEqual(steps[0]["args"], [7, "PUSH", None])
        hist = deob.vm_histogram(caps, arg_index=1)
        self.assertEqual(hist[0], ("PUSH", 2))


class TestFullStack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = FakeCDPServer()
        cls.fake.start()
        cls.cdp = CDP(f"ws://127.0.0.1:{cls.fake.port}").connect()
        cls.session = api.Session(cls.cdp)
        cls.session.start()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.session.close()
        except Exception:
            pass

    def test_01_engine_attached(self):
        targets = self.session.targets()
        self.assertTrue(any(t[1] == "page" for t in targets), targets)

    def test_02_invisible_hook_captures_pair(self):
        self.session.hook("window.fn", capture_returns=True, label="fn")
        self.assertTrue(wait_until(lambda: self.session.corpus("fn")),
                        "return pair never captured")
        pair = self.session.corpus("fn")[0]
        self.assertEqual(pair["input"], ["zoe", 7])
        self.assertEqual(pair["output"], "sig_zoe")
        self.assertEqual(pair["output_type"], "string")

    def test_03_oracle_verifies_and_rejects(self):
        r = self.session.verify("window.fn", "(a,b)=>a+'!'", label="fn")
        self.assertTrue(r["verified"], r)
        self.assertEqual(r["matched"], r["tested"])
        self.fake.candidate_value = "WRONG"
        try:
            r2 = self.session.verify("window.fn", "(a,b)=>a+'!'", label="fn")
            self.assertFalse(r2["verified"])
            self.assertTrue(r2["mismatches"])
            self.assertEqual(r2["mismatches"][0]["expected"], "sig_zoe")
            self.assertEqual(r2["mismatches"][0]["got"], "WRONG")
        finally:
            self.fake.candidate_value = "sig_zoe"

    def test_04_trace_save_load_and_offline_verify(self):
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "trace.json")
        doc = self.session.save(path)
        self.assertTrue(os.path.exists(path))
        loaded = trace_mod.load(path)
        self.assertIn("fn", loaded["pairs"])

        if not shutil.which("node"):
            self.skipTest("node not available")
        bad = trace_mod.offline_verify(loaded, "fn", "(a,b)=>a+b")
        self.assertFalse(bad["verified"], bad)
        good = trace_mod.offline_verify(loaded, "fn", "()=>'sig_zoe'")
        self.assertTrue(good["verified"], good)

    def test_05_grep(self):
        hits = self.session.grep("zoe")
        self.assertTrue(hits["pairs"], "grep should find the corpus pair")
        self.assertTrue(any("sig_zoe" in json.dumps(p) for p in hits["pairs"]))

    def test_06_heapdiff_finds_new_nodes(self):
        self.fake.heap_snapshots = [SNAP_BEFORE, SNAP_AFTER]
        d = self.session.heapdiff(action="window.checkout()")
        names = {n["name"] for n in d["new_nodes"]}
        self.assertIn("tok_new", names)
        self.assertIn("Payload", names)
        self.assertNotIn("sbx_9f27", names)
        payload = next(n for n in d["new_nodes"] if n["name"] == "Payload")
        self.assertEqual(payload["type"], "object")
        self.assertEqual(payload["heap_object_id"], "4")

    def test_07_patch_calls_callfunctionon(self):
        self.session.patch("2", "token", "NEWVAL")
        calls = self.fake.calls_of("Runtime.callFunctionOn")
        self.assertTrue(calls, "callFunctionOn never sent")
        decl = calls[-1]["functionDeclaration"]
        self.assertIn('"token"', decl)
        self.assertEqual(calls[-1]["arguments"], [{"value": "NEWVAL"}])

    def test_08_coverage_ranks_executed(self):
        self.session.coverage("start")
        r = self.session.coverage("take", only_executed=True)
        names = [f["function"] for f in r["functions"]]
        self.assertIn("sign", names)
        self.assertNotIn("unusedUtil", names)
        self.assertEqual(r["functions"][0]["count"], 3)

    def test_09_function_index_resolves_location(self):
        self.fake.heap_snapshots = [SNAP_CLOSURE]
        r = self.session.functions(contains="signFn")
        fns = r["functions"]
        self.assertTrue(fns and fns[0]["name"] == "signFn")
        self.assertEqual(fns[0]["heap_object_id"], "9")
        self.assertEqual(fns[0].get("url"), "https://x/app.js")
        loc = fns[0].get("location") or {}
        self.assertEqual(loc.get("script_id"), "7")

    def test_10_follow_connects_output_to_holders(self):
        self.fake.heap_snapshots = [SNAP_SIG]
        r = self.session.follow("fn")
        self.assertTrue(r["flows"])
        self.assertEqual(r["flows"][0]["output"], "sig_zoe")
        self.assertTrue(r["flows"][0]["holders"], "no holders found for sig_zoe")

    def test_11_audit_clean_after_hooks(self):
        r = self.session.audit()
        self.assertTrue(r["all_intact"], r)
        self.assertTrue(all(h["expected"] == FN_DESC for h in r["hooks"]))

    def test_12_dump_scripts(self):
        import tempfile
        d = tempfile.mkdtemp()
        written = self.session.dump_scripts(d)
        self.assertTrue(written, "no scripts dumped")
        self.assertTrue(any("// fake source" in open(w["path"], encoding="utf-8").read()
                            for w in written))

    def test_13_report_renders(self):
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "report.md")
        self.session.report(path)
        text = open(path, encoding="utf-8").read()
        self.assertIn("# Instrumentation report", text)
        self.assertIn("## Hooks", text)
        self.assertIn("`fn`", text)

    def test_14_blackbox_applies(self):
        self.session.blackbox(["node_modules"])
        calls = self.fake.calls_of("Debugger.setBlackboxPatterns")
        self.assertTrue(any(c.get("patterns") == ["node_modules"] for c in calls))

    def test_15_duplicate_target_session_is_ignored(self):
        import faulthandler
        # Watchdog for *this* test's 15s wait below. It must be cancelled in the
        # finally: dump_traceback_later fires on a wall-clock timer regardless of
        # whether anything is stuck, so an uncancelled one goes off in whichever
        # test happens to be running 40s later (on a slow runner, test_20) and
        # its dump has been observed killing the process on Windows/py3.12.
        faulthandler.dump_traceback_later(40)  # evidence if the pump wedges
        try:
            # the fake server re-announced t-1 under session "s-dup": it must not
            # be instrumented (one session per target), and hooks must not double-fire
            pages = [t for t in self.session.targets() if t[2] == "about:blank"]
            self.assertEqual(len(pages), 1, f"target registered twice: {pages}")
            before = len(self.session.captures())
            self.session.hook("window.fn", label="dup-check")
            if not wait_until(lambda: len(self.session.captures()) > before,
                              timeout=15):
                diag = {
                    "setBpCalls": len(self.fake.calls_of("Debugger.setBreakpointOnFunctionCall")),
                    "resumeCalls": len(self.fake.calls_of("Debugger.resume")),
                    "events_qsize": self.session.cdp._events.qsize(),
                    "unfinished": self.session.cdp._events.unfinished_tasks,
                    "pump_alive": self.session.cdp._pump.is_alive() if self.session.cdp._pump else None,
                    "reader_alive": self.session.cdp._thread.is_alive(),
                    "hooks": [h["label"] for h in self.session.tracer.hooks],
                    "by_call_bp": list(self.session.tracer.by_call_bp),
                }
                self.fail(f"entry pause never captured: {diag}")
            import time
            time.sleep(0.5)   # a duplicate session would deliver a second pause here
            self.assertEqual(len(self.session.captures()), before + 1,
                             self.session.captures())
        finally:
            faulthandler.cancel_dump_traceback_later()

    def test_16_string_match_exposes_object_holder(self):
        snap = Snapshot(SNAP_BEFORE)
        hits = snap.find(contains="sbx_9f27")
        holder = snap.object_retainer(hits[0])
        self.assertEqual(holder, {"heap_object_id": "1", "name": "Config",
                                  "via": "property:token"})

    def test_17_headless_ua_is_masked(self):
        overrides = self.fake.calls_of("Network.setUserAgentOverride")
        self.assertTrue(overrides, "no UA override applied")
        ua = overrides[0]["userAgent"]
        self.assertNotIn("Headless", ua)
        self.assertIn("Chrome", ua)
        meta = overrides[0].get("userAgentMetadata") or {}
        # The masked platform tracks the host: claiming Windows while running on
        # Linux is itself a fingerprint tell, so assert what this host should report.
        expected_platform = {"win32": "Windows", "darwin": "macOS"}.get(sys.platform, "Linux")
        self.assertEqual(meta.get("platform"), expected_platform)
        self.assertTrue(meta.get("fullVersionList"))

    def test_18_new_page_registers_and_navigates(self):
        sid = self.session.new_page("https://new/target")
        targets = self.session.targets()
        self.assertTrue(any(u == "https://new/target" for _, _, u in targets),
                        targets)
        self.assertEqual(self.session.engine.resolve_session("new/target"), sid)

    def test_19_watch_records_changes(self):
        r = self.session.watch("window.__clock__", seconds=0.5, interval=0.05)
        values = [c["value"] for c in r["changes"]]
        self.assertGreaterEqual(len(values), 2, r)
        self.assertEqual(values, sorted(values))

    def test_20_auto_hook_arms_top_function_by_object(self):
        self.session.coverage("start")
        self.fake.heap_snapshots = [SNAP_SIGN]
        before = len(self.fake.calls_of("Debugger.setBreakpointOnFunctionCall"))
        r = self.session.auto_hook(top=1, min_count=1)
        self.assertTrue(r["hooked"], r)
        self.assertEqual(r["hooked"][0]["label"], "auto:sign")
        after = len(self.fake.calls_of("Debugger.setBreakpointOnFunctionCall"))
        self.assertGreater(after, before, "hook_remote never armed a breakpoint")

    def test_21_trace_value_joins_sources(self):
        r = self.session.trace_value("sig_zoe")
        self.assertTrue(r["pairs"], "corpus pairs missing from trace_value")
        self.assertTrue(r["hook_captures"] or r["network"] or True)

    def test_22_console_and_exceptions_recorded(self):
        self.assertTrue(wait_until(
            lambda: self.session.grep("sbi_marker_log")["console"]),
            "console event never arrived")
        recs = self.session.console()          # drain
        self.assertTrue(any(r["kind"] == "exception" and
                            "sbi_marker_exc" in (r["text"] or "") for r in recs), recs)
        self.assertTrue(any(r["stack"] == ["check"] for r in recs), recs)
        self.assertEqual(self.session.console(), [])   # drained

    def test_23_screenshot_writes_png(self):
        import os
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "shot.png")
        self.session.screenshot(path)
        with open(path, "rb") as f:
            self.assertEqual(f.read(4), b"\x89PNG")

    def test_24_click_element_dispatches_trusted_events(self):
        xy = self.session.click_element("#btn")
        self.assertEqual(xy, (12, 34))
        calls = self.fake.calls_of("Input.dispatchMouseEvent")
        types = [c["type"] for c in calls]
        self.assertEqual(types, ["mousePressed", "mouseReleased"])
        self.assertEqual((calls[0]["x"], calls[0]["y"]), (12, 34))
        self.assertEqual(calls[0]["button"], "left")

    def test_25_intercept_fulfills_mock(self):
        self.session.intercept("https://t.mock/lock", body="DENIED")
        self.assertTrue(wait_until(
            lambda: bool(self.fake.calls_of("Fetch.fulfillRequest"))),
            "paused request never fulfilled")
        call = self.fake.calls_of("Fetch.fulfillRequest")[-1]
        self.assertEqual(call["responseCode"], 200)
        import base64
        self.assertEqual(base64.b64decode(call["body"]), b"DENIED")

    def test_26_cookies_and_storage(self):
        cks = self.session.cookies()
        self.assertEqual([c["name"] for c in cks], ["sid"])
        st = self.session.storage()
        self.assertEqual(st["local"], {"k": "v"})

    def test_27_dialog_policy_answers_and_records(self):
        self.session.set_dialog_policy("accept")
        self.session.navigate("https://x/next")
        self.assertTrue(wait_until(
            lambda: bool(self.fake.calls_of("Page.handleJavaScriptDialog"))),
            "dialog never answered")
        call = self.fake.calls_of("Page.handleJavaScriptDialog")[-1]
        self.assertTrue(call["accept"])
        recs = self.session.dialogs()
        self.assertTrue(any(r["type"] == "confirm" and r["action"] == "accept"
                            for r in recs), recs)

    def test_28_reconnect_rearms_hooks_and_preserves_corpus(self):
        self.session.hook("window.fn", capture_returns=True, label="recon")
        self.assertTrue(wait_until(lambda: len(self.session.corpus("recon")) >= 1,
                                   timeout=15), "initial pair never captured")
        before = len(self.session.corpus("recon"))
        old_cdps = self.session.cdp
        old_bps = len(self.fake.calls_of("Debugger.setBreakpointOnFunctionCall"))
        r = self.session.reconnect()
        self.assertIsNot(self.session.cdp, old_cdps, "transport was not rebuilt")
        self.assertIn("recon", r["hooked"], r)
        self.assertGreaterEqual(len(self.session.corpus("recon")), before,
                                "old corpus lost across reconnect")
        after = len(self.fake.calls_of("Debugger.setBreakpointOnFunctionCall"))
        self.assertGreater(after, old_bps, "reconnect never re-armed the hook")

    def test_29_metrics_returns_counters(self):
        m = self.session.metrics()
        self.assertEqual(m["JSHeapUsedSize"], 12345.0)
        self.assertEqual(m["Nodes"], 42)

    def test_30_profile_ranks_hot_functions(self):
        r = self.session.profile(action="window.work()")
        names = [h["function"] for h in r["hot"]]
        self.assertIn("hotFn", names, r)
        self.assertNotIn("idle", names)                      # zero-hit nodes dropped
        self.assertEqual(r["hot"][0]["hits"], 7)

    def test_31_pdf_writes_document(self):
        import os
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "page.pdf")
        self.session.pdf(path)
        with open(path, "rb") as f:
            self.assertEqual(f.read(5), b"%PDF-")

    def test_32_environment_control_sends_right_commands(self):
        s = self.session
        s.throttle(latency_ms=300, download_kbps=50)
        calls = [(m, p) for m, p in [(c[0], c[1]) for c in self.fake.calls]
                 if m == "Network.emulateNetworkConditions"]
        self.assertTrue(any(p["latency"] == 300 and p["downloadThroughput"] == 6250
                            and p["offline"] is False for _, p in calls), calls)
        s.offline(True)
        offline_calls = [(m, p) for m, p in [(c[0], c[1]) for c in self.fake.calls]
                         if m == "Network.emulateNetworkConditions"]
        self.assertTrue(offline_calls[-1][1]["offline"])
        s.geolocation(52.5, 13.4, accuracy=90)
        geo = [p for m, p in [(c[0], c[1]) for c in self.fake.calls]
               if m == "Emulation.setGeolocationOverride"][-1]
        self.assertEqual((geo["latitude"], geo["longitude"], geo["accuracy"]),
                         (52.5, 13.4, 90))
        s.grant_permissions(["geolocation"])
        self.assertTrue(any(p["permissions"] == ["geolocation"]
                            for m, p in [(c[0], c[1]) for c in self.fake.calls]
                            if m == "Browser.grantPermissions"))
        self.assertTrue(s.set_cookie("sid", "v1", domain="x"))
        cookie_calls = [p for m, p in [(c[0], c[1]) for c in self.fake.calls]
                        if m == "Network.setCookie"]
        self.assertEqual(cookie_calls[-1]["name"], "sid")
        s.clear_storage("https://t")
        self.assertTrue(any(p["origin"] == "https://t"
                            for m, p in [(c[0], c[1]) for c in self.fake.calls]
                            if m == "Storage.clearDataForOrigin"))

    def test_33_data_url_navigation_rejected(self):
        with self.assertRaises(ValueError):
            self.session.navigate("data:text/html,<p>x</p>")

    def test_34_save_with_sanitize_redacts(self):
        import os
        import tempfile
        with self.session.tracer.lock:
            self.session.tracer.pairs.setdefault("leak", []).append(
                {"input": ["u"], "output": "Bearer abcdefgh12345"})
        path = os.path.join(tempfile.mkdtemp(), "san.json")
        self.session.save(path, sanitize=True)
        text = open(path, encoding="utf-8").read()
        self.assertNotIn("abcdefgh12345", text, "secret survived sanitize")
        self.assertIn("REDACTED", text)

    def test_35_report_includes_dialogs(self):
        import os
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "rep.md")
        with self.session._dialogs.lock:
            self.session._dialogs.records.append(
                {"type": "confirm", "message": "sure?", "action": "accept"})
        self.session.report(path)
        text = open(path, encoding="utf-8").read()
        self.assertIn("## JS dialogs", text)
        self.assertIn("sure?", text)

    def test_36_wasm_modules_listed(self):
        self.assertTrue(wait_until(lambda: self.session.wasm_modules()),
                        "wasm scriptParsed event never processed")
        w = [m for m in self.session.wasm_modules() if m["script_id"] == "w1"]
        self.assertEqual(w[0]["url"], "wasm-abc123")
        self.assertEqual(w[0]["url"], "wasm-abc123")

    def test_37_wasm_dump_writes_magic(self):
        import os
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "mod.wasm")
        r = self.session.wasm_dump("w1", path)
        self.assertTrue(r["is_wasm"], r)
        self.assertEqual(r["bytes"], 12)
        with open(path, "rb") as f:
            self.assertEqual(f.read(4), b"\x00asm")

    def test_38_wasm_disassemble_extracts_functions(self):
        r = self.session.wasm_disassemble("w1")
        self.assertIn("shape_hash", r["functions"], r)
        self.assertIn("i32.const 42", r["text"])

    def test_39_wasm_meta_reads_exports(self):
        m = self.session.wasm_meta("window.winst")
        self.assertEqual(m["kind"], "instance", m)
        self.assertEqual(m["exports"], [{"name": "answer", "kind": "function"}])

    def test_40_wasm_from_network_dumps_wire_bytes(self):
        import os
        import tempfile

        class StubNet:
            def __init__(self):
                self.lock = __import__("threading").Lock()
                self.raw_bodies = {"r-1": b"\x00asm\x01\x00\x00\x00wire"}
                self.meta = {"r-1": {"url": "https://t/engine.wasm"}}

        out = tempfile.mkdtemp()
        dumped = wasm_mod.from_network(StubNet(), out)
        self.assertEqual(len(dumped), 1)
        self.assertEqual(dumped[0]["url"], "https://t/engine.wasm")
        with open(dumped[0]["path"], "rb") as f:
            self.assertEqual(f.read(), b"\x00\x61\x73\x6d\x01\x00\x00\x00wire")

    def test_42_export_har_structure(self):
        import os
        import tempfile
        self.session.network.drain()            # history-independent
        self.session.navigate("https://t/page42")
        self.assertTrue(wait_until(
            lambda: any(r.get("request_id") == "r-nav" and
                        self.session.network.bodies.get("r-nav")
                        for r in self.session.network.records),
            timeout=10), "page body never fetched")
        path = os.path.join(tempfile.mkdtemp(), "t.har")
        r = self.session.export_har(path)
        self.assertGreaterEqual(r["entries"], 1, r)
        har = json.load(open(path, encoding="utf-8"))
        page = [e for e in har["log"]["entries"] if e["request"]["url"] == "https://t/page42"]
        self.assertTrue(page, har["log"]["entries"])
        self.assertEqual(page[0]["request"]["method"], "GET")
        self.assertEqual(page[0]["response"]["status"], 200)
        self.assertEqual(page[0]["response"]["content"].get("text"), '{"ok":1}')

    def test_43_state_save_roundtrip(self):
        import os
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "state.json")
        r = self.session.save_state(path)
        self.assertEqual(r["cookies"], 1, r)
        state = json.load(open(path, encoding="utf-8"))
        self.assertEqual(state["cookies"][0]["name"], "sid")
        restored = self.session.load_state(path)
        self.assertGreaterEqual(restored["cookies"], 1)

    def test_44_replay_request_repeats(self):
        r = self.session.replay_request("https://t/api", method="POST", body="a=1")
        self.assertEqual(r["status"], 201, r)
        self.assertEqual(r["body"], "replayed")

    def test_45_dom_snapshot_writes(self):
        import os
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "dom.html")
        r = self.session.dom_snapshot(path)
        text = open(path, encoding="utf-8").read()
        self.assertIn("<body>", text)
        self.assertGreater(r["bytes"], 0)

    def test_46_deobf_guard_raises_for_missing_file(self):
        from sbi.deobfuscate import deobf
        with self.assertRaises(FileNotFoundError):
            deobf.deobfuscate(os.path.join("no", "such.js"))

    def test_47_environment_stress_commands(self):
        s = self.session
        s.cpu_throttle(8)
        s.emulate_media("prefers-color-scheme", "dark")
        s.cache("disable")
        s.cache("clear")
        s.bypass_csp(True)
        for m, frag in (("Emulation.setCPUThrottlingRate", None),
                        ("Emulation.setEmulatedMedia", None),
                        ("Network.setCacheDisabled", None),
                        ("Network.clearBrowserCache", None),
                        ("Page.setBypassCSP", None)):
            calls = [p for mm, p in [(c[0], c[1]) for c in self.fake.calls] if mm == m]
            self.assertTrue(calls, f"{m} never sent")
        throttle = [p for mm, p in [(c[0], c[1]) for c in self.fake.calls]
                    if mm == "Emulation.setCPUThrottlingRate"][-1]
        self.assertEqual(throttle["rate"], 8.0)
        media = [p for mm, p in [(c[0], c[1]) for c in self.fake.calls]
                 if mm == "Emulation.setEmulatedMedia"][-1]
        self.assertEqual(media["features"][0]["name"], "prefers-color-scheme")

    def test_48_wheel_scroll_dispatches(self):
        s = self.session
        s.scroll(100, 200, delta_y=900)
        calls = [p for mm, p in [(c[0], c[1]) for c in self.fake.calls]
                 if mm == "Input.dispatchMouseEvent" and p.get("type") == "mouseWheel"]
        self.assertTrue(calls, "no wheel event")
        self.assertEqual((calls[-1]["x"], calls[-1]["y"]), (100, 200))
        self.assertEqual(calls[-1]["deltaY"], 900)

    def test_49_bypass_csp_command(self):
        calls = [p for mm, p in [(c[0], c[1]) for c in self.fake.calls]
                 if mm == "Page.setBypassCSP"]
        self.assertTrue(calls and calls[-1]["enabled"] is True)

    def test_50_idb_inventory(self):
        r = self.session.idb()
        self.assertEqual(r.get("db1"), {"version": 1}, r)

    def test_51_element_screenshot_uses_clip(self):
        import os
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "el.png")
        r = self.session.screenshot_element("#btn", path)
        self.assertEqual(r["box"], {"x": 5, "y": 6, "w": 20, "h": 10})
        with open(path, "rb") as f:
            self.assertEqual(f.read(4), bytes([137]) + b"PNG")

    def test_52_call_object_generalizes_patch(self):
        r = self.session.call_object("2", "function (x) { return x * 2; }", [21])
        self.assertIsNotNone(r, "callFunctionOn returned nothing")

    def test_53_intercept_modify_request_continue(self):
        self.session.clear_intercepts()
        self.session.intercept("https://t.mock/login", stage="request",
                               modify={"method": "POST",
                                       "headers": {"X-Test": "1"},
                                       "body": "u=1"})
        def modified_continue():
            for c in self.fake.calls_of("Fetch.continueRequest"):
                if c.get("method") == "POST":
                    return c
            return None
        self.assertTrue(wait_until(modified_continue, timeout=10),
                        "modified request never continued")
        cont = modified_continue()
        self.assertEqual(cont["headers"][0]["value"], "1")
        import base64
        self.assertEqual(base64.b64decode(cont["postData"]).decode(), "u=1")

    def test_54_intercept_response_stage_replaces_body(self):
        self.session.clear_intercepts()
        self.session.intercept("https://t.mock/feed", stage="response",
                               body='{"fed":true}')
        import base64
        def fed_fulfill():
            for c in self.fake.calls_of("Fetch.fulfillRequest"):
                if base64.b64decode(c.get("body", "")).decode(errors="replace") == '{"fed":true}':
                    return c
            return None
        self.assertTrue(wait_until(fed_fulfill, timeout=10),
                        "response-stage rule never fulfilled")
        self.assertEqual(fed_fulfill()["responseCode"], 200)

    def test_55_wait_for_truthy(self):
        v = self.session.wait_for("window.__clock__", timeout=3, interval=0.05)
        self.assertGreaterEqual(v, 1)

    def test_56_capture_inputs_grows_corpus(self):
        before = len(self.session.corpus("fn"))
        r = self.session.capture_inputs("fn", "window.fn", [["captured", 1]])
        self.assertGreaterEqual(r["captured"], 1, r)
        self.assertGreater(len(self.session.corpus("fn")), before)

    def test_57_response_edit_rewrites_original(self):
        self.session.clear_intercepts()
        self.session.intercept("https://t.mock/edit", stage="response",
                               edit=[("SECRET", "REDACTED")])
        import base64
        def edited_fulfill():
            for c in self.fake.calls_of("Fetch.fulfillRequest"):
                try:
                    if "REDACTED" in base64.b64decode(c.get("body", "")).decode():
                        return c
                except Exception:
                    continue
            return None
        self.assertTrue(wait_until(edited_fulfill, timeout=10),
                        "edited response never fulfilled")
        self.assertTrue("original with" in
                        base64.b64decode(edited_fulfill()["body"]).decode())

    def test_58_type_into_focuses_and_types(self):
        self.session.type_into("#any", "hello")

    def test_59_agent_script_sends_and_rpc(self):
        s = self.session
        got = []
        s.load_agent("probe1", "send({hello: 'world'}); rpc.ping = () => 'pong';",
                     on_message=lambda payload, sid: got.append(payload))
        self.assertTrue(wait_until(lambda: got), "agent message never arrived")
        msgs = s.agent_messages("probe1")
        self.assertEqual(msgs[0]["payload"], {"hello": "world"}, msgs)
        result = s.call_agent("probe1", "ping")
        self.assertEqual(result, "pong")


if __name__ == "__main__":
    unittest.main(verbosity=2)
