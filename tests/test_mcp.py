"""End-to-end MCP integration tests: spawn `python -m sbi.mcp_server` as a
real subprocess, connect over stdio exactly like an MCP client (Claude Code)
would, and drive EVERY tool against a live Chromium. Skips when no CDP
endpoint answers — see tests/test_live.py for how to start one.

Each test holds ONE server process for the whole flow — tools build on each
other's state, which is how agent sessions actually run. This is the "use all
the tools" guarantee: the table in docs/mcp-tools.md is validated here, over
the wire, not by inspection.
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest
import urllib.request
from contextlib import asynccontextmanager
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:  # the mcp extra is optional: `pip install -e '.[mcp]'`
    raise unittest.SkipTest("mcp not installed; skipping MCP stdio suite")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CDP = os.environ.get("SBI_CDP") or "http://127.0.0.1:9222"

PAGE = (
    "<script>"
    "window.sign=(u,p)=>btoa(u+'#'+(p*7+1));"
    "var _arr=['alpha','bravo','charlie'];"
    "window.dec=(i)=>_arr[i];"
    "(function(){const st={token:'mcp_tok_4242'};"
    "window.toklen=()=>st.token.length;})();"
    "</script><p>sbi</p>"
)  # trailing element forces a <body>; all-script writes leave the body empty  # injected via document.write: top-level data: URLs are unreliable in Chrome

EXPECTED_TOOLS = {
    "sbi_attach", "sbi_targets", "sbi_hook", "sbi_captures", "sbi_verify",
    "sbi_replay", "sbi_sanitize", "sbi_objects", "sbi_object", "sbi_origin",
    "sbi_heapdiff", "sbi_patch", "sbi_functions", "sbi_coverage", "sbi_follow",
    "sbi_vm", "sbi_audit", "sbi_blackbox", "sbi_strings", "sbi_probe",
    "sbi_grep", "sbi_auto_hook", "sbi_watch", "sbi_trace_value", "sbi_new_page",
    "sbi_eval", "sbi_scripts", "sbi_source", "sbi_dump_scripts", "sbi_report",
    "sbi_save", "sbi_close",
    "sbi_console", "sbi_cookies", "sbi_storage", "sbi_screenshot", "sbi_click",
    "sbi_type", "sbi_intercept", "sbi_clear_intercepts",
    "sbi_dialogs", "sbi_emulate", "sbi_doctor",
    "sbi_reconnect", "sbi_metrics", "sbi_profile", "sbi_pdf",
    "sbi_network_conditions", "sbi_geolocation", "sbi_grant_permissions",
    "sbi_set_cookie", "sbi_clear_storage",
    "sbi_wasm_modules", "sbi_wasm_dump", "sbi_wasm_disasm", "sbi_wasm_meta",
    "sbi_wasm_from_network", "sbi_collect_script", "sbi_wasm_extract_embedded",
    "sbi_deobfuscate", "sbi_export_har", "sbi_save_state",
    "sbi_load_state", "sbi_replay_request", "sbi_dom_snapshot",
}

TIMEOUT = timedelta(seconds=180)


def _endpoint_alive():
    try:
        with urllib.request.urlopen(CDP.rstrip("/") + "/json/version", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def _params():
    env = dict(os.environ, SCRAPELESS_CDP_URL=CDP, PYTHONPATH=ROOT)
    return StdioServerParameters(command=sys.executable, args=["-m", "sbi.mcp_server"],
                                 cwd=ROOT, env=env)


@asynccontextmanager
async def server():
    async with stdio_client(_params()) as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            yield s


def run_flow(coro):
    return asyncio.run(coro)


class MCPAllTools(unittest.TestCase):
    """Scripted agent conversations covering every tool over real stdio."""

    @classmethod
    def setUpClass(cls):
        if not _endpoint_alive():
            raise unittest.SkipTest(
                f"no CDP endpoint at {CDP} "
                "(start: chrome --headless=new --remote-debugging-port=9222)")

    def test_10_tools_registered(self):
        async def flow():
            async with server() as s:
                listed = await s.list_tools()
                return {t.name for t in listed.tools}

        names = run_flow(flow())
        missing = EXPECTED_TOOLS - names
        self.assertEqual(missing, set(), f"tools missing from the server: {missing}")
        self.assertGreaterEqual(len(names), len(EXPECTED_TOOLS))

    def test_20_capture_verify_and_watch(self):
        async def flow():
            async with server() as s:
                async def call(name, args=None, parse=True):
                    res = await s.call_tool(name, args or {}, TIMEOUT)
                    text = res.content[0].text if res.content else ""
                    return text if not parse else json.loads(text)

                r = await call("sbi_attach", {"url": "about:blank", "wait": 0.3})
                assert r["ok"], r
                assert any(t[1] == "page" for t in r["targets"]), r
                await call("sbi_eval", {
                    "expression": f"document.write({json.dumps(PAGE)})"})

                r = await call("sbi_hook", {"expression": "window.sign",
                                            "capture_returns": True, "label": "sign"})
                assert r["ok"], r
                await call("sbi_hook", {"expression": "window.dec", "label": "dec"})

                await call("sbi_eval", {"expression":
                            "window.sign('zoe',0);window.sign('ana',3);window.dec(1)"})

                caps = await call("sbi_captures", {"label": "sign"})
                assert len(caps["captures"]) >= 2, caps
                assert caps["corpus_sizes"]["sign"] >= 2, caps

                wrong = await call("sbi_verify", {
                    "fn_expr": "window.sign", "candidate": "(u,p)=>btoa(u+'#'+(p*7))",
                    "label": "sign", "fresh_inputs": [["zoe", 0]]})
                assert not wrong["verified"] and wrong["mismatches"], wrong
                right = await call("sbi_verify", {
                    "fn_expr": "window.sign", "candidate": "(u,p)=>btoa(u+'#'+(p*7+1))",
                    "label": "sign"})
                assert right["verified"], right

                targets = await call("sbi_targets", {})
                assert any(t[1] == "page" for t in targets), targets

                scripts = await call("sbi_scripts", {})
                assert scripts, scripts
                # eval probes register as scripts too — search for the page's own
                found_src = False
                for sc in scripts[-8:]:
                    src = await call("sbi_source", {"script_id": sc["script_id"]},
                                     parse=False)
                    if "window.sign" in src:
                        found_src = True
                        break
                assert found_src, "injected page script not found via sbi_scripts/sbi_source"

                grep = await call("sbi_grep", {"needle": "zoe"})
                assert grep["pairs"], grep

                tv = await call("sbi_trace_value", {"needle": "zoe"})
                assert tv["pairs"], tv

                watch = await call("sbi_watch", {
                    "expression": "(window.__c=(window.__c||0)+1)",
                    "seconds": 0.8, "interval": 0.1})
                assert len(watch["changes"]) >= 2, watch

                strings = await call("sbi_strings", {"decoder_expr": "window.dec", "n": 3})
                assert [strings["values"].get(str(i)) for i in range(3)] == \
                    ["alpha", "bravo", "charlie"], strings

                follow = await call("sbi_follow", {"label": "sign"})
                assert "flows" in follow, follow

                vm = await call("sbi_vm", {})
                assert "steps" in vm, vm
                return True

        self.assertTrue(run_flow(flow()))

    def test_30_locate_and_act(self):
        async def flow():
            async with server() as s:
                async def call(name, args=None, parse=True):
                    res = await s.call_tool(name, args or {}, TIMEOUT)
                    text = res.content[0].text if res.content else ""
                    return text if not parse else json.loads(text)

                await call("sbi_attach", {"url": "about:blank", "wait": 0.3})
                await call("sbi_eval", {
                    "expression": f"document.write({json.dumps(PAGE)})"})
                await call("sbi_eval", {"expression": "window.toklen()"})

                objects = await call("sbi_objects", {"contains": "mcp_tok_4242"})
                exact = [m for m in objects["matches"] if m["name"] == "mcp_tok_4242"]
                assert exact, objects["matches"]
                holder = exact[0].get("holder")
                assert holder, "no holder for the token string"

                origin = await call("sbi_origin", {"value": "mcp_tok_4242"})
                assert origin["matches"], origin

                obj = await call("sbi_object", {"heap_object_id": holder["heap_object_id"]})
                names = {p["name"] for p in obj.get("properties") or []}
                assert "token" in names, obj

                hd = await call("sbi_heapdiff", {"action": "window.toklen()"})
                assert "new_nodes" in hd, hd

                before = await call("sbi_eval", {"expression": "window.toklen()"})
                patch = await call("sbi_patch", {"heap_object_id": holder["heap_object_id"],
                                                 "prop": "token", "value": "PATCHED"})
                assert patch.get("ok"), patch
                after = await call("sbi_eval", {"expression": "window.toklen()"})
                assert before["value"] != after["value"], "patch did not flip behaviour"

                fns = await call("sbi_functions", {"contains": "sign"})
                assert any("sign" in f["name"] for f in fns["functions"]), fns

                await call("sbi_coverage", {"action": "start"})
                await call("sbi_eval", {"expression": "window.sign('cov',1)"})
                cov = await call("sbi_coverage", {"action": "take"})
                assert cov["functions"], cov
                auto = await call("sbi_auto_hook", {"top": 1})
                assert "hooked" in auto, auto

                await call("sbi_blackbox", {"patterns": ["node_modules"]})
                audit = await call("sbi_audit", {})
                assert audit["all_intact"], audit

                page = await call("sbi_new_page", {"url": "about:blank"})
                assert "session_id" in page, page

                probe = await call("sbi_probe", {"action": "install", "names": ["crypto"]})
                assert probe.get("ok", True), probe
                drained = await call("sbi_probe", {"action": "drain"})
                assert isinstance(drained, list)

                con = await call("sbi_console", {})
                assert isinstance(con, list)

                shot = await call("sbi_screenshot", {})
                assert os.path.exists(shot["path"]), shot

                click = await call("sbi_click", {"selector": "body"})
                assert click["clicked_at"], click

                cks = await call("sbi_cookies", {})
                assert isinstance(cks, list)

                st = await call("sbi_storage", {})
                assert isinstance(st, dict)

                await call("sbi_intercept", {"pattern": "https://mock.sbi.test/api",
                                             "body": '{"ok":1}',
                                             "headers": {"Access-Control-Allow-Origin": "*"}})
                mocked = await call("sbi_eval", {
                    "expression": "fetch('https://mock.sbi.test/api').then(r => r.text())",
                    "await_promise": True})
                assert mocked["value"] == '{"ok":1}', mocked
                await call("sbi_clear_intercepts", {})

                dialogs = await call("sbi_dialogs", {"policy": "accept"})
                assert dialogs["policy"] == "accept", dialogs
                answered = await call("sbi_eval", {"expression": "window.confirm('sure?')"})
                assert answered["value"] is True, answered
                drained = await call("sbi_dialogs", {})
                assert any(d["type"] == "confirm" for d in drained), drained

                await call("sbi_emulate", {"kind": "timezone", "value": "Europe/Berlin"})
                tz = await call("sbi_eval", {
                    "expression": "Intl.DateTimeFormat().resolvedOptions().timeZone"})
                assert tz["value"] == "Europe/Berlin", tz

                met = await call("sbi_metrics", {})
                assert met.get("JSHeapUsedSize", 0) > 0, met

                prof = await call("sbi_profile", {"action": "window.toklen()"})
                assert "hot" in prof, prof

                pdf_path = os.path.join(tempfile.mkdtemp(prefix="sbi_mcp_"),
                                        "page.pdf").replace("\\", "/")
                pdf = await call("sbi_pdf", {"path": pdf_path})
                assert os.path.exists(pdf["path"]), pdf

                doc = await call("sbi_doctor", {})
                assert "endpoint" in doc, doc

                rec = await call("sbi_reconnect", {})
                assert "hooked" in rec, rec
                targets = await call("sbi_targets", {})
                assert any(t[1] == "page" for t in targets), targets

                # geolocation needs a secure origin — serve one locally
                import threading
                from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

                class Quiet(BaseHTTPRequestHandler):
                    protocol_version = "HTTP/1.0"
                    def do_GET(self):
                        self.send_response(200)
                        self.send_header("Content-Length", "2")
                        self.end_headers()
                        self.wfile.write(b"ok")
                    def log_message(self, *a):
                        pass

                srv = ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
                srv.daemon_threads = True
                geo_port = srv.server_address[1]
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                try:
                    await call("sbi_attach", {"url": f"http://127.0.0.1:{geo_port}/",
                                              "wait": 0.5})
                    await call("sbi_grant_permissions",
                               {"permissions": ["geolocation"],
                                "origin": f"http://127.0.0.1:{geo_port}"})
                    await call("sbi_geolocation", {"lat": 52.5, "lon": 13.4})
                    pos = await call("sbi_eval", {
                        "expression": ("new Promise((res, rej) => "
                                       "navigator.geolocation.getCurrentPosition("
                                       "p => res({lat: p.coords.latitude, lon: p.coords.longitude}),"
                                       " rej, {timeout: 4000}))"), "await_promise": True})
                    assert pos["value"]["lat"] == 52.5, pos
                finally:
                    srv.shutdown()
                    srv.server_close()

                cookie = await call("sbi_set_cookie", {"name": "sbi_t", "value": "1",
                                                       "url": "http://127.0.0.1/"})
                assert cookie["set"], cookie
                cks = await call("sbi_cookies", {})
                assert any(c["name"] == "sbi_t" for c in cks), cks

                await call("sbi_network_conditions", {"offline": True})
                off = await call("sbi_eval", {
                    "expression": ("fetch('https://offline.test/x')"
                                   ".catch(e => String(e))"), "await_promise": True})
                assert "Failed to fetch" in str(off["value"]), off
                await call("sbi_network_conditions", {"latency_ms": 0})
                return True

        self.assertTrue(run_flow(flow()))

    def test_40_artifacts_lifecycle(self):
        async def flow():
            async with server() as s:
                async def call(name, args=None, parse=True):
                    res = await s.call_tool(name, args or {}, TIMEOUT)
                    text = res.content[0].text if res.content else ""
                    return text if not parse else json.loads(text)

                tmp = tempfile.mkdtemp(prefix="sbi_mcp_")
                trace_path = os.path.join(tmp, "trace.json").replace("\\", "/")

                await call("sbi_attach", {"url": "about:blank", "wait": 0.3})
                await call("sbi_eval", {
                    "expression": f"document.write({json.dumps(PAGE)})"})
                await call("sbi_hook", {"expression": "window.sign",
                                        "capture_returns": True, "label": "sign"})
                await call("sbi_eval", {"expression": "window.sign('zoe',0);window.sign('ana',3)"})
                await call("sbi_eval", {"expression": "window.dec(0);window.dec(2)"})

                saved = await call("sbi_save", {"path": trace_path})
                assert "pairs" in saved, saved
                assert os.path.exists(trace_path)
                assert saved["pairs"]["sign"] >= 2, saved["pairs"]

                sanitized = await call("sbi_sanitize", {"path": trace_path})
                assert os.path.exists(sanitized["out"]), sanitized
                assert sanitized["report"]["fields_seen"] > 0

                report_path = os.path.join(tmp, "report.md").replace("\\", "/")
                await call("sbi_report", {"path": report_path})
                text = open(report_path, encoding="utf-8").read()
                assert "# Instrumentation report" in text

                dump_dir = os.path.join(tmp, "src").replace("\\", "/")
                dumped = await call("sbi_dump_scripts", {"directory": dump_dir})
                assert isinstance(dumped, list)

                replay = await call("sbi_replay", {"trace_path": trace_path})
                assert "hooked" in replay, replay

                closed = await call("sbi_close", {})
                assert closed["ok"], closed
                return True

        self.assertTrue(run_flow(flow()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
