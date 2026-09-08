"""MCP server: drive an instrumented Scrapeless session from an agent.

    pip install mcp
    claude mcp add sbi -- python -m sbi.mcp_server

Requires SCRAPELESS_API_TOKEN (or SCRAPELESS_CDP_URL) in the environment; the
session attaches lazily on the first tool call. The intended loop for the
agent is the skill in skills/verify-reimplementation: hypothesize -> hook ->
capture -> verify -> iterate until the diff is empty.
"""

import json
import os

from .api import Session

_session = None


def _get(url=None):
    global _session
    if _session is None:
        from .core.cdp import CDP
        _session = Session(CDP(_endpoint_url()).connect())
        _session.start()
    return _session


def _endpoint_url():
    from .api import endpoint
    return endpoint(token=os.environ.get("SCRAPELESS_API_TOKEN"),
                    cdp=os.environ.get("SCRAPELESS_CDP_URL") or None,
                    proxy_country=os.environ.get("SCRAPELESS_PROXY_COUNTRY") or None)


def _j(x):
    return json.dumps(x, indent=2, default=str)


def main():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        raise SystemExit("the MCP server needs the 'mcp' package: pip install mcp")

    mcp = FastMCP("scrapeless-browser-instrumentation")

    @mcp.tool()
    def sbi_attach(url: str, wait: float = 3.0) -> str:
        """Attach to a Scrapeless browser session and navigate to url."""
        s = _get()
        s.navigate(url)
        s.wait(wait)
        return _j({"ok": True, "url": url, "targets": s.targets()})

    @mcp.tool()
    def sbi_targets() -> str:
        """List live targets (pages, workers, iframes) with their session ids."""
        return _j(_get().targets())

    @mcp.tool()
    def sbi_hook(expression: str, capture_returns: bool = False, label: str = None,
                 target_url: str = None) -> str:
        """Invisibly hook a function (expr, or 'expr@@url-substr'). With
        capture_returns, records (input -> output) pairs for the oracle."""
        _get().hook(expression, target_url=target_url, capture_returns=capture_returns, label=label)
        return _j({"ok": True, "hooked": expression})

    @mcp.tool()
    def sbi_captures(label: str = None) -> str:
        """Captured hook hits; pass a label to get its (input, output) corpus."""
        s = _get()
        return _j({"captures": s.captures(label) if label else s.captures(),
                   "corpus_sizes": s.corpora()})

    @mcp.tool()
    def sbi_verify(fn_expr: str, candidate: str, label: str = None,
                   fresh_inputs: list = None, target_url: str = None,
                   mode: str = "exact") -> str:
        """Verify a reimplementation candidate against the captured corpus +
        fresh live inputs. candidate is a JS function expression. mode:
        exact | loose_string (structure) | numeric (tolerance) |
        time_tolerant (timestamps). Returns a structured diff with
        counterexamples — iterate until verified=true."""
        return _j(_get().verify(fn_expr, candidate, label=label,
                                fresh_inputs=fresh_inputs, target_url=target_url,
                                mode=mode))

    @mcp.tool()
    def sbi_replay(trace_path: str) -> str:
        """Re-establish a saved trace's hooks on the live session
        (navigate if the artifact recorded a url, re-hook every hook)."""
        return _j(_get().replay(trace_path))

    @mcp.tool()
    def sbi_sanitize(path: str, out_path: str = None) -> str:
        """Redact secrets (tokens, bearer headers, cookies, high-entropy
        strings, emails) from a trace artifact before sharing it."""
        from .artifacts.sanitize import sanitize_file
        out, report = sanitize_file(path, out_path)
        return _j({"out": out, "report": report})

    @mcp.tool()
    def sbi_objects(contains: str = None, regex: str = None, ctor: str = None,
                    session: str = None, limit: int = 25, with_retainers: int = 0) -> str:
        """Search the live V8 heap for values/objects (by substring, regex or
        constructor name), optionally with retainer paths."""
        return _j(_get().objects(session=session, contains=contains, regex=regex,
                                 ctor=ctor, limit=limit, with_retainers=with_retainers))

    @mcp.tool()
    def sbi_object(heap_object_id: str, session: str = None) -> str:
        """Resolve a heap snapshot object id back to the live object; preview properties."""
        return _j(_get().object(heap_object_id, session=session))

    @mcp.tool()
    def sbi_origin(value: str, session: str = None, depth: int = 4) -> str:
        """Find where a value lives in the heap and who retains it."""
        return _j(_get().origin(value, session=session, depth=depth))

    @mcp.tool()
    def sbi_strings(decoder_expr: str, n: int = 32, session: str = None) -> str:
        """Dump an obfuscated/rotated string table by driving the page's real
        decoder over indices 0..n-1 (runtime truth, not source order)."""
        return _j(_get().strings(decoder_expr, n=n, session=session))

    @mcp.tool()
    def sbi_probe(action: str = "drain", names: list = None, session: str = None) -> str:
        """Boundary recorders (crypto/eval/net): action=install|drain."""
        s = _get()
        if action == "install":
            s.probe_install(names or ("crypto", "eval", "net"), session=session)
            return _j({"ok": True, "installed": names})
        return _j(s.probe_drain(session=session))

    @mcp.tool()
    def sbi_grep(needle: str, regex: bool = False) -> str:
        """Search hook captures and network records/bodies for a value."""
        return _j(_get().grep(needle, regex=regex))

    @mcp.tool()
    def sbi_heapdiff(action: str, session: str = None, limit: int = 25) -> str:
        """Snapshot the heap, run `action` (JS) in the page, snapshot again:
        the nodes the action allocated, with retainer paths (the material
        trail — decoded secrets, payload objects)."""
        return _j(_get().heapdiff(action=action, session=session, limit=limit))

    @mcp.tool()
    def sbi_patch(heap_object_id: str, prop: str, value, session: str = None) -> str:
        """Mutate a property of a closure-held object found via sbi_objects/
        sbi_origin. Behaviour flips in place — proof you found the real state."""
        return _j(_get().patch(heap_object_id, prop, value, session=session))

    @mcp.tool()
    def sbi_functions(contains: str = None, regex: str = None, session: str = None,
                      limit: int = 25) -> str:
        """Index live closures by name with url + function location — includes
        closures unreachable from window. Hook targets, found."""
        return _j(_get().functions(contains=contains, regex=regex, session=session, limit=limit))

    @mcp.tool()
    def sbi_coverage(action: str = "take", session: str = None) -> str:
        """'start' before the interesting action, 'take' for executed functions
        ranked by call count, 'stop' when done. Coverage-guided hooking."""
        return _j(_get().coverage(action, session=session))

    @mcp.tool()
    def sbi_follow(label: str, depth: int = 4, limit: int = 5, session: str = None) -> str:
        """Follow a hooked producer's captured outputs into the heap: which
        objects/functions hold them downstream."""
        return _j(_get().follow(label, depth=depth, limit=limit, session=session))

    @mcp.tool()
    def sbi_vm(session: str = None) -> str:
        """Format arg-captures of a hooked bytecode-VM dispatch loop as steps
        plus an opcode-ish histogram."""
        s = _get()
        return _j({"steps": s.vm_steps(), "histogram": s.vm_histogram()})

    @mcp.tool()
    def sbi_audit(target_url: str = None) -> str:
        """Check every hook left no trace: toString identity + own-prop drift
        vs the baseline recorded at hook time."""
        return _j(_get().audit(target_url=target_url))

    @mcp.tool()
    def sbi_blackbox(patterns: list) -> str:
        """Skip vendor/framework url patterns in stacks and stepping."""
        return _j(_get().blackbox(patterns))

    @mcp.tool()
    def sbi_dump_scripts(directory: str, session: str = None) -> str:
        """Write every parsed script's source to files for static analysis."""
        return _j(_get().dump_scripts(directory, session=session))

    @mcp.tool()
    def sbi_report(path: str) -> str:
        """Render the current session state to a markdown report file."""
        return _j(_get().report(path))

    @mcp.tool()
    def sbi_auto_hook(top: int = 5, contains: str = None, url_contains: str = None,
                      capture_returns: bool = False) -> str:
        """Hook the functions that actually ran (coverage-ranked) by live
        object — covers closures unreachable from window. Run
        sbi_coverage start + the action first."""
        return _j(_get().auto_hook(top=top, contains=contains,
                                   url_contains=url_contains,
                                   capture_returns=capture_returns))

    @mcp.tool()
    def sbi_watch(expression: str, seconds: float = 10.0, interval: float = 0.5,
                  target_url: str = None) -> str:
        """Poll an expression and record every change (token rotation,
        counters, mutating state)."""
        return _j(_get().watch(expression, seconds=seconds, interval=interval,
                               target_url=target_url))

    @mcp.tool()
    def sbi_trace_value(needle: str, regex: bool = False, heap: bool = False,
                        target_url: str = None) -> str:
        """One value, full journey: hook captures, corpus pairs, network
        records, optionally the heap with holder."""
        return _j(_get().trace_value(needle, regex=regex, heap=heap,
                                     session=target_url))

    @mcp.tool()
    def sbi_new_page(url: str = None) -> str:
        """Open an additional instrumented page; returns its session id."""
        return _j({"session_id": _get().new_page(url)})

    @mcp.tool()
    def sbi_console() -> str:
        """Drain console messages + uncaught exceptions seen so far —
        hostile SDKs leak tells there (anti-debug logs, decode mistakes)."""
        return _j(_get().console())

    @mcp.tool()
    def sbi_cookies(urls: list = None, session: str = None) -> str:
        """Session cookies (name/value/domain); pass `urls` to read another
        origin's cookies (getCookies is page-scoped by default)."""
        return _j(_get().cookies(urls=urls, session=session))

    @mcp.tool()
    def sbi_storage(session: str = None) -> str:
        """localStorage + sessionStorage dump (opaque origins report errors)."""
        return _j(_get().storage(session=session))

    @mcp.tool()
    def sbi_screenshot(path: str = None, target_url: str = None) -> str:
        """PNG of the viewport — evidence for the report."""
        return _j({"path": _get().screenshot(path, target_url=target_url)})

    @mcp.tool()
    def sbi_click(selector: str = None, x: float = None, y: float = None,
                  target_url: str = None) -> str:
        """Trusted click: by CSS selector (center of first match) or raw x/y."""
        s = _get()
        if selector:
            xy = s.click_element(selector, target_url=target_url)
        else:
            s.click(x, y, target_url=target_url)
            xy = [x, y]
        return _j({"clicked_at": xy})

    @mcp.tool()
    def sbi_type(text: str, target_url: str = None) -> str:
        """Type text into the focused element (IME-safe insertText)."""
        _get().type_text(text, target_url=target_url)
        return _j({"typed": len(text)})

    @mcp.tool()
    def sbi_intercept(pattern: str, status: int = 200, body: str = "",
                      headers: dict = None, abort: bool = False,
                      passthrough: bool = False,
                      content_type: str = "application/json",
                      stage: str = "request", modify: dict = None,
                      edit: list = None) -> str:
        """Mock/abort/passthrough/edit requests (Fetch domain).
        stage='request': mock, abort, or continue with edits
        (modify={url, method, headers, body}). stage='response': body replaces
        the response; edit=[(regex, replace), ...] rewrites the ORIGINAL body
        on the way through. headers adds extra response headers."""
        n = _get().intercept(pattern, status=status, body=body, headers=headers,
                             abort=abort, passthrough=passthrough,
                             content_type=content_type, stage=stage,
                             modify=modify, edit=edit)
        return _j({"rules": n})

    @mcp.tool()
    def sbi_clear_intercepts() -> str:
        """Remove all interception rules and disable the Fetch domain."""
        _get().clear_intercepts()
        return _j({"cleared": True})

    @mcp.tool()
    def sbi_dialogs(policy: str = None) -> str:
        """With no args: drain recorded JS dialogs (alert/confirm/prompt/
        beforeunload). With policy 'accept'/'dismiss': auto-answer dialogs
        from the event thread so an alert() storm can't stall the session."""
        s = _get()
        if policy is not None:
            s.set_dialog_policy(policy)
            return _j({"policy": policy})
        return _j(s.dialogs())

    @mcp.tool()
    def sbi_emulate(kind: str, value: str = None, width: int = None,
                    height: int = None, mobile: bool = False,
                    target_url: str = None) -> str:
        """Per-session emulation: kind 'locale' (e.g. de-DE), 'timezone'
        (e.g. Europe/Berlin), 'device' (width/height/mobile), 'ua' (value =
        user agent string), 'script' (value 'on'/'off'). In-page visible;
        may conflict with the gateway's fingerprint stack."""
        s = _get()
        sid = target_url
        if kind == "locale":
            s.emulate_locale(value, session=sid)
        elif kind == "timezone":
            s.emulate_timezone(value, session=sid)
        elif kind == "device":
            s.emulate_device(width, height, mobile=mobile, session=sid)
        elif kind == "ua":
            s.emulate_ua(value, session=sid)
        elif kind == "script":
            s.set_script_execution(value != "off", session=sid)
        else:
            return _j({"error": f"unknown kind {kind!r}"})
        return _j({"emulated": kind, "value": value})

    @mcp.tool()
    def sbi_doctor() -> str:
        """Readiness self-check: deps, token, endpoint, browser reachability."""
        from . import doctor
        return _j(doctor.check(os.environ.get("SCRAPELESS_CDP_URL"),
                               os.environ.get("SCRAPELESS_API_TOKEN")))

    @mcp.tool()
    def sbi_reconnect() -> str:
        """Rebuild the transport after a websocket drop and re-arm hooks,
        probes, blackbox, dialog policy and intercept rules. Corpora survive;
        heap state is inherently gone."""
        return _j(_get().reconnect())

    @mcp.tool()
    def sbi_metrics(target_url: str = None) -> str:
        """Runtime counters: heap sizes, listeners, frames — bloat/loop detectors."""
        return _j(_get().metrics(target_url))

    @mcp.tool()
    def sbi_profile(action: str, target_url: str = None, top: int = 15) -> str:
        """CPU-profile while `action` runs; hottest functions by sample hits.
        Coverage counts calls, this counts time."""
        return _j(_get().profile(action, session=target_url, top=top))

    @mcp.tool()
    def sbi_pdf(path: str = None, target_url: str = None) -> str:
        """Print-to-PDF evidence (headless builds only)."""
        return _j({"path": _get().pdf(path, target_url=target_url)})

    @mcp.tool()
    def sbi_network_conditions(latency_ms: int = 0, download_kbps: float = -1,
                               upload_kbps: float = -1, offline: bool = False,
                               target_url: str = None) -> str:
        """Emulate network conditions (throughput kbps, -1 = default) or cut
        the network (offline=true). Feed the SDK a 3G link / outage and watch
        its retry logic."""
        _get().throttle(latency_ms, download_kbps, upload_kbps, session=target_url)
        if offline:
            _get().offline(True, session=target_url)
        return _j({"latency_ms": latency_ms, "offline": offline})

    @mcp.tool()
    def sbi_geolocation(lat: float = None, lon: float = None, accuracy: float = 100,
                         target_url: str = None) -> str:
        """Override geolocation (pair with sbi_grant_permissions); lat=None clears."""
        _get().geolocation(lat, lon, accuracy, session=target_url)
        return _j({"lat": lat, "lon": lon})

    @mcp.tool()
    def sbi_grant_permissions(permissions: list, origin: str = None) -> str:
        """Browser-level permission grants, e.g. ['geolocation', 'clipboard-read']."""
        _get().grant_permissions(permissions, origin)
        return _j({"granted": permissions})

    @mcp.tool()
    def sbi_set_cookie(name: str, value: str, url: str = None, domain: str = None,
                       target_url: str = None) -> str:
        """Plant a cookie; returns success."""
        ok = _get().set_cookie(name, value, url=url, domain=domain, session=target_url)
        return _j({"set": bool(ok), "name": name})

    @mcp.tool()
    def sbi_clear_storage(origin: str, storage_types: str =
                          "cookies,local_storage,session_storage",
                          target_url: str = None) -> str:
        """Wipe an origin's storage — reproducible sessions between runs."""
        _get().clear_storage(origin, storage_types, session=target_url)
        return _j({"cleared": origin})

    @mcp.tool()
    def sbi_wasm_modules(target_url: str = None) -> str:
        """Every loaded WebAssembly module in the target (script id + url) —
        where anti-bot engines hide fingerprint hashes and bytecode VMs."""
        return _j(_get().wasm_modules(target_url))

    @mcp.tool()
    def sbi_wasm_dump(script_id: str, path: str = None, target_url: str = None) -> str:
        """Dump a wasm module's raw bytecode to a .wasm file (wabt/Ghidra-ready)."""
        return _j(_get().wasm_dump(script_id, path, session=target_url))

    @mcp.tool()
    def sbi_wasm_disasm(script_id: str, target_url: str = None) -> str:
        """Full disassembly of a wasm module with extracted function names."""
        return _j(_get().wasm_disassemble(script_id, session=target_url))

    @mcp.tool()
    def sbi_wasm_from_network(directory: str) -> str:
        """Dump every wasm module captured on the wire (the reliable route:
        production wasm arrives via instantiateStreaming)."""
        return _j(_get().wasm_from_network(directory))

    @mcp.tool()
    def sbi_wasm_meta(module_expr: str, target_url: str = None) -> str:
        """Exports/imports/custom sections of a live wasm Module (or export
        surface of an Instance) from any JS expression."""
        return _j(_get().wasm_meta(module_expr, target_url=target_url))

    @mcp.tool()
    def sbi_collect_script(directory: str, pattern: str = None,
                           script_id: str = None, target_url: str = None) -> str:
        """Collect specific JS/wasm files to disk: every script whose url
        contains `pattern` (e.g. 'shape', 'fingerprint'), or one script_id."""
        return _j(_get().collect_script(directory, pattern=pattern,
                                        script_id=script_id, session=target_url))

    @mcp.tool()
    def sbi_wasm_extract_embedded(js_path: str, directory: str) -> str:
        """Extract wasm modules embedded as base64 inside a collected JS file
        (Shape-class 'seed' scripts), tolerating JS string concatenation."""
        return _j(_get().wasm_extract_embedded(js_path, directory))

    @mcp.tool()
    def sbi_deobfuscate(pattern: str = None, script_id: str = None,
                        source_path: str = None, out_dir: str = None) -> str:
        """Static deobfuscation via webcrack (node): string arrays, control
        flow, unminify, bundle splitting. Pass a url substring or script id
        (collected automatically) or a path on disk."""
        return _j(_get().deobfuscate(pattern=pattern, script_id=script_id,
                                     source_path=source_path, out_dir=out_dir))

    @mcp.tool()
    def sbi_export_har(path: str) -> str:
        """Write captured network traffic as HAR 1.2 (DevTools/Burp-compatible)."""
        return _j(_get().export_har(path))

    @mcp.tool()
    def sbi_save_state(path: str) -> str:
        """Snapshot cookies + local/session storage (storageState-style) for
        restoring an authenticated session later."""
        return _j(_get().save_state(path))

    @mcp.tool()
    def sbi_load_state(path: str) -> str:
        """Restore a state snapshot: cookies via CDP, storage via the page."""
        return _j(_get().load_state(path))

    @mcp.tool()
    def sbi_replay_request(url: str, method: str = "GET", headers: dict = None,
                           body: str = None, target_url: str = None) -> str:
        """Burp-style repeat: send a request from inside the page (its origin,
        its cookies); returns status + body."""
        return _j(_get().replay_request(url, method=method, headers=headers,
                                        body=body, target_url=target_url))

    @mcp.tool()
    def sbi_dom_snapshot(path: str = None, target_url: str = None) -> str:
        """Full serialized DOM to a file."""
        return _j(_get().dom_snapshot(path, target_url=target_url))

    @mcp.tool()
    def sbi_cpu_throttle(rate: float = 1, target_url: str = None) -> str:
        """Slow the CPU Nx — proof-of-work and timing checks surface."""
        _get().cpu_throttle(rate, session=target_url)
        return _j({"rate": rate})

    @mcp.tool()
    def sbi_emulate_media(feature: str, value: str, target_url: str = None) -> str:
        """Emulate media features (prefers-color-scheme, prefers-reduced-motion...)."""
        _get().emulate_media(feature, value, session=target_url)
        return _j({"feature": feature, "value": value})

    @mcp.tool()
    def sbi_cache(action: str = "clear", target_url: str = None) -> str:
        """Cache control: disable | enable | clear — reproducible cold runs."""
        return _j(_get().cache(action, session=target_url))

    @mcp.tool()
    def sbi_bypass_csp(enabled: bool = True, target_url: str = None) -> str:
        """Ignore Content-Security-Policy — set before the load you inject into."""
        _get().bypass_csp(enabled, session=target_url)
        return _j({"bypass_csp": enabled})

    @mcp.tool()
    def sbi_scroll(x: float = 400, y: float = 400, delta_y: int = 600,
                   delta_x: int = 0, target_url: str = None) -> str:
        """Mouse-wheel scroll at viewport coordinates."""
        _get().scroll(x, y, delta_y, delta_x, target_url=target_url)
        return _j({"scrolled": delta_y})

    @mcp.tool()
    def sbi_screenshot_element(selector: str, path: str = None,
                               target_url: str = None) -> str:
        """PNG of a single element, clipped to its bounding rect."""
        return _j(_get().screenshot_element(selector, path, target_url=target_url))

    @mcp.tool()
    def sbi_idb(target_url: str = None) -> str:
        """IndexedDB inventory (names + versions)."""
        return _j(_get().idb(target_url=target_url))

    @mcp.tool()
    def sbi_call_object(heap_object_id: str, function_source: str,
                        args: list = None, target_url: str = None) -> str:
        """Call any JS function against a live heap-resolved object (the
        general form of sbi_patch)."""
        return _j(_get().call_object(heap_object_id, function_source, args,
                                     session=target_url))

    @mcp.tool()
    def sbi_wait_for(expression: str, timeout: float = 10.0, target_url: str = None) -> str:
        """Poll until a JS expression is truthy — no blind sleeps."""
        try:
            value = _get().wait_for(expression, timeout=timeout, target_url=target_url)
            return _j({"ok": True, "value": value})
        except TimeoutError as e:
            return _j({"ok": False, "error": str(e)})

    @mcp.tool()
    def sbi_capture_inputs(label: str, fn_expr: str, inputs: list,
                           target_url: str = None) -> str:
        """Drive the live function with controlled inputs and persist the
        ground truth into the label's corpus (artifacts + offline verify)."""
        return _j(_get().capture_inputs(label, fn_expr, inputs, target_url=target_url))

    @mcp.tool()
    def sbi_type_into(selector: str, text: str, target_url: str = None) -> str:
        """Focus an input by selector and type into it (trusted events)."""
        _get().type_into(selector, text, target_url=target_url)
        return _j({"typed": text})

    @mcp.tool()
    def sbi_load_agent(name: str, source: str) -> str:
        """Frida-style agent injection: run a JS agent in every instrumented
        target (persists across navigations). The agent gets `send(data)` to
        stream messages back and an `rpc` object Python can call."""
        return _j(_get().load_agent(name, source))

    @mcp.tool()
    def sbi_agent_messages(name: str) -> str:
        """Drain messages an agent streamed via send()."""
        return _j(_get().agent_messages(name))

    @mcp.tool()
    def sbi_call_agent(name: str, fn: str, args: list = None,
                       target_url: str = None) -> str:
        """Call an rpc function the agent exported."""
        return _j({"value": _get().call_agent(name, fn, args, target_url=target_url)})

    @mcp.tool()
    def sbi_trace_calls(contains: str, limit: int = 10, target_url: str = None) -> str:
        """frida-trace equivalent: hook every function matching `contains`
        across live closures and log their calls (read via sbi_captures)."""
        return _j(_get().trace_calls(contains, limit=limit, target_url=target_url))

    @mcp.tool()
    def sbi_eval(expression: str, target_url: str = None, await_promise: bool = False) -> str:
        """Evaluate JS in a target page (main world)."""
        return _j({"value": _get().eval(expression, target_url=target_url, await_promise=await_promise)})

    @mcp.tool()
    def sbi_scripts(session: str = None) -> str:
        """Parsed scripts (id -> url) in a target — find what to read or hook."""
        return _j(_get().scripts(session=session))

    @mcp.tool()
    def sbi_source(script_id: str, session: str = None) -> str:
        """Fetch a script's source by id."""
        return _get().source(script_id, session=session)

    @mcp.tool()
    def sbi_save(path: str) -> str:
        """Save captures, corpora and network records to a JSON artifact."""
        doc = _get().save(path)
        return _j({"saved": path, "pairs": {k: len(v) for k, v in (doc.get("pairs") or {}).items()}})

    @mcp.tool()
    def sbi_close() -> str:
        """Close the session (ends the Scrapeless browser session)."""
        global _session
        if _session:
            _session.close()
            _session = None
        return _j({"ok": True})

    mcp.run()


if __name__ == "__main__":
    main()
