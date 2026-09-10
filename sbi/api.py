"""Session facade: one object that wires transport, target graph, hooks,
oracle, heap, probes, network and artifacts together.

    import sbi
    with sbi.attach("https://target/") as s:
        s.hook("window.sign", capture_returns=True, label="sign")
        s.wait(3)
        print(s.verify("window.sign", "(u,p)=>btoa(u+':'+p)", label="sign"))
"""

import json as _json
import os
import re
import tempfile
import time
from urllib.parse import urlencode

from .core.cdp import CDP
from .core.engine import Engine
from .hooks.tracer import Tracer
from .verify.oracle import Oracle
from .page.network import Network
from .analysis import heap as heap_mod
from .analysis import origin as origin_mod
from .deobfuscate import deob as deob_mod
from .hooks import probes as probes_mod
from .artifacts import trace as trace_mod
from .analysis import heapdiff as heapdiff_mod
from .analysis import patch as patch_mod
from .analysis import coverage as coverage_mod
from .analysis import functions as functions_mod
from .analysis import dataflow as dataflow_mod
from .artifacts import report as report_mod
from .hooks import audit as audit_mod
from .artifacts import replay as replay_mod
from .artifacts import sanitize as sanitize_mod
from .page import console as console_mod
from .page import control as control_mod
from .page import intercept as intercept_mod
from .page import dialogs as dialogs_mod
from .page import emulation as emulation_mod
from .deobfuscate import wasm as wasm_mod
from .hooks import agent as agent_mod
from .deobfuscate import deobf as deobf_mod

SCRAPELESS_WSS = "wss://browser.scrapeless.com/api/v2/browser"


def endpoint(token=None, cdp=None, proxy_country=None, session_ttl=None,
             session_name=None, session_recording=False, extra=None):
    """Build the CDP websocket URL. Explicit `cdp` (wss://... or local Chrome
    http://127.0.0.1:9222) wins; otherwise a Scrapeless endpoint is assembled."""
    token = token or os.environ.get("SCRAPELESS_API_TOKEN")
    if not cdp:
        if not token:
            raise RuntimeError(
                "no endpoint: pass cdp=..., token=..., or set SCRAPELESS_API_TOKEN")
        params = {"token": token}
        if proxy_country:
            params["proxyCountry"] = proxy_country
        if session_ttl:
            params["sessionTTL"] = int(session_ttl)
        if session_name:
            params["sessionName"] = session_name
        params["sessionRecording"] = "true" if session_recording else "false"
        params.update(extra or {})
        cdp = f"{SCRAPELESS_WSS}?{urlencode(params)}"
    elif cdp.startswith("http://") or cdp.startswith("https://"):
        # local/remote Chrome devtools http endpoint -> browser websocket url
        import urllib.request
        with urllib.request.urlopen(cdp.rstrip("/") + "/json/version", timeout=10) as r:
            cdp = _json.load(r)["webSocketDebuggerUrl"]
    return cdp


def attach(url=None, *, token=None, cdp=None, proxy_country=None, session_ttl=300,
           session_name="sbi", probes=None, wait=3, connect_timeout=45):
    """Connect to a Scrapeless session (or any CDP endpoint), open a page,
    optionally navigate. Returns a Session (context-manager friendly)."""
    cdp = cdp or os.environ.get("SCRAPELESS_CDP_URL")
    ws_url = endpoint(token=token, cdp=cdp, proxy_country=proxy_country,
                      session_ttl=session_ttl, session_name=session_name)
    c = CDP(ws_url).connect(timeout=connect_timeout)
    session = Session(c, probes=probes)
    session.start()
    if url:
        session.navigate(url)
        session.wait(wait)
    return session


class Session:
    def __init__(self, cdp, probes=None):
        self.cdp = cdp
        self.engine = Engine(cdp, probes=probes)
        self.tracer = Tracer().attach(self.engine)
        self.oracle = Oracle(self.engine, self.tracer)
        self.network = Network(self.engine)
        self._console = console_mod.Console(cdp)
        self._dialogs = dialogs_mod.Dialogs(cdp)
        self._agents = agent_mod.Agents(cdp)
        self.interceptor = intercept_mod.Interceptor(cdp)
        self._emulation = []            # (method, kwargs) replay log for reconnect

    def start(self):
        self.engine.start()
        return self

    # -- navigation / time ----------------------------------------------------

    def navigate(self, url):
        return self.engine.navigate(url)

    def new_page(self, url=None):
        """Open an additional instrumented page; returns its session id.
        Hook/eval it by url substring once it has a url."""
        return self.engine.new_page(url)

    def wait(self, seconds):
        time.sleep(seconds)     # events flow on their own threads
        return self

    def inject(self, html, target_url=None):
        """Write a page into the current document (the reliable pattern for
        test targets; top-level data: navigation is blocked in Chrome)."""
        return self.eval(f"document.write({_json.dumps(html)})", target_url=target_url)

    def eval(self, expression, target_url=None, await_promise=False):
        sid = self.engine.resolve_session(target_url)
        r = self.cdp.send("Runtime.evaluate",
                          {"expression": expression, "returnByValue": True,
                           "awaitPromise": await_promise, "silent": True},
                          session_id=sid)
        if r.get("exceptionDetails"):
            d = r["exceptionDetails"]
            raise RuntimeError((d.get("exception") or {}).get("description") or d.get("text"))
        res = r.get("result", {})
        return res.get("value", res.get("description"))

    # -- hooks / captures --------------------------------------------------------

    def hook(self, expression, target_url=None, capture_returns=False, label=None):
        """`expression@@url-substring` also accepted, e.g. 'enc@@worker.js'."""
        if expression and "@@" in expression:
            expression, target_url = expression.split("@@", 1)
        return self.tracer.hook(expression, target_url=target_url,
                                capture_returns=capture_returns, label=label)

    def captures(self, label=None):
        if label is None:
            with self.tracer.lock:
                return list(self.tracer.captures)
        return self.tracer.corpus(label)

    def corpus(self, label):
        return self.tracer.corpus(label)

    def corpora(self):
        return self.oracle.corpora()

    def load_trace(self, path):
        doc = trace_mod.load(path)
        for label, pairs in (doc.get("pairs") or {}).items():
            self.oracle.load_corpus(label, pairs)
        return doc

    # -- the oracle -----------------------------------------------------------------

    def verify(self, fn_expr, candidate, label=None, fresh_inputs=None, target_url=None, **kw):
        """kw may include mode ('exact'|'loose_string'|'numeric'|
        'time_tolerant') and the matching tolerances tol/rel/seconds."""
        return self.oracle.verify(fn_expr, candidate, label=label, fresh_inputs=fresh_inputs,
                                  target_url=target_url, **kw)

    def replay(self, path_or_doc):
        """Re-establish a saved trace's hooks on this fresh session."""
        doc = trace_mod.load(path_or_doc) if isinstance(path_or_doc, str) else path_or_doc
        return replay_mod.apply(self, doc)

    def offline_verify(self, trace_path, label, candidate):
        return trace_mod.offline_verify(trace_path, label, candidate)

    # -- heap / origin ------------------------------------------------------------

    def objects(self, session=None, **kw):
        sid = self.engine.resolve_session(session)
        return heap_mod.search(self.cdp, sid, **kw)

    def object(self, heap_object_id, session=None, **kw):
        sid = self.engine.resolve_session(session)
        return heap_mod.get_object(self.cdp, sid, heap_object_id, **kw)

    def origin(self, value_substring, session=None, depth=4, limit=25):
        """Heap matches + who holds them + what allocated them."""
        sid = self.engine.resolve_session(session)
        found = heap_mod.search(self.cdp, sid, contains=value_substring,
                                limit=limit, with_retainers=depth)
        return found

    # -- advanced instrumentation ---------------------------------------------

    def heapdiff(self, action=None, session=None, limit=25, with_retainers=2):
        """Snapshot -> run `action` (JS) -> snapshot; return the nodes the action
        allocated, with retainer paths."""
        sid = self.engine.resolve_session(session)
        return heapdiff_mod.diff(self.cdp, sid, action=action, limit=limit,
                                 with_retainers=with_retainers)

    def patch(self, heap_object_id, prop, value, session=None):
        """Mutate a property of a closure-held object found via the heap.
        Behaviour flips in place — the proof you found the real state."""
        sid = self.engine.resolve_session(session)
        return patch_mod.set_property(self.cdp, sid, heap_object_id, prop, value)

    def patch_get(self, heap_object_id, prop, session=None):
        sid = self.engine.resolve_session(session)
        return patch_mod.get_property(self.cdp, sid, heap_object_id, prop)

    def patch_function(self, heap_object_id, prop, function_source, session=None):
        """Overt: replace a function-valued property by eval'ing new source."""
        sid = self.engine.resolve_session(session)
        return patch_mod.set_function(self.cdp, sid, heap_object_id, prop, function_source)

    def functions(self, contains=None, regex=None, session=None, limit=25):
        """Index live closures by name with url + [[FunctionLocation]] — from
        heap nodes, so closures unreachable from window are included."""
        sid = self.engine.resolve_session(session)
        return functions_mod.index(self.cdp, sid, engine=self.engine,
                                   contains=contains, regex=regex, limit=limit)

    def coverage(self, action="take", session=None, **kw):
        """'start' before the interesting action; 'take' for executed functions
        ranked by call count; 'stop' when done."""
        sid = self.engine.resolve_session(session)
        if action == "start":
            coverage_mod.start(self.cdp, sid)
            return {"started": True}
        if action == "stop":
            coverage_mod.stop(self.cdp, sid)
            return {"stopped": True}
        return coverage_mod.take(self.cdp, sid, **kw)

    def auto_hook(self, top=5, contains=None, url_contains=None, session=None,
                  capture_returns=False, min_count=1):
        """Coverage-guided auto-hooking: hook the functions that actually ran
        during the last action — by live object, so closures unreachable from
        window are covered. Needs coverage('start') + action first."""
        sid = self.engine.resolve_session(session)
        ran = coverage_mod.take(self.cdp, sid, only_executed=True,
                                min_count=min_count, limit=top * 6,
                                script_filter=url_contains)
        fns = ran["functions"]
        if contains:
            fns = [f for f in fns if contains.lower() in f["function"].lower()]
        hooked, skipped = [], []
        for f in fns[:top]:
            try:
                idx = functions_mod.index(self.cdp, sid, engine=self.engine,
                                          contains=f["function"], limit=5)
            except Exception:
                idx = {"functions": []}
            cand = next((e for e in idx["functions"]
                         if e["name"] == f["function"] and e.get("live_object_id")), None)
            if not cand:
                skipped.append({"function": f["function"], "reason": "closure not resolvable"})
                continue
            self.tracer.hook_remote(cand["live_object_id"], sid=sid,
                                    label=f"auto:{f['function']}",
                                    capture_returns=capture_returns)
            hooked.append({"label": f"auto:{f['function']}", "count": f["count"],
                           "url": f["url"]})
        return {"hooked": hooked, "skipped": skipped}

    def watch(self, expression, seconds=10.0, interval=0.5, target_url=None):
        """Poll an expression and record every change — token rotation,
        counters, mutating state. Consecutive equal values are collapsed."""
        end = time.time() + seconds
        changes, last = [], object()
        while time.time() < end:
            try:
                value = self.eval(expression, target_url=target_url)
            except Exception as e:
                value = f"<error: {e}>"
            if value != last:
                changes.append({"t": round(time.time(), 3), "value": value})
                last = value
            time.sleep(min(interval, max(0.01, end - time.time())))
        return {"expression": expression, "changes": changes}

    def trace_value(self, needle, regex=False, heap=False, session=None, limit=10):
        """One value, full journey: hook captures, corpus pairs, network
        records, optionally the heap (with holder). The correlation view."""
        g = self.grep(needle, regex=regex)
        res = {"value": needle, "hook_captures": g["hook_captures"],
               "pairs": g["pairs"], "network": g["network"]}
        if heap:
            sid = self.engine.resolve_session(session)
            res["heap"] = heap_mod.search(self.cdp, sid,
                                          contains=None if regex else needle,
                                          regex=needle if regex else None,
                                          limit=limit)["matches"]
        return res

    def follow(self, label, depth=4, limit=5, session=None):
        """Follow a producer's captured outputs into the heap: who holds them."""
        return dataflow_mod.follow(self, label, depth=depth, limit=limit,
                                   target_session=session)

    def vm_steps(self, label=None):
        """Format arg-captures as VM dispatch steps (pc, opcode, operand)."""
        return deob_mod.vm_steps(self.captures())

    def vm_histogram(self, arg_index=1):
        return deob_mod.vm_histogram(self.captures(), arg_index=arg_index)

    def audit(self, target_url=None):
        """Post-hook integrity check: toString identity + own-prop drift."""
        return audit_mod.check(self, target_url=target_url)

    def blackbox(self, patterns):
        """Skip vendor/framework scripts in stacks and stepping."""
        self.engine.set_blackbox(patterns)
        return {"blackbox": patterns}

    def dump_scripts(self, directory, session=None):
        """Write every parsed script's source to files, for static analysis."""
        import os
        sid = self.engine.resolve_session(session)
        os.makedirs(directory, exist_ok=True)
        written = []
        for (psid, script_id), info in list(self.engine.scripts.items()):
            if psid != sid:
                continue
            url = info.get("url", "") if isinstance(info, dict) else info
            try:
                src = self.cdp.send("Debugger.getScriptSource", {"scriptId": script_id},
                                    session_id=sid).get("scriptSource", "")
            except Exception:
                continue
            name = (url or f"inline-{script_id}").replace("://", "_").replace("/", "_").replace("?", "_")[:120]
            path = os.path.join(directory, f"{script_id}-{name or 'anon'}.js")
            with open(path, "w", encoding="utf-8") as f:
                f.write(src)
            written.append({"script_id": script_id, "url": url, "path": path})
        return written

    def report(self, path):
        """Render the current state to a markdown report file."""
        with self.tracer.lock:
            pairs = {k: list(v) for k, v in self.tracer.pairs.items()}
        doc = {
            "meta": {"ws_endpoint": self.cdp.ws_url, "targets": self.engine.targets()},
            "hooks": self.tracer.hooks, "pairs": pairs,
            "captures": self.captures(), "network": self.network_records(),
            "extra": {"console": self._console.drain(), "dialogs": self._dialogs.drain()},
        }
        md = report_mod.markdown(doc)
        with open(path, "w", encoding="utf-8") as f:
            f.write(md)
        return {"report": path, "bytes": len(md)}

    def repl(self, banner=None):
        """Interactive shell bound to this session (`s`), for manual RE."""
        import code
        code.interact(banner=banner or
                      "sbi REPL — `s` is the live Session "
                      "(s.hook / s.captures / s.verify / s.objects / ...)",
                      local={"s": self, "sbi": __import__("sbi")})

    def allocations_start(self, session=None, interval=16384):
        return origin_mod.sampling_start(self.cdp, self.engine.resolve_session(session), interval)

    def allocations_stop(self, session=None, **kw):
        return origin_mod.sampling_stop(self.cdp, self.engine.resolve_session(session), **kw)

    # -- boundary probes / deob ------------------------------------------------

    def probe_install(self, names=("crypto", "eval", "net"), session=None):
        sid = self.engine.resolve_session(session)
        probes_mod.install(self.cdp, sid, names)

    def probe_drain(self, session=None):
        return probes_mod.drain(self.cdp, self.engine.resolve_session(session))

    def strings(self, decoder_expr, n=32, session=None):
        return deob_mod.dump_strings(self.cdp, self.engine.resolve_session(session),
                                     decoder_expr, indices=range(n))

    # -- network / misc -----------------------------------------------------------

    def network_records(self):
        return self.network.drain()

    def observed_requests(self):
        """Drain requests seen at the Fetch layer — real request headers and
        post bodies included. Arm a passthrough rule first so the pauses fire:
        `s.intercept("*", passthrough=True)`. This recovers request-side values
        (signed headers, form fields) even when the gateway strips them from
        Network-domain output."""
        return self.interceptor.drain_observed()

    def console(self):
        """Drain console messages + uncaught exceptions seen so far."""
        return self._console.drain()

    def dialogs(self):
        """Drain recorded JS dialogs (alert/confirm/prompt/beforeunload)."""
        return self._dialogs.drain()

    def set_dialog_policy(self, policy):
        """None records only; 'accept'/'dismiss' answers dialogs from the
        event thread so an alert() storm can't stall the session."""
        self._dialogs.set_policy(policy)

    def screenshot(self, path=None, target_url=None):
        """PNG of the viewport — evidence for the report."""
        return control_mod.screenshot(self.cdp, self.engine.resolve_session(target_url), path)

    def click(self, x, y, target_url=None):
        """Trusted mouse click at viewport coordinates."""
        control_mod.click(self.cdp, self.engine.resolve_session(target_url), x, y)

    def click_element(self, selector, target_url=None):
        """Trusted click on the center of the first element matching selector."""
        return control_mod.click_element(self.cdp,
                                         self.engine.resolve_session(target_url), selector)

    def type_text(self, text, target_url=None):
        """Type into the focused element."""
        control_mod.type_text(self.cdp, self.engine.resolve_session(target_url), text)

    def press_key(self, key, target_url=None):
        control_mod.press_key(self.cdp, self.engine.resolve_session(target_url), key)

    def cookies(self, urls=None, session=None):
        """Cookies visible to the target; pass `urls` for another origin."""
        return control_mod.cookies(self.cdp, self.engine.resolve_session(session), urls)

    def storage(self, session=None):
        """localStorage + sessionStorage dump (may report per-store errors on
        opaque origins)."""
        return control_mod.storage(self.cdp, self.engine.resolve_session(session))

    def intercept(self, pattern, *, status=200, body="", headers=None,
                  content_type="application/json", abort=False,
                  passthrough=False, stage="request", modify=None, edit=None,
                  session=None):
        """Mock/abort/passthrough/edit requests matching `pattern` (Fetch
        domain). stage='request': mock, abort, or continue with edits
        (modify={url, method, headers, body}). stage='response': replace the
        body on the way out. The page only sees the result."""
        sid = self.engine.resolve_session(session)
        return self.interceptor.add(sid, pattern, status=status, body=body,
                                    headers=headers, content_type=content_type,
                                    abort=abort, passthrough=passthrough,
                                    stage=stage, modify=modify, edit=edit)

    def clear_intercepts(self, session=None):
        sid = self.engine.resolve_session(session) if session else None
        self.interceptor.clear(sid)
        if sid is None:
            self.interceptor.rule_log.clear()

    # -- emulation (per-session, in-page visible; can conflict with the
    #    gateway's own fingerprint stack — caller's choice) -------------------

    def _remember_emulation(self, method, **kwargs):
        # ordered log so reconnect() can replay overrides that would otherwise
        # be lost with the old session; order is preserved so set-then-clear
        # reproduces the same final state
        self._emulation.append((method, kwargs))

    def emulate_ua(self, user_agent, metadata=None, session=None):
        self._remember_emulation("emulate_ua", user_agent=user_agent,
                                 metadata=metadata, session=session)
        emulation_mod.set_user_agent(self.cdp, self.engine.resolve_session(session),
                                     user_agent, metadata)

    def emulate_locale(self, locale, session=None):
        self._remember_emulation("emulate_locale", locale=locale, session=session)
        emulation_mod.set_locale(self.cdp, self.engine.resolve_session(session), locale)

    def emulate_timezone(self, timezone_id, session=None):
        self._remember_emulation("emulate_timezone", timezone_id=timezone_id,
                                 session=session)
        emulation_mod.set_timezone(self.cdp, self.engine.resolve_session(session),
                                   timezone_id)

    def emulate_device(self, width, height, mobile=False, scale=1, session=None):
        self._remember_emulation("emulate_device", width=width, height=height,
                                 mobile=mobile, scale=scale, session=session)
        emulation_mod.set_device(self.cdp, self.engine.resolve_session(session),
                                 width, height, mobile=mobile, scale=scale)

    def clear_emulated_device(self, session=None):
        self._remember_emulation("clear_emulated_device", session=session)
        emulation_mod.clear_device(self.cdp, self.engine.resolve_session(session))

    def set_script_execution(self, enabled, session=None):
        """Watch the page behave with its JS disabled."""
        self._remember_emulation("set_script_execution", enabled=enabled, session=session)
        emulation_mod.set_script_execution(self.cdp,
                                           self.engine.resolve_session(session), enabled)

    # -- resilience & visibility ----------------------------------------------

    def reconnect(self, ws_url=None, wait=1.0):
        """Rebuild the transport after a drop and re-arm what was set up on it:
        hooks (expression-armed ones), boundary probes, blackbox, dialog
        policy, intercept rules, loaded agents, and per-session emulation
        overrides (UA/locale/timezone/device). Corpora and captures survive;
        heap state and object ids are inherently gone with the old session."""
        old_hooks = [dict(h) for h in self.tracer.hooks]
        old_pairs = self.tracer.corpora()
        old_captures = self.captures()
        old_blackbox = self.engine.blackbox
        old_probes = list(self.engine.probes)
        old_dialog_policy = self._dialogs.auto
        old_rules = list(self.interceptor.rule_log)
        old_agents = [(name, source,
                       self._agents.agents.get(name, {}).get("callback"))
                      for (name, source) in self.engine.agents]
        old_emulation = list(self._emulation)
        try:
            self.cdp.close()
        except Exception:
            pass
        cdp = CDP(ws_url or self.cdp.ws_url).connect()
        Session.__init__(self, cdp, probes=old_probes)
        self.start()
        self.tracer.captures = old_captures
        for label, pairs in old_pairs.items():
            self.tracer.pairs[label] = list(pairs)
        rehooked, skipped = [], []
        for h in old_hooks:
            if not h.get("expression"):
                skipped.append({"label": h["label"],
                                "reason": "object-armed hook can't re-arm"})
                continue
            self.tracer.hook(h["expression"], target_url=h.get("target_url"),
                             capture_returns=h.get("returns"), label=h["label"])
            rehooked.append(h["label"])
        if old_blackbox:
            self.engine.set_blackbox(old_blackbox)
        if old_dialog_policy:
            self._dialogs.set_policy(old_dialog_policy)
        for pattern, kwargs in old_rules:
            # the facade's `session` is a url substring; reconnect re-adds to
            # the new page session directly
            self.interceptor.add(self.engine.page_session, pattern, **kwargs)
        for name, source, callback in old_agents:
            # re-inject each agent; the engine also re-installs it on every
            # target it auto-attaches to from here
            self.load_agent(name, source, on_message=callback)
        for method, kwargs in old_emulation:
            # replay overrides in order onto the fresh session
            try:
                getattr(self, method)(**kwargs)
            except Exception:
                pass
        return {"hooked": rehooked, "skipped": skipped,
                "agents": [n for n, _s, _c in old_agents],
                "emulation": len(old_emulation),
                "corpora": self.corpora()}

    def metrics(self, session=None):
        """Runtime counters: heap sizes, listeners, frames — bloat and loop
        detectors."""
        return control_mod.metrics(self.cdp, self.engine.resolve_session(session))

    def profile(self, action=None, session=None, top=15):
        """CPU-profile while `action` runs; hottest functions by sample hits."""
        return control_mod.profile(self.cdp, self.engine.resolve_session(session),
                                   action=action, top=top)

    def pdf(self, path=None, target_url=None):
        """Print-to-PDF (headless builds only) — evidence for long pages."""
        return control_mod.pdf(self.cdp, self.engine.resolve_session(target_url), path)

    # -- environment control: the SDK under bad conditions --------------------

    def throttle(self, latency_ms=0, download_kbps=-1, upload_kbps=-1, session=None):
        """Emulate network conditions (kbps; -1 = default). Watch retry/backoff."""
        control_mod.throttle(self.cdp, self.engine.resolve_session(session),
                             latency_ms, download_kbps, upload_kbps)

    def offline(self, on=True, session=None):
        """Cut (or restore) the target's network."""
        control_mod.offline(self.cdp, self.engine.resolve_session(session), on)

    def geolocation(self, lat=None, lon=None, accuracy=100, session=None):
        """Override geolocation (pair with grant_permissions); lat=None clears."""
        control_mod.geolocation(self.cdp, self.engine.resolve_session(session),
                                lat, lon, accuracy)

    def grant_permissions(self, permissions, origin=None):
        """Browser-level permission grants, e.g. ['geolocation', 'clipboard-read']."""
        control_mod.grant_permissions(self.cdp, permissions, origin)

    def set_cookie(self, name, value, url=None, domain=None, path="/", session=None):
        return control_mod.set_cookie(self.cdp, self.engine.resolve_session(session),
                                      name, value, url=url, domain=domain, path=path)

    def clear_storage(self, origin, storage_types="cookies,local_storage,session_storage",
                      session=None):
        """Wipe an origin's storage — reproducible sessions between runs."""
        control_mod.clear_storage(self.cdp, self.engine.resolve_session(session),
                                  origin, storage_types)

    # -- static analysis / interoperability ----------------------------------

    def deobfuscate(self, pattern=None, script_id=None, source_path=None,
                    out_dir=None, session=None):
        """Static deobfuscation of a collected script via webcrack (node).
        Accepts a url substring, a script id, or a path on disk."""
        if not source_path:
            saved = self.collect_script(tempfile.mkdtemp(prefix="sbi-src-"),
                                        pattern=pattern, script_id=script_id,
                                        session=session)
            if not saved or "path" not in saved[0]:
                raise RuntimeError(f"no script collected for {pattern or script_id!r}")
            source_path = max(saved, key=lambda s: s.get("bytes", 0))["path"]
        return deobf_mod.deobfuscate(source_path, out_dir)

    def beautify(self, source_path, out_path=None):
        """Format a minified file with prettier (node)."""
        return deobf_mod.beautify(source_path, out_path)

    def export_har(self, path):
        """Write captured network traffic as HAR 1.2 — speaks to every other
        tool (DevTools, Burp, mitmproxy viewers)."""
        with self.network.lock:
            records = list(self.network.records)
            bodies = dict(self.network.bodies)
        entries = []
        rid_to_entry = {}
        for r in records:
            if r.get("kind") == "request":
                e = {"startedDateTime": "", "time": 0,
                     "request": {"method": r.get("method") or "GET",
                                 "url": r.get("url"), "httpVersion": "http/1.1",
                                 "headers": [], "queryString": [],
                                 "headersSize": -1, "bodySize":
                                 len(r.get("post_data") or "")},
                     "response": {"status": 0, "statusText": "", "httpVersion": "http/1.1",
                                  "headers": [], "content": {"size": 0, "mimeType": ""},
                                  "headersSize": -1, "bodySize": -1},
                     "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}}
                if r.get("post_data"):
                    e["request"]["postData"] = {"mimeType": "application/x-www-form-urlencoded",
                                                "text": r["post_data"]}
                entries.append(e)
                rid_to_entry[r.get("request_id")] = e
            elif r.get("kind") == "response":
                e = rid_to_entry.get(r.get("request_id"))
                if e:
                    e["response"]["status"] = r.get("status") or 0
                    e["response"]["headers"] = [
                        {"name": k, "value": v} for k, v in (r.get("headers") or {}).items()]
                    e["response"]["content"]["mimeType"] = r.get("mime") or ""
        for rid, body in bodies.items():
            e = rid_to_entry.get(rid)
            if e:
                e["response"]["content"]["size"] = len(body)
                e["response"]["content"]["text"] = body
        har = {"log": {"version": "1.2", "creator": {"name": "sbi", "version": "0.9.0"},
                       "entries": entries}}
        with open(path, "w", encoding="utf-8") as f:
            _json.dump(har, f, indent=1, default=str)
        return {"har": path, "entries": len(entries)}

    def save_state(self, path, session=None):
        """Snapshot cookies + local/session storage (Playwright storageState
        style) so an authenticated session can be restored later."""
        sid = self.engine.resolve_session(session)
        state = {"cookies": control_mod.cookies(self.cdp, sid),
                 "origins": [{"origin": self.eval("location.origin", target_url=session),
                              "localStorage": _pairs(self.eval(
                                  "JSON.stringify(Object.entries(localStorage))",
                                  target_url=session) or "[]"),
                             "sessionStorage": _pairs(self.eval(
                                 "JSON.stringify(Object.entries(sessionStorage))",
                                 target_url=session) or "[]")}]}
        with open(path, "w", encoding="utf-8") as f:
            _json.dump(state, f, indent=2)
        return {"path": path, "cookies": len(state["cookies"])}

    def load_state(self, path, session=None):
        """Restore a state snapshot: cookies via CDP, storage via the page."""
        sid = self.engine.resolve_session(session)
        with open(path, "r", encoding="utf-8") as f:
            state = _json.load(f)
        restored = {"cookies": 0, "localStorage": 0, "sessionStorage": 0}
        for c in state.get("cookies", []):
            params = {k: v for k, v in c.items()
                      if k in ("name", "value", "domain", "path", "expires",
                               "httpOnly", "secure", "sameSite")}
            try:
                if self.cdp.send("Network.setCookie", params, session_id=sid).get("success"):
                    restored["cookies"] += 1
            except Exception:
                pass
        for entry in state.get("origins", []):
            origin = entry.get("origin")
            for kind in ("localStorage", "sessionStorage"):
                pairs = entry.get(kind) or []
                if pairs:
                    setter = ("(() => { const o = JSON.parse(%s);"
                              " o.forEach(([k, v]) => %s.setItem(k, v));"
                              " return o.length; })()"
                              % (_json.dumps(_json.dumps(pairs)), kind))
                    try:
                        restored[kind] += int(self.cdp.send(
                            "Runtime.evaluate",
                            {"expression": "/*sbi*/" + setter, "returnByValue": True},
                            session_id=sid).get("result", {}).get("value") or 0)
                    except Exception:
                        pass
        del origin
        return restored

    def replay_request(self, url, method="GET", headers=None, body=None,
                       target_url=None):
        """Burp-style repeat: send a request from inside the page (its origin,
        its cookies) and capture status + body. Overrides welcome."""
        opts = {"method": method, "headers": headers or {}}
        if body is not None:
            opts["body"] = body
        js = ("fetch(%s, %s).then(async r => ({status: r.status,"
              " body: await r.text()}))" % (_json.dumps(url), _json.dumps(opts)))
        sid = self.engine.resolve_session(target_url)
        r = self.cdp.send("Runtime.evaluate",
                          {"expression": "/*sbi*/" + js, "returnByValue": True,
                           "awaitPromise": True, "silent": True},
                          session_id=sid, timeout=60)
        if r.get("exceptionDetails"):
            d = r["exceptionDetails"]
            raise RuntimeError((d.get("exception") or {}).get("description") or d.get("text"))
        value = r.get("result", {}).get("value")
        if isinstance(value, str):
            try:
                value = _json.loads(value)
            except Exception:
                pass
        return value

    def dom_snapshot(self, path=None, target_url=None):
        """Full serialized DOM to a file (the page as the engine sees it)."""
        html = self.eval("document.documentElement.outerHTML", target_url=target_url)
        if path is None:
            import time
            path = f"sbi-dom-{time.strftime('%Y%m%d-%H%M%S')}.html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html or "")
        return {"path": path, "bytes": len(html or "")}

    # -- environment stress -----------------------------------------------------

    def cpu_throttle(self, rate=1, session=None):
        """Slow the CPU Nx — proof-of-work and timing checks surface."""
        control_mod.cpu_throttle(self.cdp, self.engine.resolve_session(session), rate)

    def emulate_media(self, feature, value, session=None):
        """Emulate media features (prefers-color-scheme, prefers-reduced-motion...)."""
        control_mod.emulate_media(self.cdp, self.engine.resolve_session(session),
                                  feature, value)

    def cache(self, action="disable", session=None):
        """'disable' | 'enable' | 'clear' — reproducible cold runs."""
        sid = self.engine.resolve_session(session)
        if action == "disable":
            control_mod.set_cache_disabled(self.cdp, sid, True)
        elif action == "enable":
            control_mod.set_cache_disabled(self.cdp, sid, False)
        elif action == "clear":
            control_mod.clear_browser_cache(self.cdp, sid)
        return {"cache": action}

    def bypass_csp(self, enabled=True, session=None):
        """Ignore Content-Security-Policy — set before the load you inject into."""
        control_mod.bypass_csp(self.cdp, self.engine.resolve_session(session), enabled)

    def scroll(self, x=400, y=400, delta_y=600, delta_x=0, target_url=None):
        """Mouse-wheel scroll at viewport coordinates."""
        control_mod.scroll(self.cdp, self.engine.resolve_session(target_url),
                           x, y, delta_y, delta_x)

    def screenshot_element(self, selector, path=None, target_url=None):
        """PNG of a single element, clipped to its bounding rect."""
        return control_mod.screenshot_element(
            self.cdp, self.engine.resolve_session(target_url), selector, path)

    def idb(self, target_url=None):
        """IndexedDB inventory (names + versions)."""
        return control_mod.idb(self.cdp, self.engine.resolve_session(target_url))

    def call_object(self, heap_object_id, function_source, args=None, session=None):
        """Call any JS function against a live object resolved from the heap
        (the general form of patch)."""
        sid = self.engine.resolve_session(session)
        return control_mod.call_object(self.cdp, sid, heap_object_id,
                                       function_source, args)

    # -- ergonomics ---------------------------------------------------------------

    def frames(self):
        """All frames of the page (same-origin + cross-origin targets):
        iframes appear as their own instrumented sessions via auto-attach."""
        page_url = self.eval("location.href") or ""
        page_iframes = []
        try:
            page_iframes = [{"src": f.get("src"), "id": f.get("id"),
                             "w": f.get("width"), "h": f.get("height")}
                            for f in (_json.loads(self.eval(
                                "JSON.stringify([...document.querySelectorAll('iframe')]"
                                ".map(f => ({src: f.src, id: f.id,"
                                " width: f.width, height: f.height})))") or "[]"))]
        except Exception:
            pass
        iframe_targets = [(sid, info.get("url"), info.get("type"))
                          for sid, info in self.engine.sessions.items()
                          if info.get("type") in ("iframe", "webview")]
        return {"page": page_url[:120], "page_iframes": page_iframes,
                "iframe_targets": [{"session": sid, "url": url, "type": t}
                                   for sid, url, t in iframe_targets]}

    def probe_drain_all(self):
        """Drain boundary probes from EVERY instrumented session — the
        challenge-iframe's fingerprint reads land in its own session."""
        out = {}
        with self.engine.lock:
            sids = list(self.engine.sessions.keys())
        for sid in sids:
            try:
                recs = probes_mod.drain(self.cdp, sid)
                if recs:
                    out[sid] = recs
            except Exception:
                pass
        return out

    def deep_query(self, selector, limit=20):
        """Shadow-DOM-piercing query: matches through every shadow root,
        returning tag + snippet + the host chain for each match."""
        js = (
            "(() => { const out = []; const sel = " + _json.dumps(selector) + ";"
            " const walk = (root, path) => {"
            "  for (const el of root.querySelectorAll('*')) {"
            "   if (el.shadowRoot) walk(el.shadowRoot, path.concat(el.tagName));"
            "  }"
            "  for (const el of root.querySelectorAll(sel)) {"
            "   if (out.length < " + str(limit) + ") out.push({"
            "     tag: el.tagName, path: path.join(' > '),"
            "     html: el.outerHTML.slice(0, 160)});"
            "  }"
            " };"
            " walk(document, []);"
            " if (!out.length && document.querySelector(sel))"
            "  out.push({tag: document.querySelector(sel).tagName, path: 'document',"
            "   html: document.querySelector(sel).outerHTML.slice(0, 160)});"
            " return JSON.stringify(out); })()"
        )
        try:
            return _json.loads(self.eval("/*sbi*/" + js) or "[]")
        except Exception as e:
            return [{"error": str(e)}]

    def wait_for(self, expression, timeout=10.0, interval=0.1, target_url=None):
        """Poll until a JS expression is truthy — no blind sleeps. Returns the
        truthy value; raises TimeoutError otherwise."""
        end = time.time() + timeout
        last = None
        while time.time() < end:
            try:
                last = self.eval(expression, target_url=target_url)
                if last:
                    return last
            except Exception:
                pass
            time.sleep(min(interval, max(0.01, end - time.time())))
        raise TimeoutError(f"{expression!r} not truthy within {timeout}s (last: {last!r})")

    def wait_for_url(self, substring, timeout=15.0, interval=0.1, target_url=None):
        """Wait until the target's location.href contains `substring`."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                href = self.eval("location.href", target_url=target_url) or ""
                if substring in href:
                    return href
            except Exception:
                pass
            time.sleep(interval)
        raise TimeoutError(f"url never contained {substring!r} within {timeout}s")

    def capture_inputs(self, label, fn_expr, inputs, target_url=None):
        """Drive the live function with controlled inputs and persist the
        (input -> output) ground truth into the label's corpus — artifacts
        and offline verification then carry them."""
        results = self.oracle.query_live(fn_expr, inputs, target_url)
        recs = []
        for inp, out in zip(inputs, results):
            if isinstance(out, dict) and "__error__" in out:
                continue
            recs.append({"input": inp if isinstance(inp, list) else [inp],
                         "output": out})
        self.oracle.load_corpus(label, recs)
        return {"label": label, "captured": len(recs), "errors": len(results) - len(recs)}

    def type_into(self, selector, text, target_url=None):
        """Focus an input by selector and type into it (trusted events)."""
        self.eval(f'{{const el = document.querySelector({_json.dumps(selector)});'
                  f' if (!el) throw new Error("no element {selector}"); el.focus();}}',
                  target_url=target_url)
        self.type_text(text, target_url=target_url)

    # -- webassembly -------------------------------------------------------------

    def load_agent(self, name, source, on_message=None):
        """Frida-style: inject a JS agent into every instrumented target
        (persists across navigations). The agent gets `send(data)` to stream
        messages to Python and an `rpc` object Python can call back."""
        self.engine.agents.append((name, source))
        self._agents.install(self.engine, self.engine.page_session,
                             name, source, on_message)
        return {"agent": name}

    def agent_messages(self, name):
        """Drain messages an agent streamed via send()."""
        return self._agents.drain(name)

    def call_agent(self, name, fn, args=None, target_url=None, await_promise=False):
        """Call an rpc function the agent exported: call_agent('a', 'ping')."""
        sid = self.engine.resolve_session(target_url)
        call = ("window.__sbi_agent_" + name + ".rpc." + fn + "(" +
                ", ".join(_json.dumps(a) for a in (args or [])) + ")")
        r = self.cdp.send("Runtime.evaluate",
                          {"expression": call, "returnByValue": True,
                           "awaitPromise": await_promise, "silent": True},
                          session_id=sid, timeout=30)
        if r.get("exceptionDetails"):
            d = r["exceptionDetails"]
            raise RuntimeError((d.get("exception") or {}).get("description") or d.get("text"))
        return r.get("result", {}).get("value")

    def trace_calls(self, contains, limit=10, session=None, verbose=False):
        """frida-trace equivalent: hook every function whose name contains
        `contains` across live closures (heap-resolved, so window-unreachable
        ones are covered) and log their calls. Returns the hooked labels."""
        import time as _t
        fns = self.functions(contains=contains, session=session, limit=limit)
        if not any(f.get("live_object_id") for f in fns["functions"]):
            _t.sleep(0.6)                     # closures can lag one GC cycle
            fns = self.functions(contains=contains, session=session, limit=limit)
        hooked = []
        sid = self.engine.resolve_session(session)
        for f in fns["functions"]:
            oid = f.get("live_object_id")
            if not oid:
                try:   # fresh resolve per entry: GC races are per-object
                    oid = functions_mod._resolve_location(self.cdp, sid,
                                                          f["heap_object_id"])
                except Exception:
                    oid = None
            if not oid:
                continue
            try:
                h = self.tracer.hook_remote(oid, sid=sid,
                                            label=f"trace:{f['name']}")
                self.tracer.verbose = self.tracer.verbose or verbose
                hooked.append(h["label"])
            except Exception:
                continue
        return {"hooked": hooked, "candidates": len(fns["functions"])}

    def wasm_modules(self, session=None):
        """Every loaded WebAssembly module in the target (script id + url)."""
        return wasm_mod.modules(self.engine, self.engine.resolve_session(session))

    def wasm_dump(self, script_id, path=None, session=None):
        """Dump a wasm module's raw bytecode (debugger route; may be refused
        by the build — prefer wasm_from_network for network-delivered modules)."""
        return wasm_mod.dump(self.cdp, self.engine.resolve_session(session),
                             script_id, path)

    def wasm_from_network(self, directory):
        """Dump every wasm module captured on the wire (the reliable route:
        production wasm arrives via instantiateStreaming)."""
        return wasm_mod.from_network(self.network, directory)

    def wasm_extract_embedded(self, js_path, directory, min_bytes=64):
        """Extract wasm modules embedded as base64 inside a collected JS file
        (Shape-class 'seed' scripts)."""
        return wasm_mod.extract_embedded(js_path, directory, min_bytes=min_bytes)

    def wasm_disassemble(self, script_id, session=None):
        """Full disassembly of a wasm module (experimental Debugger API)."""
        return wasm_mod.disassemble(self.cdp, self.engine.resolve_session(session),
                                    script_id)

    def wasm_meta(self, module_expr, target_url=None):
        """Exports/imports/custom sections of a live wasm Module — or the
        export surface of a live Instance — from any JS expression."""
        return wasm_mod.meta(self.cdp, self.engine.resolve_session(target_url),
                             module_expr)

    def collect_script(self, directory, pattern=None, script_id=None, session=None):
        """Save specific JS/wasm files to disk: every script whose url
        contains `pattern`, or the single `script_id`. Returns saved paths."""
        import os
        sid = self.engine.resolve_session(session)
        os.makedirs(directory, exist_ok=True)
        targets = []
        if script_id is not None:
            info = self.engine.scripts.get((sid, script_id))
            if info:
                targets.append((script_id, info))
        else:
            for (psid, s_id), info in self.engine.scripts.items():
                if psid != sid:
                    continue
                url = info.get("url", "") if isinstance(info, dict) else str(info)
                if pattern and pattern.lower() not in url.lower():
                    continue
                targets.append((s_id, info))
        saved = []
        for s_id, info in targets:
            url = info.get("url", "") if isinstance(info, dict) else str(info)
            try:
                src = self.cdp.send("Debugger.getScriptSource", {"scriptId": s_id},
                                    session_id=sid, timeout=60).get("scriptSource", "")
            except Exception as e:
                saved.append({"script_id": s_id, "url": url, "error": str(e)})
                continue
            safe_url = (url or f"inline-{s_id}").replace("://", "_").replace("/", "_")
            safe_url = "".join(c if c.isalnum() or c in "._-" else "_" for c in safe_url)[:120]
            path = os.path.join(directory, f"{s_id}-{safe_url or 'anon'}.js")
            with open(path, "w", encoding="utf-8") as f:
                f.write(src)
            saved.append({"script_id": s_id, "url": url, "path": path,
                          "bytes": len(src)})
        return saved

    def grep(self, needle, regex=False):
        """Search hook captures, console, network records/bodies, and observed
        Fetch-layer requests (headers + bodies) for a value."""
        needle = str(needle)
        rx = re.compile(needle) if regex else None
        hits = {"hook_captures": [], "pairs": [],
                "console": self._console.grep(needle, regex=regex),
                "network": self.network.grep(needle, regex=regex),
                "intercepted": self.interceptor.grep_observed(needle, regex=regex)}
        with self.tracer.lock:
            for rec in self.tracer.captures:
                if _mentions(rec.get("args"), needle, rx):
                    hits["hook_captures"].append(rec)
            for label, pairs in self.tracer.pairs.items():
                for p in pairs:
                    if _mentions(p.get("input"), needle, rx) or _mentions(p.get("output"), needle, rx):
                        hits["pairs"].append({"label": label, **p})
        return hits

    def targets(self):
        return self.engine.targets()

    def scripts(self, session=None):
        sid = self.engine.resolve_session(session)
        return [{"script_id": s, "url": (i.get("url") if isinstance(i, dict) else i),
                 "language": (i.get("language") if isinstance(i, dict) else "JavaScript")}
                for (psid, s), i in self.engine.scripts.items() if psid == sid]

    def source(self, script_id, session=None):
        sid = self.engine.resolve_session(session)
        return self.cdp.send("Debugger.getScriptSource", {"scriptId": script_id},
                             session_id=sid).get("scriptSource", "")

    # -- artifacts / lifecycle ---------------------------------------------------

    def save(self, path, extra=None, sanitize=False):
        """Write the trace artifact; sanitize=True redacts secrets in place
        (tokens, bearer headers, cookies, high-entropy strings, emails)."""
        extra = dict(extra or {})
        extra.setdefault("console", self._console.drain())
        extra.setdefault("dialogs", self._dialogs.drain())
        meta = {"ws_endpoint": self.cdp.ws_url, "targets": self.engine.targets(),
                "wasm_modules": self.wasm_modules()}
        doc = trace_mod.save(path, meta, self.tracer, self.network, extra=extra)
        if sanitize:
            doc, report = sanitize_mod.sanitize_doc(doc)
            with open(path, "w", encoding="utf-8") as f:
                _json.dump(doc, f, indent=2, default=str)
            doc["sanitize_report"] = report
        return doc

    def close(self):
        try:
            self.oracle.close()
        except Exception:
            pass
        try:
            self.cdp.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _pairs(json_text):
    try:
        return [list(p) for p in _json.loads(json_text or "[]")]
    except Exception:
        return []


def _mentions(value, needle, rx):
    try:
        text = _json.dumps(value, default=str) if not isinstance(value, str) else value
    except Exception:
        text = str(value)
    return (rx.search(text) if rx else needle in text)
