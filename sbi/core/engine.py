"""Session engine: owns the target graph.

One CDP websocket reaches the whole target graph. Flat-mode auto-attach
(Target.setAutoAttach with flatten) cascades from the browser to pages, and
from every page to its workers and out-of-process iframes — which is where the
crypto / anti-bot engines actually run. New targets start paused
(waitForDebuggerOnStart) so boundary probes can be installed *before* any page
script runs, then are released with Runtime.runIfWaitingForDebugger.

Private targets (the oracle's isolated scratch page) are attached with
Runtime only: no Debugger, no probes — candidate code runs in a page that
cannot see the instrumented ones.
"""

import sys
import threading
import time

INSTRUMENTED_TYPES = ("page", "iframe", "webview", "app", "background_page")


def _headless_stealth(user_agent, product):
    """UA + client-hint override for local headless Chrome: still reports
    HeadlessChrome in the UA and hints, an instant tell. (On Scrapeless the
    gateway's fingerprint stack owns this; this only covers direct CDP.)"""
    if "Headless" not in user_agent:
        return None, None
    ua = user_agent.replace("HeadlessChrome", "Chrome")
    full = product.split("Chrome/")[-1] if "Chrome/" in product else "120.0.0.0"
    major = full.split(".")[0]
    grease = "Not)A;Brand"
    platform = {"win32": "Windows", "darwin": "macOS"}.get(sys.platform, "Linux")
    arch = {"darwin": "arm64"}.get(sys.platform, "x86")
    meta = {
        "brands": [{"brand": grease, "version": "24"},
                   {"brand": "Chromium", "version": major},
                   {"brand": "Google Chrome", "version": major}],
        "fullVersionList": [{"brand": grease, "version": "24.0.0.0"},
                            {"brand": "Chromium", "version": full},
                            {"brand": "Google Chrome", "version": full}],
        "platform": platform, "platformVersion": "",
        "architecture": arch, "model": "", "mobile": False,
    }
    return ua, meta


class Engine:
    def __init__(self, cdp, probes=None):
        self.cdp = cdp
        self.sessions = {}              # sessionId -> targetInfo
        self.page_session = None
        self.page_target = None
        self.private = set()            # targetIds excluded from instrumentation
        self.scripts = {}               # (sessionId, scriptId) -> {url, language}
        self.probes = list(probes or [])  # names of boundary recorders to install
        self.blackbox = None            # patterns skipped in stacks/stepping
        self.user_agent = None          # set when the UA leaks Headless
        self.ua_metadata = None
        self.agents = []                # (name, source) re-installed per target
        self.lock = threading.Lock()
        self.page_attached = threading.Event()
        self._probe_sources = None
        cdp.on("Target.attachedToTarget", self._attached)
        cdp.on("Target.detachedFromTarget", self._detached)
        cdp.on("Target.targetInfoChanged", self._info_changed)
        cdp.on("Debugger.scriptParsed", self._script_parsed)

    def set_blackbox(self, patterns):
        """Skip framework/vendor frames in stacks and stepping (e.g.
        ['node_modules', 'chunk-vendors']). Applies to live sessions too."""
        self.blackbox = list(patterns)
        with self.lock:
            sids = [sid for sid, info in self.sessions.items()
                    if info.get("targetId") not in self.private]
        for sid in sids:
            try:
                self.cdp.send("Debugger.setBlackboxPatterns",
                              {"patterns": self.blackbox}, session_id=sid)
            except Exception:
                pass

    # -- lifecycle ---------------------------------------------------------

    def start(self):
        try:  # keeps targetInfoChanged flowing so urls stay fresh; some gateways reject it
            self.cdp.send("Target.setDiscoverTargets", {"discover": True})
        except Exception:
            pass
        try:
            version = self.cdp.send("Browser.getVersion")
            self.user_agent, self.ua_metadata = _headless_stealth(
                version.get("userAgent", ""), version.get("product", ""))
        except Exception:
            pass
        # No browser-level setAutoAttach: it would auto-attach the page we're
        # about to attach explicitly, and one target under two Debugger
        # sessions delivers every pause twice. Children (workers, OOPIFs) are
        # picked up by the per-session auto-attach in _enable.
        self.page_target = self.cdp.send("Target.createTarget", {"url": "about:blank"})["targetId"]
        self.cdp.send("Target.attachToTarget", {"targetId": self.page_target, "flatten": True})
        if not self.page_attached.wait(30):
            raise RuntimeError("page target never attached")
        return self

    def new_page(self, url=None):
        """Open an additional instrumented page. Created on about:blank so
        the instrumentation is in place before the real load, then navigated."""
        target = self.cdp.send("Target.createTarget", {"url": "about:blank"})["targetId"]
        sid = self.cdp.send("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
        deadline = time.time() + 15
        while time.time() < deadline:
            with self.lock:
                if sid in self.sessions:
                    break
            time.sleep(0.05)
        with self.lock:
            if sid not in self.sessions:
                raise RuntimeError("new page never attached")
        if url:
            self.cdp.send("Page.navigate", {"url": url}, session_id=sid)
            self.cdp.flush_events(10)   # the url becomes resolvable deterministically
        return sid

    def navigate(self, url):
        if "://" not in url and ":" not in url.split("/", 1)[0]:
            url = "https://" + url     # bare host -> omnibox behaviour
        if url.startswith("data:"):
            # top-level data: navigation is blocked/unreliable in Chrome and
            # attaching to such targets misbehaves; inject instead
            raise ValueError(
                "top-level data: URLs are unreliable in Chrome — navigate "
                "about:blank and inject the page via document.write, or serve "
                "it over http://127.0.0.1 (see examples/crypto_log.py)")
        self.cdp.send("Page.navigate", {"url": url}, session_id=self.page_session)
        return self

    def close(self):
        pass                            # the cloud session ends when the websocket does

    # -- registry ----------------------------------------------------------

    def targets(self):
        with self.lock:
            return [(sid, info.get("type"), info.get("url", ""))
                    for sid, info in self.sessions.items()
                    if info.get("targetId") not in self.private]

    def resolve_session(self, url_substr=None):
        if not url_substr:
            if self.page_session is None:
                raise RuntimeError("page not attached yet")
            return self.page_session
        with self.lock:
            for sid, info in self.sessions.items():
                if info.get("targetId") not in self.private and url_substr in (info.get("url") or ""):
                    return sid
        raise RuntimeError(f"no target url contains {url_substr!r}; known: {self.targets()}")

    def open_isolated_page(self):
        """A page the probes and hooks never touch — for running candidate code."""
        target = self.cdp.send("Target.createTarget", {"url": "about:blank", "background": True})["targetId"]
        with self.lock:
            self.private.add(target)
        sid = self.cdp.send("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
        try:
            self.cdp.send("Runtime.enable", session_id=sid)
        except Exception:
            pass
        return sid

    def close_target(self, sid):
        with self.lock:
            target = self.sessions.get(sid, {}).get("targetId")
        if target:
            try:
                self.cdp.send("Target.closeTarget", {"targetId": target})
            except Exception:
                pass

    # -- event handlers ------------------------------------------------------

    def _attached(self, params, session_id=None):
        sid = params["sessionId"]
        info = params.get("targetInfo", {})
        with self.lock:
            if sid in self.sessions:
                return
            duplicate = any(i.get("targetId") == info.get("targetId")
                            for i in self.sessions.values())
            if not duplicate:
                self.sessions[sid] = info
                is_private = info.get("targetId") in self.private
        if duplicate:
            # the same target is already instrumented under another session:
            # release it (it may arrive paused) and never instrument it twice
            try:
                self.cdp.send("Runtime.enable", session_id=sid)
            except Exception:
                pass
            self._run_if_waiting(sid)
            return
        if is_private:
            # candidates run here: reachable, but blind to everything above
            self.cdp.send("Runtime.enable", session_id=sid)
            self._run_if_waiting(sid)
            return
        is_page = info.get("type") in INSTRUMENTED_TYPES
        self._enable(sid, is_page)
        if self._probe_sources is None:
            from ..hooks.probes import build_sources
            self._probe_sources = build_sources(self.probes)
        if is_page and self._probe_sources:
            for src in self._probe_sources:
                try:
                    self.cdp.send("Page.addScriptToEvaluateOnNewDocument", {"source": src},
                                  session_id=sid)
                except Exception:
                    pass
        for name, source in list(self.agents):
            try:
                from ..hooks.agent import install_on_session
                install_on_session(self.cdp, sid, name, source)
            except Exception:
                pass
        if info.get("targetId") == self.page_target:
            self.page_session = sid
            self.page_attached.set()
        self._run_if_waiting(sid)

    def _detached(self, params, session_id=None):
        with self.lock:
            self.sessions.pop(params.get("sessionId"), None)

    def _info_changed(self, params, session_id=None):
        info = params.get("targetInfo", {})
        with self.lock:
            for sid, existing in self.sessions.items():
                if existing.get("targetId") == info.get("targetId"):
                    self.sessions[sid] = info
                    break

    def _script_parsed(self, params, session_id=None):
        if session_id:
            self.scripts[(session_id, params.get("scriptId"))] = {
                "url": params.get("url", ""),
                "language": params.get("scriptLanguage") or
                            ("WebAssembly" if (params.get("url") or "").startswith("wasm-")
                             or (params.get("url") or "").endswith(".wasm") else "JavaScript"),
            }

    # -- helpers -------------------------------------------------------------

    def _enable(self, sid, is_page):
        def enable(method, params=None):
            try:
                self.cdp.send(method, params, session_id=sid)
            except Exception:
                pass
        for domain in ("Runtime", "Debugger", "Network"):
            enable(domain + ".enable")
        if is_page:
            enable("Page.enable")
        if self.user_agent:                  # before any target script runs
            enable("Network.setUserAgentOverride",
                   {"userAgent": self.user_agent, "userAgentMetadata": self.ua_metadata})
        if self.blackbox:
            enable("Debugger.setBlackboxPatterns", {"patterns": self.blackbox})
        enable("Target.setAutoAttach",
               {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True})

    def _run_if_waiting(self, sid):
        try:
            self.cdp.send("Runtime.runIfWaitingForDebugger", session_id=sid)
        except Exception:
            pass

    def script_url(self, sid, script_id):
        info = self.scripts.get((sid, script_id)) or {}
        return info.get("url", "")
