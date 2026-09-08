"""Browser control from the protocol layer: screenshots, input, storage.

No Puppeteer/Playwright in the stack — clicking, typing, screenshots and
storage dumps are plain CDP calls, so they work in the same session the
hooks live in. Input events are untrusted by construction (isTrusted=false
they are not — Input.dispatchMouseEvent events ARE trusted, which is exactly
why they can drive checkout flows a synthetic `.click()` cannot).
"""

import base64
import json as _json


def screenshot(cdp, sid, path=None):
    """PNG of the viewport; writes to path (or alongside the trace) and
    returns the path — evidence for the report. The target is brought to
    front first: a backgrounded tab's compositor may never produce a frame
    and captureScreenshot would wait forever."""
    try:
        cdp.send("Page.bringToFront", session_id=sid, timeout=10)
    except Exception:
        pass  # some targets (workers) have no widget; capture may still work
    r = cdp.send("Page.captureScreenshot",
                 {"format": "png", "captureBeyondViewport": False}, session_id=sid,
                 timeout=30)
    data = base64.b64decode(r.get("data", ""))
    if path is None:
        import time
        path = f"sbi-shot-{time.strftime('%Y%m%d-%H%M%S')}.png"
    with open(path, "wb") as f:
        f.write(data)
    return path


def click(cdp, sid, x, y):
    """Trusted left click at viewport coordinates."""
    for type_ in ("mousePressed", "mouseReleased"):
        cdp.send("Input.dispatchMouseEvent",
                 {"type": type_, "x": int(x), "y": int(y),
                  "button": "left", "clickCount": 1}, session_id=sid)


def click_element(cdp, sid, selector):
    """Click the center of the first element matching `selector`."""
    expr = ("(() => { const el = document.querySelector(%s); if (!el) return null;"
            " const r = el.getBoundingClientRect();"
            " return JSON.stringify([r.x + r.width / 2, r.y + r.height / 2]); })()"
            % _json.dumps(selector))
    r = cdp.send("Runtime.evaluate",
                 {"expression": "/*sbi*/" + expr, "returnByValue": True},
                 session_id=sid)
    val = r.get("result", {}).get("value")
    if not val:
        raise RuntimeError(f"no element matches {selector!r}")
    x, y = _json.loads(val)
    click(cdp, sid, x, y)
    return (x, y)


def type_text(cdp, sid, text):
    """Insert text into the focused element (Input.insertText: IME-safe)."""
    cdp.send("Input.insertText", {"text": text}, session_id=sid)


def press_key(cdp, sid, key, code=None):
    """Raw key down/up (e.g. 'Enter'). `key` is the DOM key value; printable
    keys should prefer type_text."""
    base = {"type": "rawKeyDown", "key": key, "code": code or key}
    cdp.send("Input.dispatchKeyEvent", base, session_id=sid)
    cdp.send("Input.dispatchKeyEvent",
             dict(base, type="keyUp"), session_id=sid)


def cookies(cdp, sid, urls=None):
    """Cookies visible to the target (Network.getCookies is page-scoped;
    pass `urls` to read another origin's cookies)."""
    params = {"urls": urls} if urls else None
    r = cdp.send("Network.getCookies", params, session_id=sid)
    return r.get("cookies", [])


def storage(cdp, sid, origin=None):
    """localStorage + sessionStorage of the target frame. `origin` switches
    the trusted-types-free dump to another frame via its own session."""
    expr = ("JSON.stringify({local: (()=>{try{return Object.fromEntries("
            "Object.entries(localStorage))}catch(e){return {__error__: String(e)}}})(),"
            "session: (()=>{try{return Object.fromEntries("
            "Object.entries(sessionStorage))}catch(e){return {__error__: String(e)}}})()})")
    r = cdp.send("Runtime.evaluate",
                 {"expression": "/*sbi*/" + expr, "returnByValue": True},
                 session_id=sid)
    try:
        return _json.loads(r.get("result", {}).get("value") or "{}")
    except Exception:
        return {"__error__": "unserializable"}


def pdf(cdp, sid, path=None):
    """Print-to-PDF of the target (headless Chrome only — headed builds
    reject PrintToPDF). Evidence for long pages a screenshot can't hold."""
    r = cdp.send("Page.printToPDF", {"printBackground": True}, session_id=sid,
                 timeout=60)
    data = base64.b64decode(r.get("data", ""))
    if path is None:
        import time
        path = f"sbi-page-{time.strftime('%Y%m%d-%H%M%S')}.pdf"
    with open(path, "wb") as f:
        f.write(data)
    return path


def metrics(cdp, sid):
    """Runtime performance counters (heap, documents, frames, listeners)."""
    cdp.send("Performance.enable", session_id=sid)
    m = cdp.send("Performance.getMetrics", session_id=sid).get("metrics", [])
    return {row["name"]: row["value"] for row in m}


def profile(cdp, sid, action=None, top=15, timeout=120):
    """CPU-profile the target while `action` (JS) runs; return the hottest
    functions by sample hits. Coverage counts calls, this counts time —
    the dispatch loop that eats the CPU is the VM, not the noise."""
    cdp.send("Profiler.enable", session_id=sid)
    try:
        cdp.send("Profiler.start", session_id=sid)
        if action:
            cdp.send("Runtime.evaluate",
                     {"expression": action, "awaitPromise": True, "returnByValue": True,
                      "silent": True}, session_id=sid, timeout=timeout)
        stop = cdp.send("Profiler.stop", session_id=sid, timeout=timeout).get("profile", {})
    finally:
        try:
            cdp.send("Profiler.disable", session_id=sid)
        except Exception:
            pass
    hot = []
    for node in stop.get("nodes", []):
        hits = node.get("hitCount", 0) or 0
        if hits > 0:
            frame = node.get("callFrame", {})
            hot.append({"hits": hits, "function": frame.get("functionName") or "<anon>",
                        "url": frame.get("url"), "node_id": node.get("id")})
    hot.sort(key=lambda h: -h["hits"])
    return {"hot": hot[:top], "total_hits": sum(h["hits"] for h in hot)}


# -- environment control: how does the SDK behave under bad conditions? ------

def throttle(cdp, sid, latency_ms=0, download_kbps=-1, upload_kbps=-1):
    """Emulate network conditions (throughput in kbps; -1 keeps the default).
    Feed the SDK a 3G link and watch its retry/backoff logic."""
    cdp.send("Network.emulateNetworkConditions",
             {"offline": False, "latency": latency_ms,
              "downloadThroughput": download_kbps * 125 if download_kbps > 0 else download_kbps,
              "uploadThroughput": upload_kbps * 125 if upload_kbps > 0 else upload_kbps},
             session_id=sid)


def offline(cdp, sid, on=True):
    """Cut the network for the target (or restore it with on=False)."""
    cdp.send("Network.emulateNetworkConditions",
             {"offline": on, "latency": 0,
              "downloadThroughput": -1, "uploadThroughput": -1},
             session_id=sid)


def geolocation(cdp, sid, lat=None, lon=None, accuracy=100):
    """Override the target's geolocation; lat=None clears the override.
    Pair with grant_permissions(['geolocation']) or the page can't read it."""
    if lat is None:
        cdp.send("Emulation.clearGeolocationOverride", session_id=sid)
    else:
        cdp.send("Emulation.setGeolocationOverride",
                 {"latitude": lat, "longitude": lon, "accuracy": accuracy},
                 session_id=sid)


def grant_permissions(cdp, permissions, origin=None):
    """Grant browser permissions (e.g. ['geolocation', 'clipboard-read']) —
    browser-level, not per session."""
    params = {"permissions": list(permissions)}
    if origin:
        params["origin"] = origin
    cdp.send("Browser.grantPermissions", params)


def set_cookie(cdp, sid, name, value, url=None, domain=None, path="/"):
    """Plant a cookie (session-scoped Network domain). Returns success."""
    params = {"name": name, "value": value, "path": path}
    if url:
        params["url"] = url
    if domain:
        params["domain"] = domain
    return bool(cdp.send("Network.setCookie", params, session_id=sid).get("success"))


def clear_storage(cdp, sid, origin, storage_types="cookies,local_storage,session_storage"):
    """Wipe an origin's storage — reproducible sessions between runs."""
    cdp.send("Storage.clearDataForOrigin",
             {"origin": origin, "storageTypes": storage_types}, session_id=sid)


# -- environment stress: how does the SDK behave on a slow machine? ----------

def cpu_throttle(cdp, sid, rate=1):
    """Slow the CPU Nx (proof-of-work and timing checks reveal themselves)."""
    cdp.send("Emulation.setCPUThrottlingRate", {"rate": float(rate)}, session_id=sid)


def emulate_media(cdp, sid, feature, value):
    """Emulate media features: prefers-color-scheme, prefers-reduced-motion..."""
    cdp.send("Emulation.setEmulatedMedia",
             {"features": [{"name": feature, "value": value}]}, session_id=sid)


def set_cache_disabled(cdp, sid, disabled=True):
    cdp.send("Network.setCacheDisabled", {"cacheDisabled": disabled}, session_id=sid)


def clear_browser_cache(cdp, sid):
    cdp.send("Network.clearBrowserCache", session_id=sid)


def bypass_csp(cdp, sid, enabled=True):
    """Ignore Content-Security-Policy for this page — must be set before the
    load you want to inject into. Without it, strict-CSP targets silently
    refuse injected scripts and probes."""
    cdp.send("Page.setBypassCSP", {"enabled": bool(enabled)}, session_id=sid)


def scroll(cdp, sid, x, y, delta_y=600, delta_x=0):
    """Mouse-wheel scroll at viewport coordinates."""
    cdp.send("Input.dispatchMouseEvent",
             {"type": "mouseWheel", "x": int(x), "y": int(y),
              "deltaX": int(delta_x), "deltaY": int(delta_y)}, session_id=sid)


def screenshot_element(cdp, sid, selector, path=None):
    """PNG of one element (clip to its bounding rect)."""
    expr = ("(() => { const el = document.querySelector(%s); if (!el) return null;"
            " const r = el.getBoundingClientRect();"
            " return JSON.stringify({x: r.x, y: r.y, w: r.width, h: r.height}); })()"
            % _json.dumps(selector))
    r = cdp.send("Runtime.evaluate",
                 {"expression": "/*sbi*/" + expr, "returnByValue": True},
                 session_id=sid)
    val = r.get("result", {}).get("value")
    if not val:
        raise RuntimeError(f"no element matches {selector!r}")
    box = _json.loads(val)
    try:
        cdp.send("Page.bringToFront", session_id=sid, timeout=10)
    except Exception:
        pass
    r = cdp.send("Page.captureScreenshot",
                 {"format": "png", "clip": {"x": box["x"], "y": box["y"],
                                            "width": box["w"], "height": box["h"],
                                            "scale": 2},
                  "captureBeyondViewport": True}, session_id=sid, timeout=30)
    data = base64.b64decode(r.get("data", ""))
    if path is None:
        import time
        path = f"sbi-element-{time.strftime('%Y%m%d-%H%M%S')}.png"
    with open(path, "wb") as f:
        f.write(data)
    return {"path": path, "box": box}


def idb(cdp, sid):
    """IndexedDB database inventory (names + versions)."""
    expr = ("(async () => { try { const dbs = await indexedDB.databases();"
            " const out = {}; for (const db of dbs)"
            " out[db.name || '?'] = {version: db.version};"
            " return JSON.stringify(out); }"
            " catch (e) { return JSON.stringify({__error__: String(e)}); } })()")
    r = cdp.send("Runtime.evaluate",
                 {"expression": "/*sbi*/" + expr, "returnByValue": True,
                  "awaitPromise": True, "silent": True}, session_id=sid)
    try:
        return _json.loads(r.get("result", {}).get("value") or "{}")
    except Exception:
        return {"__error__": "unserializable"}


def call_object(cdp, sid, heap_object_id, function_source, args=None):
    """Call any function against a live object resolved from the heap —
    the general form of patch(). `function_source` is a JS function
    declaration; args are JSON-serializable."""
    live = _resolve(cdp, sid, heap_object_id, "sbi-call")
    r = cdp.send("Runtime.callFunctionOn",
                 {"objectId": live, "functionDeclaration": function_source,
                  "arguments": [{"value": a} for a in (args or [])],
                  "returnByValue": True}, session_id=sid)
    if r.get("exceptionDetails"):
        raise RuntimeError(f"call failed: {r['exceptionDetails'].get('text')}")
    return (r.get("result") or {}).get("value")


def _resolve(cdp, sid, heap_object_id, group):
    r = cdp.send("HeapProfiler.getObjectByHeapObjectId",
                 {"objectId": str(heap_object_id), "objectGroup": group},
                 session_id=sid)
    remote = r.get("result", {})
    if not remote.get("objectId"):
        raise RuntimeError(f"heap object {heap_object_id} is no longer alive: {remote}")
    return remote["objectId"]
