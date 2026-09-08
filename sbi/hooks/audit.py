"""Stealth audit: did the instrumentation leave a trace?

For every hook we re-read the function the page sees and compare it with what
we recorded at hook time: toString identity and own-property count. Any drift
means the page (or a later script) noticed something. Boundary probes are
reported as exposed-by-design — they are wrappers, that is their job; the
audit only quantifies the surface.
"""

import json

GW = "/*sbi-audit*/"


def check(session, target_url=None):
    sid = session.engine.resolve_session(target_url)
    with session.tracer.lock:
        hooks = [dict(h) for h in session.tracer.hooks]
    results = []
    for h in hooks:
        expr = (GW + "JSON.stringify((function(){ var f = (" + h["expression"] + ");"
                " return { s: Function.prototype.toString.call(f),"
                " p: Object.getOwnPropertyNames(f).length }; })())")
        try:
            r = session.cdp.send("Runtime.evaluate",
                                 {"expression": expr, "returnByValue": True, "silent": True},
                                 session_id=sid)
            val = r.get("result", {}).get("value")
            now = json.loads(val) if isinstance(val, str) else {}
        except Exception as e:
            now = {"s": None, "p": -1, "err": str(e)}
        # hooks armed from a bare objectId have no recorded baseline: presence
        # of a signature is what the integrity compare needs
        intact = ((h.get("signature") is None or now.get("s") == h.get("signature"))
                  and (h.get("own_props") is None or now.get("p") == h.get("own_props")))
        results.append({"label": h["label"], "intact": bool(intact),
                        "expected": h.get("signature"), "signature_now": now.get("s")})
    return {"hooks": results,
            "all_intact": all(r["intact"] for r in results) if results else True,
            "probe_surface": "installed" if session.engine._probe_sources else "none",
            "note": "probes are wrappers and detectable by design; hooks should be intact"}
