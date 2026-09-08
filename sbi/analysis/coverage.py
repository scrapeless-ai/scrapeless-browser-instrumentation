"""Coverage-guided hooking: which functions actually ran?

A hostile bundle ships hundreds of functions; the signer is one of them.
Precise coverage (V8 block counts via the Profiler domain) says which ones
executed during the interesting action — start coverage, reproduce the
behaviour, take counts, and rank the survivors. A function with callCount>0
whose name smells like encoding/crypto is the highest-value hook target, and
call counts often reveal retry/rotation loops you'd otherwise miss.
"""


def start(cdp, sid):
    try:
        cdp.send("Profiler.enable", session_id=sid)
        cdp.send("Profiler.startPreciseCoverage",
                 {"callCount": True, "detailed": False}, session_id=sid)
    except Exception as e:
        raise RuntimeError(f"precise coverage unavailable: {e}")


def take(cdp, sid, only_executed=True, min_count=1, limit=200, script_filter=None):
    r = cdp.send("Profiler.takePreciseCoverage", session_id=sid)
    out = []
    for script in r.get("result", []):
        url = script.get("url", "")
        if script_filter and script_filter not in url:
            continue
        for fn in script.get("functions", []):
            ranges = fn.get("ranges") or []
            count = max((rg.get("count", 0) for rg in ranges), default=0)
            if only_executed and count < min_count:
                continue
            if not fn.get("functionName"):
                continue
            out.append({"function": fn["functionName"], "url": url,
                        "script_id": script.get("scriptId"), "count": count,
                        "size": sum(rg.get("endOffset", 0) - rg.get("startOffset", 0)
                                    for rg in ranges[:1])})
    out.sort(key=lambda f: -f["count"])
    return {"functions": out[:limit], "total": len(out)}


def stop(cdp, sid):
    try:
        cdp.send("Profiler.stopPreciseCoverage", session_id=sid)
        cdp.send("Profiler.disable", session_id=sid)
    except Exception:
        pass
