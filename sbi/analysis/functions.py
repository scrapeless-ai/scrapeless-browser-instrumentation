"""Function index: every live closure in the page, with name, location, url.

Minified bundles hide the targets; the heap does not. Closure nodes carry
their (mangled) names, and once resolved to a live object each exposes
[[FunctionLocation]] — script + line + column — which maps to a real url via
the engine's scriptParsed registry. This is how you get from "somewhere in
app.js there is an HMAC" to a hookable expression in one step.
"""

from .heap import Snapshot, take_snapshot


def index(cdp, sid, engine=None, contains=None, regex=None, limit=25, with_ids=True):
    snap = Snapshot(take_snapshot(cdp, sid))
    idxs = snap.find(contains=contains, regex=regex, kind="closure", limit=limit * 3)
    out = []
    for i in idxs:
        if len(out) >= limit:
            break
        entry = {"name": snap.node_name(i), "heap_object_id": str(snap.node_id(i)),
                 "self_size": snap.node_size(i)}
        if with_ids:
            live = _resolve_location(cdp, sid, entry["heap_object_id"])
            if live:
                entry["live_object_id"] = live    # hookable via tracer.hook_remote
                entry["url"], entry["location"] = _locate(cdp, sid, engine, live)
        out.append(entry)
    return {"functions": out, "total_closures_scanned": len(idxs)}


def _resolve_location(cdp, sid, heap_object_id):
    try:
        r = cdp.send("HeapProfiler.getObjectByHeapObjectId",
                     {"objectId": str(heap_object_id), "objectGroup": "sbi-fn"},
                     session_id=sid)
        return (r.get("result") or {}).get("objectId")
    except Exception:
        return None


def _locate(cdp, sid, engine, live_id):
    try:
        props = cdp.send("Runtime.getProperties",
                         {"objectId": live_id, "ownProperties": False}, session_id=sid)
        for ip in props.get("internalProperties", []):
            if ip.get("name") == "[[FunctionLocation]]":
                loc = (ip.get("value") or {}).get("value") or {}
                script_id = loc.get("scriptId")
                url = engine.script_url(sid, script_id) if engine else ""
                return url, {"script_id": script_id, "line": loc.get("lineNumber"),
                             "column": loc.get("columnNumber")}
    except Exception:
        pass
    return None, None
