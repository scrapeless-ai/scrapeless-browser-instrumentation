"""Live patch of state that only exists inside closures.

Heap search finds the object; getObjectByHeapObjectId resolves it to a live
reference; Runtime.callFunctionOn mutates it in place. No page-visible
wrapper, no redefinition — the closure still holds the same object, its field
just changed. Behaviour flips (e.g. an internal flag), which is the proof
that you found the real state and not a copy.

set_function goes further and is PATCHING in the open: it evals a new source
into a property. Detectable by descriptor checks — use it late, verify early.
"""

import json as _json


def _resolve(cdp, sid, heap_object_id, group):
    r = cdp.send("HeapProfiler.getObjectByHeapObjectId",
                 {"objectId": str(heap_object_id), "objectGroup": group}, session_id=sid)
    remote = r.get("result", {})
    if not remote.get("objectId"):
        raise RuntimeError(f"heap object {heap_object_id} is no longer alive: {remote}")
    return remote["objectId"]


def set_property(cdp, sid, heap_object_id, prop, value):
    """Set `prop` on the live object behind a snapshot node id (JSON values)."""
    live = _resolve(cdp, sid, heap_object_id, "sbi-patch")
    decl = ("function (v) { try { this[%s] = v; return {ok: true, value: this[%s]}; }"
            " catch (e) { return {ok: false, error: String(e)}; } }"
            % (_json.dumps(prop), _json.dumps(prop)))
    r = cdp.send("Runtime.callFunctionOn",
                 {"objectId": live, "functionDeclaration": decl,
                  "arguments": [{"value": value}], "returnByValue": True},
                 session_id=sid)
    if r.get("exceptionDetails"):
        raise RuntimeError(f"patch failed: {r['exceptionDetails'].get('text')}")
    return (r.get("result") or {}).get("value")


def get_property(cdp, sid, heap_object_id, prop):
    live = _resolve(cdp, sid, heap_object_id, "sbi-patch")
    decl = ("function () { try { return JSON.stringify(this[%s]); }"
            " catch (e) { return JSON.stringify({__error__: String(e)}); } }" % _json.dumps(prop))
    r = cdp.send("Runtime.callFunctionOn",
                 {"objectId": live, "functionDeclaration": decl, "returnByValue": True},
                 session_id=sid)
    try:
        return _json.loads((r.get("result") or {}).get("value") or "null")
    except Exception:
        return None


def set_function(cdp, sid, heap_object_id, prop, function_source):
    """Replace a function-valued property with new source (eval'd in the page
    world). Overt patching — the old fn.toString() identity is gone."""
    live = _resolve(cdp, sid, heap_object_id, "sbi-patch")
    decl = ("function (src) { try { this[%s] = (0, eval)('(' + src + ')'); return {ok: true}; }"
            " catch (e) { return {ok: false, error: String(e)}; } }" % _json.dumps(prop))
    r = cdp.send("Runtime.callFunctionOn",
                 {"objectId": live, "functionDeclaration": decl,
                  "arguments": [{"value": function_source}], "returnByValue": True},
                 session_id=sid)
    return (r.get("result") or {}).get("value")
