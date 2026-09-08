"""Heap diff: what did this action allocate?

Snapshot -> trigger the action (any JS) -> snapshot again. New string/object/
closure nodes are the material trail of the action: the decoded secret a
click produced, the payload object a signer built. Every new node comes with
a retainer path so the holder (usually the function or cache that keeps it)
is named, not guessed.
"""

from .heap import Snapshot, take_snapshot

_TRACKED = ("string", "object", "closure", "array")


def diff(cdp, sid, action=None, limit=25, with_retainers=2, timeout=60):
    before = Snapshot(take_snapshot(cdp, sid))
    if action:
        cdp.send("Runtime.evaluate",
                 {"expression": action, "awaitPromise": True, "returnByValue": True, "silent": True},
                 session_id=sid, timeout=timeout)
        cdp.flush_events(10)
    after = Snapshot(take_snapshot(cdp, sid))

    seen = set()
    for i in range(len(before.nodes) // before.nstride):
        seen.add(before.node_id(i))

    new = []
    for i in range(len(after.nodes) // after.nstride):
        if after.node_id(i) in seen:
            continue
        t = after.node_type(i)
        if t not in _TRACKED:
            continue
        entry = {"heap_object_id": str(after.node_id(i)), "type": t,
                 "name": after.node_name(i), "self_size": after.node_size(i)}
        if with_retainers:
            entry["retained_via"] = after.retainers(i, depth=with_retainers)
        new.append(entry)

    new.sort(key=lambda e: -e["self_size"])
    return {"new_nodes": new[:limit], "total_new_tracked": len(new),
            "action": action, "snapshot_sizes": [len(before.nodes) // before.nstride,
                                                 len(after.nodes) // after.nstride]}
