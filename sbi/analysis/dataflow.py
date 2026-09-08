"""Dataflow follow: from a hooked producer's outputs to whoever holds them.

The producer hook gives you output values; the heap tells you where each one
landed. For every captured output we search live heap string nodes and walk
retainer paths — the property/element chain names the consumer objects
(request builders, caches, DOM nodes) that received the value. This is the
bridge between "the signer returns X" and "X ends up in the POST body built
by that other function".
"""

from . import heap as heap_mod


def follow(session, label, depth=4, limit=5, heap_limit=3, target_session=None):
    sid = session.engine.resolve_session(target_session)
    pairs = session.corpus(label)[:limit]
    flows = []
    for p in pairs:
        val = p.get("output")
        if p.get("unserialized") or not isinstance(val, str) or not val:
            continue
        found = heap_mod.search(session.cdp, sid, contains=val,
                                limit=heap_limit, with_retainers=depth)
        flows.append({"input": p.get("input"), "output": val,
                      "holders": found["matches"]})
    skipped = len(pairs) - len(flows)
    return {"producer": label, "flows": flows,
            "skipped_unserializable": max(0, skipped),
            "note": "values absent from the heap are usually unflattened rope "
                    "strings (never serialized) or already collected"}
