"""Live patch of closure-held state: find it, flip it, prove it.

Nothing exposes `state` on window. The heap finds candidate objects by
constructor; the resolved previews say which one holds `tier`/`quota`;
Runtime.callFunctionOn patches it in place — same object, same closure, new
field values. The page's own getters report the flip.
"""

import json

from _common import require_config
import sbi

require_config()

PAGE = """
<script>
  (function () {
    const state = { tier: 'free', quota: 3 };
    window.quotaLeft = () => state.quota;
    window.tier = () => state.tier;
  })();
</script>
"""


def find_holder(s):
    """Object nodes whose live preview owns both 'tier' and 'quota'.
    The heap keeps moving — objects can be collected between the snapshot
    and the resolve, so per-object failures are tolerated."""
    found = s.objects(ctor="Object", limit=100)
    props = []
    for m in found["matches"]:
        try:
            live = s.object(m["heap_object_id"])
        except Exception:
            continue                  # died between snapshot and resolve (GC)
        names = {p["name"] for p in (live.get("properties") or [])}
        if {"tier", "quota"} <= names:
            props.append((m["heap_object_id"], live))
    return props


with sbi.attach() as s:
    s.inject(PAGE)
    s.wait(0.3)
    s.eval("window.quotaLeft()")          # warm the closure state

    holders = find_holder(s)
    assert holders, "state object not found among live Object nodes"
    holder_id, preview = holders[0]
    print("holder:", holder_id, "preview:", json.dumps(preview)[:200])

    before = (s.eval("window.tier()"), s.eval("window.quotaLeft()"))
    assert before == ("free", 3), before

    s.patch(holder_id, "tier", "enterprise")
    s.patch(holder_id, "quota", 99)

    after = (s.eval("window.tier()"), s.eval("window.quotaLeft()"))
    print(f"before: {before}  after: {after}")
    assert after == ("enterprise", 99), after
    print("PASS: closure-held state patched in place, behaviour flipped")
