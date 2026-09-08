"""Find the live object holding a secret by value, then see who retains it.

Nothing on `window` exposes the token — it lives in a closure. A heap search
by value finds it; retainer paths name the closure/object graph that holds
it; the resolved object preview shows the shape around it.
"""

import json

from _common import require_config, target
import sbi

require_config()

PAGE = """
<script>
  (function () {
    const session = { token: 'sbx_live_9f27aa41', user: 'ana' };
    window.check = () => session.token.length;
  })();
</script>
"""

with sbi.attach() as s:
    s.inject(PAGE)
    s.wait(0.3)
    s.eval("window.check()")

    found = s.objects(contains="sbx_live_9f27aa41", with_retainers=3)
    print(json.dumps(found, indent=2)[:1200])

    matches = found["matches"]
    assert matches, "token not found in heap"
    # script sources are heap strings too and may contain the token — take the exact value
    match = next(m for m in matches if m["name"] == "sbx_live_9f27aa41")
    # strings aren't resolvable live — the holder object is
    holder = match.get("holder")
    assert holder, "no object holder found for the token string"
    print("holder:", holder)
    live = s.object(holder["heap_object_id"])
    print("resolved holder object:", json.dumps(live)[:300])
    names = {p["name"] for p in (live.get("properties") or [])}
    assert "token" in names, f"holder lacks the token property: {names}"
    print("PASS: closure-held secret found by value, holder object resolved")
