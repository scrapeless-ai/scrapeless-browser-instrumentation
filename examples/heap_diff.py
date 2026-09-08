"""Heap diff: the material trail of one action.

The page keeps a private cache nothing on `window` exposes. One heapdiff
call — snapshot, run the action, snapshot again — shows exactly what the
action allocated (the decoded secret, the growing cache), each with a
retainer path naming its holder.
"""

import json

from _common import require_config
import sbi

require_config()

PAGE = """
<script>
  (function () {
    const cache = {};
    window.decode = () => {
      cache.token = 'decoded_secret_' + Date.now().toString(36);
      cache.attempts = (cache.attempts || 0) + 1;
      return cache.token;
    };
  })();
</script>
"""

with sbi.attach() as s:
    s.inject(PAGE)
    s.wait(0.3)

    d = s.heapdiff(action="window.decode()")
    print(f"new tracked nodes: {d['total_new_tracked']} (heap grew "
          f"{d['snapshot_sizes'][0]} -> {d['snapshot_sizes'][1]})")
    for n in d["new_nodes"]:
        print(f"  +{n['type']} {n['name']!r} ({n['self_size']}B) via {n['retained_via']}")

    names = [n["name"] for n in d["new_nodes"]]
    assert any("decoded_secret_" in n for n in names), f"the minted token is missing: {names}"
    assert d["total_new_tracked"] >= 1
    print("PASS: heap diff exposed what the action allocated, with retainers")
