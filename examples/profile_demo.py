"""CPU profiling: which function eats the time during the action?

Coverage counts calls; the profiler counts time. A retry loop called 500
times is cheap, the crypto primitive called once can dominate — profile the
action and the hot path names itself.
"""

import json

from _common import require_config
import sbi

require_config()

PAGE = """<script>
  window.checkout = () => {
    let acc = 0;
    for (let i = 0; i < 40; i++) acc += heavy_mix(i);
    acc += cheap_tag(acc);
    return acc;
  };
  function heavy_mix(n) { let t = n; for (let i = 0; i < 2e5; i++) t = (t * 31 + i) | 0; return t; }
  function cheap_tag(x) { return ('' + x).length; }
</script>"""

with sbi.attach() as s:
    s.inject(PAGE)
    s.wait(0.3)

    r = s.profile(action="window.checkout()")
    print(f"total samples: {r['total_hits']}")
    for h in r["hot"]:
        print(f"  {h['hits']:5d}  {h['function']}  {h['url'] or '<inline>'}")

    names = [h["function"] for h in r["hot"]]
    assert "heavy_mix" in names, f"the hot loop is missing: {names}"
    assert names.index("heavy_mix") == 0, f"heavy loop not ranked first: {names}"
    if "cheap_tag" not in names:
        print("cheap_tag never sampled — it costs less than one profiler tick, "
              "which is exactly the point: profile counts time, not calls")
    print("PASS: profile ranked the hot path, heavy loop first")
