"""Save a corpus, close the session, re-verify offline in bare Node.

window.mix(a, b) is hooked with capture_returns and called twice; the trace is
saved to disk and the session closed. Everything after the with-block runs
with no browser at all: offline_verify re-runs candidate implementations in a
bare Node process against the saved pairs — a plausible-but-wrong candidate
(drops the +7 and the |0) is rejected, the exact one verifies.
"""

import json
import os
import tempfile

from _common import require_config
import sbi

require_config()

PAGE = """
<script>
  window.mix = (a,b) => (a*31 + b + 7) | 0;
</script>
"""

with sbi.attach() as s:
    s.inject(PAGE)
    s.hook("window.mix", capture_returns=True, label="mix")
    s.eval("window.mix(3,4); window.mix(10,20)")
    s.wait(0.5)

    path = os.path.join(tempfile.mkdtemp(), "trace.json")
    s.save(path)

    truth = {"3,4": int(s.eval("window.mix(3,4)")), "10,20": int(s.eval("window.mix(10,20)"))}
    print("live truth:", truth)

# -- offline: no browser, no page — bare Node against the saved corpus ------
from sbi.artifacts import trace as trace_mod

wrong = trace_mod.offline_verify(path, "mix", "(a,b)=>a*31+b")
right = trace_mod.offline_verify(path, "mix", "(a,b)=>(a*31+b+7)|0")
print("wrong candidate:", wrong["verified"], f"({wrong['matched']}/{wrong['tested']})",
      wrong["mismatches"][:1])
print("right candidate:", right["verified"], f"({right['matched']}/{right['tested']})")

saved = {f"{p['input'][0]},{p['input'][1]}": p["output"]
         for p in trace_mod.load(path)["pairs"]["mix"]}
assert saved == truth, "saved corpus disagrees with the live page"
assert wrong["verified"] is False, "offline oracle accepted the wrong candidate"
assert right["verified"] is True, "correct candidate did not verify offline"
assert right["tested"] == 2, f"expected the 2 saved pairs, got {right['tested']}"
print("PASS: saved corpus re-verified offline in bare Node after the session closed")
