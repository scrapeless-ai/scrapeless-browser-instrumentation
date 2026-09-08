"""The oracle catching a wrong reimplementation.

window.sign(u, p) computes a "signature". We hook it with capture_returns to
build a ground-truth corpus, then propose a plausible-but-wrong candidate
(drops the +1). The oracle runs the candidate in an isolated page and returns
concrete counterexamples. Fixing the candidate flips verified to true.
"""

import json

from _common import require_config, target
import sbi

require_config()

PAGE = """
<script>
  window.sign = (u, p) => btoa(u + '#' + (p * 7 + 1));
</script>
"""

with sbi.attach() as s:
    s.inject(PAGE)
    s.hook("window.sign", capture_returns=True, label="sign")
    s.eval("window.sign('zoe', 0); window.sign('ana', 3); window.sign('', 1);")
    s.wait(0.5)
    print("corpus:", s.corpus("sign"))

    wrong = s.verify("window.sign", "(u,p)=>btoa(u + '#' + (p*7))", label="sign",
                     fresh_inputs=[["zoe", 0], ["", 1]])
    print("wrong candidate:", wrong["verified"], wrong["mismatches"][:1])

    right = s.verify("window.sign", "(u,p)=>btoa(u + '#' + (p*7+1))", label="sign")
    print("right candidate:", right["verified"], f"({right['matched']}/{right['tested']})")

    assert not wrong["verified"] and wrong["mismatches"], "oracle missed a real mismatch"
    assert right["verified"], "correct candidate did not verify"
    print("PASS: oracle separated the wrong reimplementation from the right one")
