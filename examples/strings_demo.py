"""Cracking a rotated string array by driving the real decoder.

obfuscator.io rotates its string array at load time, so the order in the
source is a lie. We dump the runtime mapping by calling the page's own
decoder over the index range, then compare with the (wrong) source order.
"""

import json

from _common import require_config, target
import sbi

require_config()

# source shows the array BEFORE rotation: a static reader would copy this order
PAGE = """
<script>
  var _arr = ['guest', 'admin', 'token', 'secret', 'login', 'craig',
              'patched', 'osint', 'backend', 'session'];
  (function rotate(k) { while (--k) { _arr.push(_arr.shift()); } })(7);
  function dec(i) { return _arr[i]; }
  window.dec = dec;
</script>
"""

SOURCE_ORDER = ["guest", "admin", "token", "secret", "login", "craig",
                "patched", "osint", "backend", "session"]

with sbi.attach() as s:
    s.inject(PAGE)
    s.wait(0.3)

    dump = s.strings("window.dec", n=10)
    runtime = dump["values"]

    match = sum(1 for i, v in enumerate(SOURCE_ORDER) if runtime.get(i) == v)
    print("runtime (rotated): ", {i: runtime.get(i) for i in sorted(runtime)})
    print("static source order matches:", f"{match}/{len(SOURCE_ORDER)}")

    assert runtime[0] == "patched", "expected the rotated order as runtime truth"
    assert match < len(SOURCE_ORDER), "rotation did not change the order?"
    print("PASS: runtime mapping recovered — a source-copied reimpl would be wrong")
