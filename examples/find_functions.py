"""Function index: from a minified bundle to a hookable expression.

The closures `_0xencode`/`_0xdecode` live behind `window.api`, never on
window by their own names. The closure index finds them in the heap with
their script urls and [[FunctionLocation]] — and what the index finds, the
hook can hook.
"""

import json

from _common import require_config
import sbi

require_config()

PAGE = """
<script>
  (function () {
    function _0xencode(v) { return btoa(v + '|salt'); }
    function _0xdecode(v) { return atob(v).split('|')[0]; }
    window.api = { encode: _0xencode, decode: _0xdecode };
  })();
</script>
"""

with sbi.attach() as s:
    s.inject(PAGE)
    s.wait(0.3)
    s.eval("window.api.encode('x')")      # instantiate the closures

    r = s.functions(contains="_0x")
    for fn in r["functions"]:
        loc = fn.get("location") or {}
        print(f"{fn['name']}  {fn.get('url') or '?'}:"
              f"{loc.get('line')}:{loc.get('column')}  heap={fn['heap_object_id']}")

    names = [fn["name"] for fn in r["functions"]]
    assert len(names) >= 2 and all(n.startswith("_0x") for n in names), names
    # about:blank pages have no url, so inline scripts report url "" — the
    # script/line/column location is the resolvable truth here
    assert all(fn.get("location", {}).get("script_id") for fn in r["functions"]), \
        "location not resolved"

    s.hook("window.api.encode", label="enc")
    s.eval("window.api.encode('probe')")
    s.wait(0.3)
    caps = s.captures()
    assert caps and caps[-1]["args"] == ["probe"], caps
    print("PASS: index found the hidden closures and the hook captured a live call")
