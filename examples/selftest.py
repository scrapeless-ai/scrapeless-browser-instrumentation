"""Invisibility + live-arg capture, end to end.

The page defines window.fn; we hook it and let it run. Then we prove the page
still sees its own untouched function: toString() unchanged, no own-property
wrapper, and the call still went through — while we captured the arguments.
"""

import json

from _common import require_config, target
import sbi

require_config()

PAGE = """
<script>
  function fn(a, b) { return a + ':' + b; }
  window.fn = fn;
  window.sees = () => ({ s: fn.toString(),
                         foreign: Object.getOwnPropertyNames(fn)
                           .filter(n => !['length', 'name', 'prototype'].includes(n)).length });
  setTimeout(() => { window.result = fn('x', 1); }, 800);
</script>
"""

with sbi.attach() as s:
    s.inject(PAGE)
    s.hook("window.fn", label="fn")
    s.wait(1.5)

    seen = s.eval("JSON.stringify(window.sees())")
    result = s.eval("window.result")
    caps = [c for c in s.captures() if c.get("fn") == "fn"]

    print("page's view of fn (must be untouched):", seen)
    print("page's own call result:", result)
    print("our capture:", caps)
    body = json.loads(seen)
    assert "native code" not in body["s"] and body["foreign"] == 0, "function was touched!"
    assert caps and caps[-1]["args"] == ["x", 1], "args not captured!"
    assert result == "x:1", "the hook changed behaviour!"
    print("PASS: hook was invisible to the page and captured live arguments")
