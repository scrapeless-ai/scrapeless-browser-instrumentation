"""One page, four observers: mock it, hear it, click it, photograph it.

The page fetches a config and exposes a button. We intercept the config
endpoint with a lie (debugFlag on), watch the page's console confess, click
the button like a user would, and take the evidence PNG. No network needed —
the mock fulfills locally.
"""

import json
import os
import tempfile

from _common import require_config
import sbi

require_config()

PAGE = """<p>sbi</p><script>
  console.warn('config loaded');
  window.flag = null;
  window.reload = () => fetch('https://api.target.test/v1/config')
      .then(r => r.json()).then(c => { window.flag = c.debugFlag; });
  window.bought = 0;
</script><button id='buy' onclick="window.bought=1">buy</button>"""

with sbi.attach() as s:
    s.inject(PAGE)
    s.wait(0.3)

    s.intercept("https://api.target.test/v1/config",
                body=json.dumps({"debugFlag": 42}),
                headers={"Access-Control-Allow-Origin": "*"})
    s.eval("window.reload()", await_promise=True)
    assert s.eval("window.flag") == 42, "the mock did not feed the page"

    recs = s.console()
    assert any("config loaded" in (r.get("text") or "") for r in recs), recs

    s.click_element("#buy")
    s.wait(0.2)
    assert s.eval("window.bought") == 1, "the trusted click did not land"

    path = os.path.join(tempfile.mkdtemp(), "evidence.png")
    s.screenshot(path)
    with open(path, "rb") as f:
        assert f.read(4) == b"\x89PNG"

    print("mocked config fed, console heard, button clicked, evidence:",
          path)
    print("PASS: intercept + console + trusted input + screenshot, one session")
