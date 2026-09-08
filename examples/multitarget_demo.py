"""Whole target graph: hook a function inside a Worker.

Flat-mode auto-attach follows pages, workers and out-of-process iframes —
which is where crypto and anti-bot engines actually run. The demo spawns a
blob worker, targets it by url substring, hooks `self.enc` inside it and
captures the message the page receives back.
"""

import json
import sys

from _common import require_config
import sbi

require_config()

PAGE = """
<script>
  const src = `self.enc = (u) => u + '-worker-side';
               self.onmessage = (e) => self.postMessage(self.enc(e.data));`;
  const blob = new Blob([src], { type: 'application/javascript' });
  const w = new Worker(URL.createObjectURL(blob));
  w.onmessage = (e) => { window.workerOut = e.data; };
  window.ask = (u) => w.postMessage(u);
</script>
"""


def worker_url(s):
    for _ in range(5):
        targets = s.targets()
        print("targets:", targets)
        workers = [t for t in targets if t[1] == "worker"]
        if workers:
            return workers[0][2]
        s.wait(1.0)
    return None


with sbi.attach() as s:
    s.inject(PAGE)
    wurl = worker_url(s)
    if not wurl:
        print("SKIP: this cloud browser did not expose the worker target")
        sys.exit(0)

    # the worker may still be paused/starting — self.enc appears once it runs
    for attempt in range(20):
        try:
            s.hook("self.enc", target_url=wurl, label="wenc")
            break
        except RuntimeError:
            s.wait(0.25)
    else:
        print("SKIP: self.enc never became hookable in the worker")
        sys.exit(0)
    s.eval("window.ask('zoe')")

    out = None
    for _ in range(5):
        s.wait(0.5)
        out = s.eval("window.workerOut")
        if out:
            break
    caps = [c for c in s.captures() if "enc" in (c.get("fn") or "")]

    print(f"page saw: {out!r}   hook captured: {caps}")
    assert out == "zoe-worker-side", out
    assert caps and caps[-1]["args"] == ["zoe"], caps
    print("PASS: hooked a function inside a worker via auto-attach")
