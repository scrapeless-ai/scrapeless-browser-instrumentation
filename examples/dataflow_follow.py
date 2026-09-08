"""Dataflow follow: where does the producer's output land?

`makeToken` returns a token; a closure-private `bag` keeps every token it
ever made. The hook captures (user -> token) pairs; follow() searches the
heap for each output and walks retainer paths — the bridge between "the
signer returns X" and "X is held by that object over there".
"""

import json

from _common import require_config
import sbi

require_config()

PAGE = """
<script>
  (function () {
    const bag = {};
    window.makeToken = (u) => {
      const t = 'tok_' + u + '_' + (Math.random() * 1e6 | 0);
      bag[u] = t;                        // strong ref: the heap must see it
      return t;
    };
    window.dumpBag = () => JSON.stringify(bag);   // serialization flattens rope strings
  })();
</script>
"""

with sbi.attach() as s:
    s.inject(PAGE)
    s.wait(0.3)

    s.hook("window.makeToken", capture_returns=True, label="mk")
    s.eval("window.makeToken('zoe'); window.makeToken('ana')")
    s.eval("window.dumpBag()")            # flatten the tokens so the heap shows their values
    s.wait(0.5)
    print("corpus:", [(p["input"], p["output"]) for p in s.corpus("mk")])

    r = s.follow("mk")
    for flow in r["flows"]:
        print(f"{flow['input']} -> {flow['output']}")
        for h in flow["holders"]:
            print(f"   held as {h['name']!r} via {h['retained_via']}")

    assert r["flows"], "no flows followed"
    assert r["flows"][0]["output"].startswith("tok_zoe"), r["flows"][0]
    holders_found = [f for f in r["flows"] if f["holders"]]
    assert holders_found, f"no holder found for any token ({r['note']})"
    print("PASS: producer outputs traced to the objects that retain them")
