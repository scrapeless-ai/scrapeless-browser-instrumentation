# Reverse-engineering recipes

Working cookbook for `sbi`. Every recipe assumes one law: **a reading of obfuscated JS is a hypothesis; only runtime ground truth makes it a fact** (LLMs read obfuscated code ~97% syntactically right and ~61% semantically right — JsDeObsBench). Each recipe ends at the oracle, or explicitly says what is still unverified.

## Which tool when

| You have | You want | Reach for |
|---|---|---|
| An artifact in a request/response | The function that made it | `grep` → `coverage` → `hook` |
| A value you can name | Who holds / made it | `objects` / `origin` / `heapdiff` |
| A bundle too big to read | The hot functions | `coverage("take")`, `functions()` |
| `obfuscator.io` strings | The real mapping | `strings()` |
| A bytecode VM | Its semantics | hook dispatch → `vm_steps` |
| A candidate reimplementation | Proof | `verify` → `offline_verify` |
| Two captures of two versions | The regression | `compare.compare_docs` |

## 1. Find the request signer in a minified bundle

**When:** a POST body/header contains a signature you must reproduce.

```python
with sbi.attach("https://target/") as s:
    s.wait(5)
    hits = s.grep("x-signature")            # or a body fragment
    print(hits["network"])                  # which request carries it
```

Then bracket the interesting moment with coverage:

```python
    s.coverage("start")
    s.eval("document.querySelector('#pay').click()")   # reproduce the behaviour
    s.wait(3)
    ran = s.coverage("take", only_executed=True)
    for f in ran["functions"]:
        print(f["count"], f["function"], f["url"])
```

Hook the plausible survivor (name/url reeking of sign/hmac/encode, called once or in a retry pattern), capture pairs, verify:

```python
    s.hook("window._0x4c21", capture_returns=True, label="sign")
    s.eval("document.querySelector('#pay').click()")
    s.wait(3)
    print(s.corpus("sign"))
    print(s.verify("window._0x4c21", "(b)=>btoa(b.id+'|'+b.ts)", label="sign"))
```

**Truth:** `verified: true` with a corpus of varied inputs. **Traps:** functions called 1000× are usually encoding noise, not crypto; signers often live in workers — check `targets()`.

## 2. Crack a rotated string table

**When:** `var _0xabc = [...]` plus a rotating IIFE and a decoder function.

Never copy the source array — it rotates at load. Drive the page's decoder:

```python
dump = s.strings("window._0x1234", n=128)
print(dump["values"])     # index -> actual runtime string
```

Key-dependent decoder (`dec(i, key)`)? Hook it instead — every real call gives a pair for free:

```python
s.hook("window._0x1234", capture_returns=True, label="dec")
# ...trigger page behaviour...
pairs = s.corpus("dec")   # [{input:[i,key], output:"string"}]
```

**Truth:** the runtime mapping + a decoder candidate that passes `verify`. **Trap:** source order matching runtime on 0/10 indices is normal, not evidence of anything.

## 3. Reverse a bytecode VM

**When:** the bundle is a dispatcher over an opaque byte array.

```python
s.coverage("start")
s.eval("window.challenge()")
s.wait(2)
s.coverage("take")            # the dispatch loop is the hottest function
s.hook("window.step", label="vm")
s.eval("window.challenge()")
steps = s.vm_steps()          # one capture == one dispatch (pc, opcode, operand)
print(s.vm_histogram(arg_index=1))   # opcode frequency
```

Rebuild semantics in Python from `steps`, express it as a JS candidate, and let the oracle check it against the hooked VM's return values (see `examples/vm_trace.py`).

**Truth:** candidate verified on the full step trace. **Traps:** opcodes differ per build; the histogram's rare codes are the interesting handlers.

## 4. Where did this token come from?

**When:** a value appears (response, DOM, cookie) and you need its producer.

```python
found = s.origin("tok_9f27", depth=4)      # heap matches + retainer paths
for m in found["matches"]:
    print(m["name"], m["retained_via"])
```

Retainer paths name the holders. To catch the minting moment itself:

```python
d = s.heapdiff(action="document.querySelector('#login').click()")
for n in d["new_nodes"]:
    print(n["type"], n["name"], n["retained_via"])
```

**Truth:** the allocating holder identified; optionally `allocations_start` → action → `allocations_stop` for the stack. **Trap:** GC — diff promptly.

## 5. Flip closure-held state

**When:** behaviour is gated on state no API exposes.

```python
for m in s.objects(ctor="Object")["matches"]:
    if "tier" in (s.object(m["heap_object_id"]).get("properties") or []):
        s.patch(m["heap_object_id"], "tier", "enterprise")
```

The same object, same closure — the page's own getters report the flip. Then `s.audit()` to confirm hooks stayed invisible.

**Truth:** behaviour changed and stayed changed. **Trap:** copies — patch the holder the retainer path points at, not a look-alike object.

## 6. Watch the crypto boundary without reading code

**When:** you need plaintexts, not implementation.

```python
with sbi.attach("https://target/", probes=("crypto",)) as s:
    s.wait(6)
    for e in s.probe_drain():
        if e.get("probe") == "crypto":
            print(e["op"], e["phase"], e.get("args"))
```

The drained inputs are your next grep needles — correlate with `s.grep(...)` on network records. **Note:** probes are wrappers (visible in principle); for stealth work use hooks.

## 7. Hook inside a worker or iframe

**When:** `window.fn` doesn't exist because the code runs in another target.

```python
print(s.targets())                          # find the worker by type/url
s.hook("self.enc", target_url="worker.js", label="wenc")   # or 'self.enc@@worker.js'
```

Auto-attach already follows the graph; you only name the session. **Truth:** a capture lands when the worker runs.

## 8. Verify a reimplementation end to end

The canonical loop:

```python
with sbi.attach("https://target/") as s:
    s.hook("window.sign", capture_returns=True, label="sign")
    # trigger varied calls...
    r = s.verify("window.sign", "(u,p)=>btoa(u+':'+(p*7+1))",
                 label="sign", fresh_inputs=[["zoe", 0], ["", 1]])
    # iterate on r["mismatches"] until r["verified"]
    s.save("traces/sign.json")
```

Then, with the session long dead, in bare Node:

```python
from sbi import trace
trace.offline_verify("traces/sign.json", "sign", "(u,p)=>btoa(u+':'+(p*7+1))")
```

Non-deterministic outputs? Pass a comparison mode — `s.verify(..., mode="loose_string")` (structure), `mode="time_tolerant"` (timestamps), `mode="numeric"` (tolerances).

## 9. Compare two captures across site versions

```python
from sbi import trace, compare
a = trace.load("traces/v1.json")
b = trace.load("traces/v2.json")
diff = compare.compare_docs(a, b)
print(diff["summary"])
print(compare.changed_only(diff))       # [{label, input, a, b}]
```

New endpoints (`diff["network"]["new_urls"]`), hooks that changed mode, corpora outputs that moved — the regression surface in one object.

## 10. Share findings safely

Artifacts contain live secrets. Redact before they leave the machine:

```python
from sbi.sanitize import sanitize_doc, sanitize_file
clean, report = sanitize_doc(trace.load("traces/sign.json"))
print(report)                            # per-rule redaction counts
sanitize_file("traces/sign.json")        # -> traces/sign.sanitized.json
```

Query params, bearer tokens, cookies, high-entropy secrets and emails are replaced; stacks and function names survive. **Rule:** the sanitized file is the only thing you paste into an issue or an LLM.

## 11. Listen to what the page confesses

**When:** hostile SDKs talk to themselves — `console.debug` traces during anti-debug checks, decoded values logged by mistake, and the exact exception a tamper check throws when it notices you. You want that tape.

The Runtime domain already streams every console call and uncaught exception for an instrumented session; `sbi` just keeps it:

```python
with sbi.attach("https://target/") as s:
    s.wait(5)
    for rec in s.console():              # drained records: console calls + uncaught exceptions
        print(rec["kind"], rec["level"], rec["text"], rec["stack"])
```

Correlate by value — `grep` searches console alongside hook captures, corpus pairs and network records, in one call:

```python
s.hook("window.sign", capture_returns=True, label="sign")
s.eval("document.querySelector('#pay').click()")
s.wait(3)
hits = s.grep("signature mismatch")      # one needle, all sources
print(hits["console"])                   # the SDK's own complaint, with the top stack frames
print(hits["pairs"])                     # the hooked call that produced it
```

**Truth:** the page's own log text naming the check it ran (or the value it was not supposed to log), tied to the call that triggered it. **Trap:** `console()` *drains* — the tape is empty afterwards, so keep the return value (and `save()` embeds whatever is undrained).

## 12. Feed the SDK a lie

**When:** you want the signer/decoder's error path, not just its happy path — or a must-talk endpoint has to stay quiet while you poke.

Interception rules are per session, matched in order, and the page only ever sees the response — a mock is indistinguishable from the real server:

```python
with sbi.attach("https://target/") as s:
    s.intercept("https://api.target/v2/config", body='{"flags":{"debug":1}}')  # canned config
    s.intercept("*/telemetry", abort=True)                                     # or fail it
    s.wait(5)
    print(s.grep("flags")["network"])        # the SDK fetched — and swallowed the lie

    s.hook("window.sign", capture_returns=True, label="sign")
    # ...drive the flow; the signer now runs against a config that should not exist...
    print(s.verify("window.sign", "(b)=>btoa(b.id+'|'+b.ts)", label="sign"))
    s.clear_intercepts()
```

`status=`, `headers=` and `content_type=` shape the mock; `abort=True` fails the request; `passthrough=True` lets a rule's URLs through while others are held. **Truth:** a signer whose output changes (or that throws — see recipe 11) when its config lies is a signer that actually reads the config, and you now hold its inputs. **Traps:** rules match in order with `fnmatch`/prefix semantics, so `*/v2/*` beats a later exact rule; on opaque origins a mock needs the right `headers=` or CORS eats the body before the SDK ever sees it.

## 13. Drive the page like a user

**When:** the behaviour only fires on a real gesture, or you need evidence a screenshot can carry.

```python
with sbi.attach("https://target/") as s:
    s.click_element("#login-tab")            # trusted press+release at the element's center
    s.type_text("user@corp.example")         # into the focused element (Input.insertText)
    s.press_key("Enter")
    s.wait(2)
    print(s.screenshot("evidence.png"))      # PNG proof for the report
```

`s.click_element(selector)` returns the `(x, y)` it clicked (element center via `getBoundingClientRect`); `s.screenshot()` brings the tab to front first and returns the path (auto-named `sbi-shot-*.png` when you pass none).

**Trusted events vs `.click()`:** `el.click()` from JS is a synthetic event — `isTrusted: false`, and a checkout flow that checks the flag ignores it. CDP `Input.dispatchMouseEvent` events are *trusted*: at the JS level the page sees a normal user click and cannot tell it apart from yours. **Traps:** typing lands in the *focused* element, so click the field first; and a worker target has no widget to bring to front, so its "screenshot" may come back empty.

## 14. Find the hot path, not the loud path

**When:** the action is slow or the anti-bot runs a proof-of-work you must replicate cheaply.

```python
r = s.profile(action="window.checkout()")     # coverage counts calls, this counts time
for h in r["hot"]:
    print(h["hits"], h["function"], h["url"])
```

The top hit is the primitive worth reimplementing (or caching). A dispatch
loop eating 80% of samples IS the bytecode VM; a retry storm burning time in
`fetch` is a resilience probe. Pair with coverage: high call count + low
hits = noise; low call count + high hits = the target.

**Truth:** hot ranking consistent across reruns. **Trap:** JIT warms up — profile the second run, not the first.
