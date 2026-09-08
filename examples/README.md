# Examples

Each example is executable proof: it injects a small hostile-looking page,
exercises one capability, asserts the outcome and prints `PASS`. All need a
live session — `export SCRAPELESS_API_TOKEN=...` (or `SCRAPELESS_CDP_URL`,
e.g. local Chrome's `http://127.0.0.1:9222`).

Run one: `python examples/oracle_demo.py` (from the repo root, so `import sbi` resolves).

| Example | Proves |
|---|---|
| `selftest.py` | Hook invisibility: page's own `toString`/own-property checks see nothing while args are captured |
| `oracle_demo.py` | The oracle rejects a plausible-but-wrong reimplementation and accepts the right one |
| `strings_demo.py` | Rotated string table: runtime mapping recovered by driving the real decoder; source order exposed as a lie |
| `crypto_log.py` | Plaintext entering `crypto.subtle` recovered at the boundary (probe = patched, non-stealth) |
| `heap_search.py` | Closure-held secret found by value with retainer paths |
| `heap_diff.py` | What one action allocated — snapshot → action → snapshot, with holders |
| `live_patch.py` | Closure-held state patched in place; behaviour flips through the page's own getters |
| `find_functions.py` | Closure index: hidden `_0x`-style functions with url + location, then hooked |
| `dataflow_follow.py` | Producer outputs traced to the objects that retain them downstream |
| `vm_trace.py` | Bytecode VM dispatch traced into steps + opcode histogram, semantics rebuilt and verified |
| `multitarget_demo.py` | Hooking inside a spawned Worker via flat auto-attach |
| `network_demo.py` | Real-web network capture + grep correlation (httpbin) |
| `offline_reverify.py` | Session closed, artifact saved, corpus re-verified in bare Node — no browser |

## Suggested order

1. `selftest` → `oracle_demo` (the core contract: invisible + verified)
2. `strings_demo` → `vm_trace` (deobfuscation)
3. `heap_search` → `heap_diff` → `live_patch` (state discovery and control)
4. `find_functions` → `dataflow_follow` → `multitarget_demo` (locating and following)
5. `network_demo` → `offline_reverify` (correlation and artifacts)
