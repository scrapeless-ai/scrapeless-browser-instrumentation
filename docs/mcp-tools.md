# sbi MCP tools — complete reference

`sbi/mcp_server.py` exposes a FastMCP server (`scrapeless-browser-instrumentation`) so an agent can drive an instrumented Scrapeless browser session: hypothesize about hostile JavaScript, hook it invisibly, capture ground truth, and verify a reimplementation against it. Tool names and parameters below are transcribed exactly from the source.

## Setup

```bash
pip install mcp
claude mcp add sbi -- python -m sbi.mcp_server      # run from the repo checkout
```

Environment variables (read at attach time):

| Variable | Meaning |
|---|---|
| `SCRAPELESS_API_TOKEN` | API token from your Scrapeless dashboard (default path) |
| `SCRAPELESS_CDP_URL` | Alternative: any direct CDP endpoint, e.g. `wss://...` gateway or `http://127.0.0.1:9222` for local Chrome |
| `SCRAPELESS_PROXY_COUNTRY` | Optional proxy country for the Scrapeless session |

The Scrapeless session **attaches lazily on the first tool call** that needs it: the server connects the CDP websocket, starts the Session, and reuses it for every subsequent call. `sbi_close` tears it down (and resets, so the next call attaches fresh). The cloud session lives only as long as the websocket — call `sbi_save` before closing, or the evidence is gone.

## Tools

| Tool | Parameters (`name: type = default`) | Purpose |
|---|---|---|
| `sbi_attach` | `url: str`; `wait: float = 3.0` | Attach to a Scrapeless browser session and navigate to url. |
| `sbi_targets` | — | List live targets (pages, workers, iframes) with their session ids. |
| `sbi_hook` | `expression: str`; `capture_returns: bool = False`; `label: str = None`; `target_url: str = None` | Invisibly hook a function (expr, or `'expr@@url-substr'`). With `capture_returns`, records (input -> output) pairs for the oracle. |
| `sbi_captures` | `label: str = None` | Captured hook hits; pass a label to get its (input, output) corpus. |
| `sbi_verify` | `fn_expr: str`; `candidate: str`; `label: str = None`; `fresh_inputs: list = None`; `target_url: str = None`; `mode: str = "exact"` | Verify a reimplementation candidate against the captured corpus + fresh live inputs. `candidate` is a JS function expression. Returns a structured diff with counterexamples — iterate until `verified=true`. |
| `sbi_objects` | `contains: str = None`; `regex: str = None`; `ctor: str = None`; `session: str = None`; `limit: int = 25`; `with_retainers: int = 0` | Search the live V8 heap for values/objects (by substring, regex or constructor name), optionally with retainer paths. |
| `sbi_object` | `heap_object_id: str`; `session: str = None` | Resolve a heap snapshot object id back to the live object; preview properties. |
| `sbi_origin` | `value: str`; `session: str = None`; `depth: int = 4` | Find where a value lives in the heap and who retains it. |
| `sbi_strings` | `decoder_expr: str`; `n: int = 32`; `session: str = None` | Dump an obfuscated/rotated string table by driving the page's real decoder over indices 0..n-1 (runtime truth, not source order). |
| `sbi_probe` | `action: str = "drain"`; `names: list = None`; `session: str = None` | Boundary recorders (crypto/eval/net): `action=install\|drain`. |
| `sbi_grep` | `needle: str`; `regex: bool = False` | Search hook captures and network records/bodies for a value. |
| `sbi_heapdiff` | `action: str`; `session: str = None`; `limit: int = 25` | Snapshot the heap, run `action` (JS) in the page, snapshot again: the nodes the action allocated, with retainer paths (the material trail — decoded secrets, payload objects). |
| `sbi_patch` | `heap_object_id: str`; `prop: str`; `value` (untyped — passed through as JSON); `session: str = None` | Mutate a property of a closure-held object found via `sbi_objects`/`sbi_origin`. Behaviour flips in place — proof you found the real state. |
| `sbi_functions` | `contains: str = None`; `regex: str = None`; `session: str = None`; `limit: int = 25` | Index live closures by name with url + function location — includes closures unreachable from `window`. Hook targets, found. |
| `sbi_coverage` | `action: str = "take"`; `session: str = None` | `'start'` before the interesting action, `'take'` for executed functions ranked by call count, `'stop'` when done. Coverage-guided hooking. |
| `sbi_follow` | `label: str`; `depth: int = 4`; `limit: int = 5`; `session: str = None` | Follow a hooked producer's captured outputs into the heap: which objects/functions hold them downstream. |
| `sbi_vm` | `session: str = None` | Format arg-captures of a hooked bytecode-VM dispatch loop as steps plus an opcode-ish histogram. |
| `sbi_audit` | `target_url: str = None` | Check every hook left no trace: `toString` identity + own-prop drift vs the baseline recorded at hook time. |
| `sbi_blackbox` | `patterns: list` | Skip vendor/framework url patterns in stacks and stepping. |
| `sbi_dump_scripts` | `directory: str`; `session: str = None` | Write every parsed script's source to files for static analysis. |
| `sbi_report` | `path: str` | Render the current session state to a markdown report file. |
| `sbi_eval` | `expression: str`; `target_url: str = None`; `await_promise: bool = False` | Evaluate JS in a target page (main world). |
| `sbi_auto_hook` | `top: int = 5`; `contains: str = None`; `url_contains: str = None`; `capture_returns: bool = False` | Hook the functions that actually ran (coverage-ranked) by live object — covers closures unreachable from `window`. Run `sbi_coverage start` + the action first. |
| `sbi_watch` | `expression: str`; `seconds: float = 10.0`; `interval: float = 0.5`; `target_url: str = None` | Poll an expression and record every change (token rotation, counters, mutating state). |
| `sbi_trace_value` | `needle: str`; `regex: bool = False`; `heap: bool = False`; `target_url: str = None` | One value, full journey: hook captures, corpus pairs, network records, optionally the heap with holder. |
| `sbi_new_page` | `url: str = None` | Open an additional instrumented page; returns its session id. |
| `sbi_dialogs` | `policy: str = None` | No args: drain recorded JS dialogs. policy 'accept'/'dismiss': auto-answer from the event thread (alert() storms can't stall the session). |
| `sbi_emulate` | `kind: str`; `value: str = None`; `width: int = None`; `height: int = None`; `mobile: bool = False`; `target_url: str = None` | Per-session emulation: kind 'locale' / 'timezone' / 'device' / 'ua' / 'script'. In-page visible; may conflict with the gateway's fingerprint stack. |
| `sbi_doctor` | — | Readiness self-check: deps, token, endpoint, browser reachability. |
| `sbi_reconnect` | — | Rebuild the transport after a websocket drop; re-arms hooks, probes, blackbox, dialog policy, intercept rules. Corpora survive; heap state is gone. |
| `sbi_metrics` | `target_url: str = None` | Runtime counters (heap, listeners, frames) — bloat/loop detectors. |
| `sbi_profile` | `action: str`; `target_url: str = None`; `top: int = 15` | CPU-profile while action runs; hottest functions by sample hits. |
| `sbi_pdf` | `path: str = None`; `target_url: str = None` | Print-to-PDF evidence (headless builds only). |
| `sbi_network_conditions` | `latency_ms: int = 0`; `download_kbps: float = -1`; `upload_kbps: float = -1`; `offline: bool = False`; `target_url: str = None` | Emulate network conditions or cut the network — feed the SDK a 3G link / outage and watch its retry logic. |
| `sbi_geolocation` | `lat: float = None`; `lon: float = None`; `accuracy: float = 100`; `target_url: str = None` | Override geolocation (pair with sbi_grant_permissions); lat=None clears. |
| `sbi_grant_permissions` | `permissions: list`; `origin: str = None` | Browser-level permission grants. |
| `sbi_set_cookie` | `name: str`; `value: str`; `url: str = None`; `domain: str = None`; `target_url: str = None` | Plant a cookie. |
| `sbi_clear_storage` | `origin: str`; `storage_types: str`; `target_url: str = None` | Wipe an origin's storage — reproducible runs. |
| `sbi_wasm_modules` | `target_url: str = None` | Every loaded WebAssembly module (script id + url) — where anti-bot engines hide hashes and VMs. |
| `sbi_wasm_dump` | `script_id: str`; `path: str = None`; `target_url: str = None` | Dump a module's raw bytecode to a .wasm file (wabt/Ghidra-ready). |
| `sbi_wasm_disasm` | `script_id: str`; `target_url: str = None` | Full disassembly with extracted function names. |
| `sbi_wasm_meta` | `module_expr: str`; `target_url: str = None` | Exports/imports/custom sections of a live Module (or Instance surface). |
| `sbi_wasm_from_network` | `directory: str` | Dump every wasm module captured on the wire — the reliable route (production wasm arrives via instantiateStreaming). |
| `sbi_collect_script` | `directory: str`; `pattern: str = None`; `script_id: str = None`; `target_url: str = None` | Collect specific JS/wasm files to disk by url substring (e.g. 'shape') or script id. |
| `sbi_wasm_extract_embedded` | `js_path: str`; `directory: str` | Extract wasm modules embedded as base64 inside a collected JS 'seed' file, tolerating JS string concatenation. |
| `sbi_cpu_throttle` | `rate: float = 1`; `target_url: str = None` | Slow the CPU Nx — proof-of-work and timing checks surface. |
| `sbi_emulate_media` | `feature: str`; `value: str`; `target_url: str = None` | Emulate media features (prefers-color-scheme, prefers-reduced-motion...). |
| `sbi_cache` | `action: str = "clear"`; `target_url: str = None` | Cache control: disable / enable / clear. |
| `sbi_bypass_csp` | `enabled: bool = True`; `target_url: str = None` | Ignore Content-Security-Policy — set before the load you inject into. |
| `sbi_scroll` | `x: float = 400`; `y: float = 400`; `delta_y: int = 600`; `delta_x: int = 0`; `target_url: str = None` | Mouse-wheel scroll at viewport coordinates. |
| `sbi_screenshot_element` | `selector: str`; `path: str = None`; `target_url: str = None` | PNG of a single element, clipped to its bounding rect. |
| `sbi_idb` | `target_url: str = None` | IndexedDB inventory (names + versions). |
| `sbi_call_object` | `heap_object_id: str`; `function_source: str`; `args: list = None`; `target_url: str = None` | Call any JS function against a live heap-resolved object (general form of sbi_patch). |
| `sbi_wait_for` | `expression: str`; `timeout: float = 10.0`; `target_url: str = None` | Poll until a JS expression is truthy — no blind sleeps. |
| `sbi_capture_inputs` | `label: str`; `fn_expr: str`; `inputs: list`; `target_url: str = None` | Drive the live function with controlled inputs; persist ground truth into the corpus. |
| `sbi_type_into` | `selector: str`; `text: str`; `target_url: str = None` | Focus an input by selector and type into it (trusted events). |
| `sbi_trace_calls` | `contains: str`; `limit: int = 10`; `target_url: str = None` | frida-trace equivalent: hook every function matching `contains` across live closures; read calls via sbi_captures. |
| `sbi_load_agent` | `name: str`; `source: str` | Frida-style agent injection: run a JS agent in every instrumented target (persists across navigations); agent gets `send(data)` + `rpc`. |
| `sbi_agent_messages` | `name: str` | Drain messages an agent streamed via send(). |
| `sbi_call_agent` | `name: str`; `fn: str`; `args: list = None`; `target_url: str = None` | Call an rpc function the agent exported. |
| `sbi_deobfuscate` | `pattern: str = None`; `script_id: str = None`; `source_path: str = None`; `out_dir: str = None` | Static deobfuscation via webcrack: string arrays, control flow, unminify, bundle splitting. |
| `sbi_export_har` | `path: str` | Captured network traffic as HAR 1.2 (DevTools/Burp-compatible). |
| `sbi_save_state` | `path: str` | Snapshot cookies + local/session storage (storageState-style). |
| `sbi_load_state` | `path: str` | Restore a state snapshot: cookies via CDP, storage via the page. |
| `sbi_replay_request` | `url: str`; `method: str = "GET"`; `headers: dict = None`; `body: str = None`; `target_url: str = None` | Burp-style repeat from inside the page (its origin, its cookies). |
| `sbi_dom_snapshot` | `path: str = None`; `target_url: str = None` | Full serialized DOM to a file. |
| `sbi_console` | — | Drain console messages + uncaught exceptions — hostile SDKs leak tells (anti-debug logs, decode mistakes). |
| `sbi_cookies` | `session: str = None` | Session cookies (name/value/domain). |
| `sbi_storage` | `session: str = None` | localStorage + sessionStorage dump (opaque origins report errors). |
| `sbi_screenshot` | `path: str = None`; `target_url: str = None` | PNG of the viewport — evidence for the report. |
| `sbi_click` | `selector: str = None`; `x: float = None`; `y: float = None`; `target_url: str = None` | Trusted click by CSS selector (center of first match) or raw x/y. |
| `sbi_type` | `text: str`; `target_url: str = None` | Type into the focused element (IME-safe insertText). |
| `sbi_intercept` | `pattern: str`; `status: int = 200`; `body: str = ""`; `headers: dict = None`; `abort: bool = False`; `passthrough: bool = False`; `content_type: str`; `stage: str = "request"`; `modify: dict = None`; `edit: list = None` | Mock/abort/passthrough/edit requests (Fetch domain). stage='request': continue with edits (modify url/method/headers/body); stage='response': replace the body on the way out. The page only sees the result. |
| `sbi_clear_intercepts` | — | Remove all interception rules and disable the Fetch domain. |
| `sbi_scripts` | `session: str = None` | Parsed scripts (id -> url) in a target — find what to read or hook. |
| `sbi_source` | `script_id: str`; `session: str = None` | Fetch a script's source by id. |
| `sbi_save` | `path: str` | Save captures, corpora and network records to a JSON artifact. |
| `sbi_replay` | `trace_path: str` | Re-establish a saved trace's hooks on the live session (navigate if the artifact recorded a url, re-hook every hook). |
| `sbi_sanitize` | `path: str`; `out_path: str = None` | Redact secrets (tokens, bearer headers, cookies, high-entropy strings, emails) from a trace artifact before sharing it. |
| `sbi_close` | — | Close the session (ends the Scrapeless browser session). |

Tools that accept `target_url` / `session` let you aim at a specific target in the graph (a url substring or a session id from `sbi_targets`); by default the main page is used and auto-attach already follows workers/OOPIFs.

## Worked agent session — finding and verifying a signer

> **Illustrative transcript** (abridged, not a real session) of the
> hypothesize -> hook -> capture -> verify loop in ~8 tool calls.

**1. Attach and look around.**

```
sbi_attach url="https://target.example/login" wait=3
→ {"ok": true, "url": "...", "targets": [{"targetId": "...", "url": "https://target.example/login", ...}]}
```

**2. Find hook candidates without reading 4 MB of webpack.**

```
sbi_functions regex="sign|token|hmac|digest"
→ [{"name": "computeSign", "url": "https://cdn.target.example/app.8f2c.js", "line": 4412}, ...]
```

One hit is a closure unreachable from `window`. Hypothesis: the signer is `computeSign(payload, t) -> header` per a quick `sbi_source` skim of that region. Reading is a hypothesis, not a fact — so capture ground truth.

**3. Hook it invisibly, with return capture.**

```
sbi_hook expression="signModule.computeSign" capture_returns=true label="sign"
→ {"ok": true, "hooked": "signModule.computeSign"}
```

**4. Trigger the behaviour.**

```
sbi_eval expression="document.querySelector('button[type=submit]').click()"
→ {"value": null}
```

**5. Read the captured corpus.**

```
sbi_captures label="sign"
→ {"captures": [{"args": ["{\"u\":\"zoe\"}", 1725446400], "ret": "v1:9f2ab..."}], "corpus_sizes": {"sign": 1}}
```

**6. Verify the candidate from the source reading.**

```
sbi_verify fn_expr="signModule.computeSign" label="sign" \
           candidate="(p,t)=>'v1:'+sha1hex(p+t)" \
           fresh_inputs=[["{\"u\":\"ada\"}", 0], ["", 1725446400]]
→ {"verified": false, "mismatches": [{"input": ["{\"u\":\"ada\"}", 0], "expected": "v1:e3b0...", "got": "v1:da4a..."}]}
```

Wrong. The counterexample shows the timestamp is not concatenated raw — the diff suggests it is included as a little-endian byte tail.

**7. Fix and re-verify.**

```
sbi_verify fn_expr="signModule.computeSign" label="sign" \
           candidate="(p,t)=>'v1:'+sha1hex(p+le32(t))" \
           fresh_inputs=[["{\"u\":\"ada\"}", 0], ["", 1725446400], ["é"*512, 1]]
→ {"verified": true, "matched": 4, "total": 4}
```

**8. Audit stealth, save the artifact, close.**

```
sbi_audit            → {"clean": true, "hooks": [...]}     # no trace left
sbi_save path="sign-trace.json"  → {"saved": "sign-trace.json", "pairs": {"sign": 4}}
sbi_close            → {"ok": true}
```

The signer is now reimplemented and verified; `sign-trace.json` re-verifies offline (bare Node, no browser) at any time.

## Notes

**Stealth properties.** The mechanism matters as much as the result:

- `sbi_hook` (and everything built on it — `sbi_captures`, `sbi_verify` corpus, `sbi_vm`, `sbi_follow`) is **invisible**: a `Debugger.setBreakpointOnFunctionCall` on the live function object, nothing wrapped or replaced. `fn.toString()`, Proxy traps and monkeypatch detectors see nothing. `sbi_audit` proves it per hook (toString identity + own-prop drift vs a hook-time baseline).
- `sbi_probe` is **patched and visible**: main-world wrappers installed before page scripts run, with toString/name masqueraded but detectable by a determined SDK. Use probes to observe boundaries (plaintext entering `crypto.subtle`, evals, net); use hooks to be stealthy.
- Heap tools (`sbi_objects`, `sbi_object`, `sbi_origin`, `sbi_heapdiff`), script tools (`sbi_scripts`, `sbi_source`, `sbi_dump_scripts`) and network capture are read-only observations — no page-visible change.
- `sbi_eval` runs real JS in the main world: no patching of the runtime, but its side effects are the page's, so keep it to triggering behaviour. `sbi_patch` deliberately mutates live state — use it to prove you found the real closure-held state, and expect behaviour to flip.
- The `sbi_verify` oracle runs the candidate in a private page that cannot see the instrumented targets, so a candidate that cheats by calling the real function fails.

**Artifact workflow.** A cloud session's evidence dies with the websocket, so end every session with `sbi_save path=...` — it writes captures, corpora and network records to one JSON artifact that reloads and re-verifies offline in a bare Node process (no browser, no network; a candidate that calls home fails there). `sbi_report path=...` renders the current session state as a markdown report for the record.

**Skill pointer.** `skills/verify-reimplementation/SKILL.md` teaches the full loop for agents — hypothesize -> hook -> capture -> verify -> iterate until the diff is empty, including corpus-honesty and red-teaming rules (empty/unicode/large inputs, nonce-dependent signers). Use it whenever about to trust a reading of obfuscated JavaScript.


**Validation.** Every tool in this table is exercised over real MCP stdio against a live Chromium by `tests/test_mcp.py` — the table cannot drift from the server without breaking the suite.
