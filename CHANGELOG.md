# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - frida-trace

### Added
- **`Session.trace_calls(contains)`** / MCP `sbi_trace_calls`: the frida-trace move — hook every function matching a name across live closures (heap-resolved, so window-unreachable ones included) and log their calls to the capture stream. Pair with `sbi_captures`/`sbi_grep` to watch a whole subsystem execute.

## [1.2.0] - Frida-style agent scripting

### Added
- **Agent scripting** (`sbi/agent.py`): the Frida workflow, natively via CDP — `Session.load_agent(name, source)` injects a JS agent into every instrumented target (persists across navigations, re-installed on auto-attached targets). Agents get `send(data)` (Runtime.addBinding bridge -> `Runtime.bindingCalled` -> Python callback/drain) and an `rpc` object callable from Python via `Session.call_agent`. `agent_messages(name)` drains the tape.
- MCP tools `sbi_load_agent`, `sbi_agent_messages`, `sbi_call_agent` — **79 tools**, doc-verified 79/79.
- Live test: agent birth-message, rpc call, and re-run persistence across documents.

## [1.1.0] - Ergonomics: condition waits, corpus growth, response match/replace

### Added
- **`wait_for(expression)` / `wait_for_url(substring)`**: condition-based waiting — no blind sleeps between action and observation.
- **`capture_inputs(label, fn_expr, inputs)`**: drive the live function with controlled inputs and persist the ground truth into the corpus — artifacts and offline verification then carry exactly what was proven.
- **Response-stage match/replace**: `intercept(..., stage="response", edit=[(regex, replace), ...])` rewrites the ORIGINAL response body on the way through (interception stream read + re-fulfill), not just full replacement.
- **`type_into(selector, text)`** — focus + trusted typing in one call.
- `save()` now records the loaded wasm modules in trace metadata. MCP tools `sbi_wait_for`, `sbi_capture_inputs`, `sbi_type_into`; `sbi_intercept` gained `stage`/`modify`/`edit` params — **76 tools**, doc diff-verified 76/76.
- Failure diagnostics for the intermittent full-suite event-starvation flake (faulthandler + pump/queue state dump in test_15).

## [1.0.0] - Two-stage interception, environment stress, the last Frida gaps

### Added
- **Two-stage interception** (`sbi/intercept.py` v2): request-stage rules can now **continue with edits** (`modify={url, method, headers, body}` — the Burp "intercept and edit" move) and **response-stage rules** replace bodies on the way out (`stage="response"`). The page can't tell an edit from the origin.
- **Environment stress**: `cpu_throttle(rate)` (Emulation.setCPUThrottlingRate — proof-of-work and timing checks surface), `emulate_media(feature, value)`, `cache('disable'|'enable'|'clear')`, `bypass_csp(True)` (Page.setBypassCSP — the fix for strict-CSP targets refusing injected probes).
- **Reach**: `screenshot_element(selector)` (clip to bounding rect), `scroll(x, y, delta_y)` (trusted wheel), `idb()` (IndexedDB inventory), `call_object(heap_id, fn, args)` (any function against a live heap-resolved object — the general form of patch).
- New agent skill `skills/wasm-recon` — the validated Starbucks Shape flow as a reusable loop. MCP surface: **73 tools**.
- Live tests: CPU-throttle timing delta, response-stage modification, element screenshot, bypass-CSP injection.

## [0.9.0] - Frida-grade breadth: static deob, environment probes, interoperability

### Added
- **Static deobfuscation** (`sbi/deobf.py`): `Session.deobfuscate()` runs collected scripts through webcrack (string arrays, control flow, unminify, bundle splitting); `Session.beautify()` via prettier. Bridges the runtime captures to the node deobfuscation ecosystem — webcrack output is a reading aid, runtime captures stay the source of truth.
- **Fingerprint + DOM probes**: `sbi_probe names=["fingerprint"]` records canvas 2D/WebGL/Audio reads and battery queries (exactly what Shape/Kasada-class engines harvest); `names=["dom"]` records DOM mutations via MutationObserver (injected iframes/scripts).
- **Interoperability**: `Session.export_har()` (HAR 1.2 from captured traffic), `save_state()`/`load_state()` (storageState-style cookies + storage snapshots for reproducible authenticated sessions), `replay_request()` (Burp-style repeat from inside the page), `dom_snapshot()`.
- 7 MCP tools (`sbi_deobfuscate`, `sbi_export_har`, `sbi_save_state`, `sbi_load_state`, `sbi_replay_request`, `sbi_dom_snapshot`, plus probe choices fingerprint/dom) — **66 tools**.

### Fixed
- **Pump sends are bounded (5s)**: hook-path CDP sends run on the event thread while the page is paused; a hung send (hostile page, OS-level socket wedge) previously blocked the pump for up to 30s each, silently slowing entire suite runs to a crawl. Full suite now runs ~2x faster and the intermittent event-starvation flakes are gone.
- HAR response/request pairing (response records now carry request_id).

### Removed
- Anti-bot engine detection (scrapfly-style) — intentionally left out; detection will be added separately.

## [0.8.0] - WebAssembly recon

### Added
- **`sbi/wasm.py`**: the wasm story end to end — `wasm_modules()` (scriptParsed scriptLanguage route), `wasm_dump()` (debugger bytecode route), `wasm_from_network()` (wire capture; binary bodies now kept as bytes), `wasm_disassemble()` (Debugger.disassembleWasmModule streaming + function-name extraction), `wasm_meta()` (exports/imports/custom sections of a live Module or Instance), `wasm_extract_embedded()` (base64 modules embedded in JS 'seed' files, tolerant of string-concatenation junk), `Session.collect_script()` (save specific JS/wasm files by url pattern or script id).
- Engine tracks `scriptLanguage` per parsed script.
- MCP tools (wasm family + collect_script) — **59 tools**, doc diff-verified 59/59.
- `examples/wasm_recon.py`; live test drives a hand-assembled wasm module through enumerate -> network-dump -> meta -> oracle.

### Validated against real Shape Security (Starbucks sign-in, observation only)
- 100 scripts parsed; the Shape payload hides as a same-domain `vendor2.js?seed=<token>` script (no 'shape' string anywhere).
- 2 live wasm modules found and **fully disassembled** (204 + 1399 lines) — .wat artifacts saved.
- Delivery recovered: the seed script embeds both modules as **base64**, extracted to valid .wasm files (1859B + 3082B) via wasm_extract_embedded.

## [0.7.0] - Environment control

### Added
- **Environment levers** (`sbi/control.py` + Session): `throttle(latency_ms, kbps)` / `offline(on)` (Network.emulateNetworkConditions — feed the SDK a 3G link or an outage and watch its retry/backoff), `geolocation(lat, lon)` + `grant_permissions`, `set_cookie`, `clear_storage(origin)` (reproducible runs).
- Trace artifacts now carry the JS-dialog tape (`extra.dialogs`) and markdown reports render a "JS dialogs" section.
- **52 MCP tools** (+`sbi_network_conditions`, `sbi_geolocation`, `sbi_grant_permissions`, `sbi_set_cookie`, `sbi_clear_storage`), doc diff-verified 52/52; new agent skill `skills/drive-and-observe` (the environment-control loop).
- Test-coverage gaps closed: `data:`-URL navigation rejection, `save(sanitize=True)` redaction roundtrip, report dialogs section, and the `--doctor` CLI exit path (subprocess test).

## [0.6.0] - Resilience & visibility

### Added
- **`Session.reconnect()`**: rebuild the transport after a websocket drop and re-arm everything — expression hooks, boundary probes, blackbox, dialog policy, intercept rules (interceptor now keeps a rule log for replay). Corpora and captures survive; heap state is inherently gone.
- **CPU profiling** (`Session.profile(action)`): Profiler-domain hot functions by sample hits — coverage counts calls, profiling counts time. The example proves the heavy loop outranks the cheap work.
- **`Session.metrics()`**: Performance-domain counters (heap, listeners, frames) — bloat and loop detectors.
- **`Session.pdf()`**: Print-to-PDF evidence for long pages (headless builds).
- MCP tools `sbi_reconnect`, `sbi_metrics`, `sbi_profile`, `sbi_pdf` — **47 tools**, `docs/mcp-tools.md` diff-verified 47/47.
- `examples/profile_demo.py`; CI live job gained a Windows leg.

## [0.5.0] - Ready & prepared: dialogs, emulation, doctor

### Added
- **Dialog handling** (`sbi/dialogs.py`): `Page.javascriptDialogOpening` recorded per session (capped ring); `Session.set_dialog_policy('accept'|'dismiss')` answers from the event thread so an `alert()` storm can't stall the renderer. `Session.dialogs()` drains.
- **Per-session emulation** (`sbi/emulation.py`): `Session.emulate_locale/emulate_timezone/emulate_device/emulate_ua/set_script_execution/clear_emulated_device` — region/locale/device-restricted behavior without touching the gateway's fingerprint stack (in-page visible; caller's choice).
- **`sbi doctor`** (`sbi/doctor.py`, CLI `python -m sbi --doctor`, MCP `sbi_doctor`): readiness self-check — deps, node, mcp, token, endpoint resolution, live browser probe (`/json/version`).
- MCP tools `sbi_dialogs`, `sbi_emulate`, `sbi_doctor` — surface now **43 tools**, `tests/test_mcp.py` asserts the registry and `docs/mcp-tools.md` is diff-verified 43/43 against the server.
- `examples/intercept_demo.py`: mock-fed config + console + trusted click + screenshot evidence in one session.
- CLI flags `--doctor` and `--dialog-policy`.

### Fixed
- `tests/test_offline.py` test_27 assertion (params double-wrap) caught by full-suite ordering.

## [0.4.0] - Observability & control

### Added
- **Console capture** (`sbi/console.py`): `Runtime.consoleAPICalled` + `exceptionThrown` recorded per session; `Session.console()` drains, `grep()` includes it, trace artifacts and markdown reports carry it. Hostile SDKs log tells (anti-debug notices, decode mistakes).
- **Browser control** (`sbi/control.py`): trusted clicks (`click`, `click_element` via live `getBoundingClientRect`), `type_text`/`press_key` (Input domain), `screenshot` (PNG evidence; `Page.bringToFront` first — a backgrounded tab's compositor never produces a frame and capture would hang forever), `cookies`, `storage` (localStorage/sessionStorage dump).
- **Request interception** (`sbi/intercept.py`): Fetch-domain rules per session — mock (`status/body/headers`), `abort`, or `passthrough`. The page only sees the response: a mock is indistinguishable from the real server. Feeding an SDK canned/broken endpoints reveals decoder/signer error paths.
- `Session.inject(html)` — the reliable pattern for test targets (top-level `data:` navigation is blocked in Chrome); all 11 injecting examples now use it.
- 7 new MCP tools: `sbi_console`, `sbi_cookies`, `sbi_storage`, `sbi_screenshot`, `sbi_click`, `sbi_type`, `sbi_intercept`, `sbi_clear_intercepts` — the whole surface again exercised over real stdio by `tests/test_mcp.py`.

### Fixed
- `Interceptor` deadlock: `add()` held a non-reentrant lock while `_arm()` re-acquired it.
- MCP `sbi_intercept` silently dropped the `headers` argument (schema omitted it) — opaque-origin mocks failed CORS; now passed through and tested.
- Screenshot hang after opening a second page: fixed via `Page.bringToFront` before capture.
- `tests/test_mcp.py` fixture correctness: all-script `document.write` leaves no `<body>`; promise-returning evals need `await_promise`.

## [0.3.1] - MCP integration hardening

### Added
- `tests/test_mcp.py`: the whole tool surface (32 tools) is exercised over **real MCP stdio** — `python -m sbi.mcp_server` spawned as a subprocess, driven exactly like an MCP client, against live Chromium, in one scripted agent conversation per flow (capture/verify/watch, locate/act incl. heapdiff + live patch + auto_hook, artifacts incl. save/sanitize/report/replay/close). Skips without a browser.
- `engine.navigate` now rejects top-level `data:` URLs with guidance (blocked/unreliable in Chrome — inject via `document.write` or serve over `http://127.0.0.1`), instead of failing confusingly later.

### Fixed
- `corpora()` returned full pair lists where its name and consumers (MCP `sbi_captures` -> `corpus_sizes`) promised counts; the report path now reads raw pairs directly.

## [0.3.0] - Operator ergonomics

### Added
- **UA stealth for direct CDP**: local headless Chrome no longer advertises `HeadlessChrome` — UA + client hints are overridden per session (Scrapeless's own fingerprint stack is untouched).
- **`new_page()`**: additional instrumented pages; created on about:blank so instrumentation precedes the real load.
- **`auto_hook()`**: coverage-guided auto-hooking by **live object** — hooks the functions that actually ran, including closures unreachable from `window` (`tracer.hook_remote`).
- **`watch(expression)`**: poll-and-record value timelines (token rotation, counters).
- **`trace_value(value)`**: one value, full journey — hook captures, corpus pairs, network records, heap holder.
- MCP tools `sbi_auto_hook`, `sbi_watch`, `sbi_trace_value`, `sbi_new_page`; audit tolerates object-armed hooks without a toString baseline.
- `scripts/live_battery.py`: one command launches a throwaway headless Chromium and runs all 13 examples + live tests; CI gained a `live` job running real Chrome on ubuntu.

## [0.2.0] - Locate & act

### Validated live
- Full feature battery run against real Chrome 152 (headless CDP): all 13 examples pass; `tests/test_live.py` encodes the end-to-end contract (invisible hook + arrow-arg capture, oracle reject/accept, heap value + holder) and skips when no browser endpoint answers.

### Fixed (found only by live testing)
- Duplicate flat CDP sessions for one target double-delivered every pause; the engine now dedups by targetId and never instruments a target twice.
- Hook pauses are routed by the arming `breakpointId` from `hitBreakpoints` instead of function-location matching, which misrouted a second hook sharing a location.
- Arrow functions have no `arguments` binding: args are now recovered from the paused frame's scope chain (verified live).
- Heap string nodes are not resolvable via `getObjectByHeapObjectId`; value search now exposes the nearest object `holder` instead.
- Runtime-concatenated strings are invisible to heap search until flattened (V8 ropes); `follow()` reports this honestly.
- `attach()` now honors `SCRAPELESS_CDP_URL`, matching the MCP server.

### Added

- Heap diff: `Session.heapdiff(action=...)` takes a snapshot, evaluates a JS
  action, snapshots again, and reports what the action allocated.
- Live patch: evaluate patches against running pages from captures and traces
  without losing the original function objects.
- Coverage-guided hooking: precise per-function coverage (`Session.coverage`)
  to find which code actually executed before choosing hook targets.
- Function index: index live closures matching a pattern with URL and location
  (`Session.functions`) to locate unnamed or buried functions.
- Dataflow follow: track how captured values propagate through the page.
- VM trace helpers: step and trace VM-style obfuscated code (per-script
  stepping, blackboxed stacks).
- Audit: verify that every installed hook is still intact on the live function
  object (`Session.audit`).
- Blackbox: mark URL patterns to skip in stacks and stepping
  (`Session.blackbox`, CLI `--blackbox`).
- Report: render a markdown report of a session (captures, pairs, coverage,
  audit) via `Session.report`.
- Script dumping for static analysis (`Session.dump_scripts`).
- CLI flags: `--coverage`, `--functions`, `--heapdiff-action`,
  `--dump-scripts`, `--report`, `--repl`, plus `--blackbox`.
- MCP tool expansion for the new locate/act features.

### Changed

- `flush_events` is now deterministic: it drains exactly the events that were
  buffered when it was called.

## [0.1.0] - Initial release

### Added

- Invisible hooks: breakpoints on the live function object via CDP — nothing
  wrapped or replaced, so `fn.toString()` checks and monkeypatch detectors see
  nothing.
- Oracle: reimplementation hypotheses checked against captured ground truth
  with `Session.verify`.
- Heap search: query live heap objects for captured values.
- Probes: boundary recorders (crypto, eval, net) installed before page scripts.
- Network capture correlated with hook captures.
- Deobfuscation helpers for captured scripts.
- Trace artifacts: save/load full session traces as JSON.
- MCP server exposing the session over tools.
- CLI (`python -m sbi` / `sbi`) with hooks, probes, grep, and trace output.
- Offline test suite (no browser required).

[1.3.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scrapeless-ai/scrapeless-browser-instrumentation/releases/tag/v0.1.0
