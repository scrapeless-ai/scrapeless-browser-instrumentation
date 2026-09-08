# Architecture

Deep-dive for contributors. The one-paragraph version: `sbi` speaks raw CDP over one websocket to the Scrapeless cloud browser, auto-attaches to the whole target graph, hooks functions with Debugger breakpoints on the live function object (nothing page-visible changes), captures (input → output) pairs at the function's own return locations, and verifies reimplementation candidates in an isolated page against that ground truth.

```
 CLI (python -m sbi)      MCP tools (sbi.mcp_server)      Python API (sbi.attach)
        └──────────────────────┬──────────────────────────────┘
                          Session  (sbi/api.py — the facade)
   ┌──────────┬──────────┬─────┴────┬──────────┬──────────┬──────────┐
 engine      tracer     oracle    network/   heap/       probes     trace/
 (target     (hooks +   (isolated console/   heapdiff/   (page-side artifacts
  graph)      pairs)     verify)  control/   patch/...   wrappers)  report/
                                   intercept)
   └──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
                        CDP  (sbi/core/cdp.py — sync facade)
          websocket ──► wss://browser.scrapeless.com/api/v2/browser
                          └─► page ─► workers ─► OOPIFs  (flat sessions)
```

## Transport and concurrency (cdp.py)

Two threads around one asyncio loop:

- **Reader/loop thread** runs `websockets.connect(...)` and `async for raw in ws`. Every incoming frame is either a command response (resolves a future) or an event (pushed onto a `queue.Queue`). The reader **never blocks** on handler code.
- **Pump thread** pulls events off the queue **in arrival order** and dispatches to handlers registered via `cdp.on(method, handler)`. Handlers run here, so they may issue *blocking CDP calls* — the fundamental hook pattern is exactly that: on `Debugger.paused`, read the frame with `Debugger.evaluateOnCallFrame`, then `Debugger.resume`.

Ordering guarantee: the reader enqueues an event **before** resolving the response of any command that follows it on the wire, so after `send()` returns, `flush_events()` (which joins on the queue's unfinished-task counter) proves all preceding events were handled. Heap snapshots depend on this: `takeHeapSnapshot` streams its payload as `addHeapSnapshotChunk` events and only then returns.

`send()` marshals a command onto the loop with `asyncio.run_coroutine_threadsafe`; slow commands (heap snapshots) get a longer deadline. `CDPError` carries protocol error codes; connection loss fails all pending futures.

## The engine: one flat session namespace (engine.py)

`Target.setAutoAttach {autoAttach, waitForDebuggerOnStart, flatten}` is sent at the browser level **and re-sent on every attached session**, so the cascade reaches workers and out-of-process iframes wherever they spawn. New targets arrive paused; the engine enables Runtime/Debugger/Network (+Page for document targets), installs probe sources via `addScriptToEvaluateOnNewDocument` *before* releasing with `Runtime.runIfWaitingForDebugger` — boundary recorders therefore exist before any page script of that target runs.

The registry maps flat `sessionId → targetInfo`; `resolve_session(url_substr)` is how callers target a worker/iframe. **Private targets** (the oracle's scratch page) are attached with Runtime only — no Debugger, no probes, invisible to the instrumentation and unable to see it. `Debugger.scriptParsed` events populate `(sessionId, scriptId) → url`, the map that turns [[FunctionLocation]]s into real urls.

## Lifecycle of a hook (tracer.py)

1. `hook(expression)` resolves the expression with `Runtime.evaluate` → a live function `objectId`. Its `description` (source text) and own-property count are recorded as a **baseline** for the audit.
2. If `capture_returns`: `Runtime.getProperties` internal `[[FunctionLocation]]` → `Debugger.getPossibleBreakpoints {restrictToFunction}` → every `return`-type location gets a `Debugger.setBreakpoint`; breakpoint ids map to the hook label. This happens **before** arming the entry breakpoint (the first pause can race otherwise).
3. `Debugger.setBreakpointOnFunctionCall {objectId}` — the function object itself is never wrapped, replaced or proxied.
4. On call, the target pauses twice per invocation:
   - **Entry pause** (`hitBreakpoints` empty): `_match` finds the hook; args read via `evaluateOnCallFrame("JSON.stringify(Array.prototype.slice.call(arguments))")`; resume.
   - **Return pause** (breakpoint id known): the top frame is still the callee — `callFrames[0].returnValue` plus the in-scope args form **one atomic (input, output) pair**; resume.
5. `Debugger.resume` always runs, including on handler errors.

Handler work is deliberately tiny (read, record, resume): every pause freezes the page's JS, so slow handlers are a timing side channel.

## Observers and actors on the same pump (console.py, control.py, intercept.py — 0.4)

`Session` wires three more capabilities onto the one CDP connection. None of them opens a second channel or changes page-visible JS; they are ordinary pump-thread citizens.

- **console.py — the Runtime-domain observer.** `Runtime.enable` is already on for every instrumented target (the engine turns it on before releasing it), so console output and uncaught exceptions were already streaming as `Runtime.consoleAPICalled` / `Runtime.exceptionThrown` events. `Console` just registers two handlers on the same pump thread and keeps a tape of `{kind, level, text, stack (top 5 frames), session}` records — no new domain is enabled, nothing page-visible changes. `Session.console()` drains the tape, `Session.grep()` searches it alongside hook captures and network records, `save()` embeds it in the artifact, `report()` renders it.
- **control.py — Input/Page domain calls.** Plain protocol calls, no Puppeteer/Playwright. `screenshot()` sends `Page.bringToFront` **before** `Page.captureScreenshot` — the bring-to-front is required because a backgrounded tab's compositor may never produce a frame and the capture would wait forever (targets without a widget, e.g. workers, skip it and may still capture). `click()` dispatches a trusted `Input.dispatchMouseEvent` press/release pair at viewport coordinates; `click_element()` resolves the element's center via `getBoundingClientRect` first and returns the `(x, y)` it clicked; `type_text()` uses `Input.insertText` (IME-safe); `press_key()` sends raw key down/up; `cookies()` and `storage()` dump state for the evidence trail.
- **intercept.py — Fetch domain rules per session.** `Session.intercept(pattern, ...)` appends a rule (mock with `status`/`body`/`headers`/`content_type`, `abort=True`, or `passthrough=True`) to that flat session's ordered rule list, then re-arms `Fetch.enable` with the full pattern set — `Fetch.enable` *replaces* the pattern list, so `add()` disarms and re-arms under a reentrant lock (the lock is reentrant precisely because `_arm()` re-reads the rules). `Fetch.requestPaused` is handled on the pump thread like any event: the first matching rule (fnmatch or prefix) decides — `Fetch.fulfillRequest` with the canned response, `Fetch.failRequest` (abort), or `Fetch.continueRequest` (passthrough / no match). Handler errors fall back to a continue so the page never stalls on a paused request.

Two further modules ship as direct helpers (construct them against the session's `cdp`; not yet wired onto `Session`): `dialogs.py` records `Page.javascriptDialogOpening` to a capped tape and can auto-accept/dismiss via `Page.handleJavaScriptDialog`, and `emulation.py` issues per-session UA / locale / timezone / viewport overrides.

## The oracle's isolation (oracle.py)

`verify(fn_expr, candidate, label, fresh_inputs)`:

- Ground truth = the label's corpus (captured pairs) + `query_live` results of driving the real function with fresh inputs.
- The candidate runs via `run_candidate` on the **private scratch page** (`engine.open_isolated_page`). That page has no Debugger, no hooks, and cannot reference the instrumented targets — a candidate that "cheats" by calling the real function throws.
- Comparison is `matching.compare(expected, got, mode)` — `exact` by default (bool≠1, "1"≠1, order matters), with structural modes for nonce/time-dependent outputs.
- Result: `{verified, tested, matched, mismatches:[{input, expected, got, source}], coverage_notes}` — counterexamples first, coverage honesty always (unserializable outputs and live-query errors are counted, never silently dropped).

`trace.offline_verify` re-runs the same comparison in a bare Node subprocess against a saved corpus: no browser, no network — a candidate that calls home fails there.

## Heap model (heap.py, heapdiff.py, patch.py, functions.py)

`takeHeapSnapshot` → chunks (events) → `flush_events` → one JSON document: flat `nodes`/`edges` arrays with strides from `snapshot.meta`. `Snapshot` indexes nodes by id, walks edges forward, and builds a reverse-edge map for **retainer paths** (`retainers`), rendered as `.prop on object:Name` steps. `heapdiff` diffs two snapshots by node id (new ids = new allocations, each with retainers). `functions` filters closure nodes and resolves each through `getObjectByHeapObjectId` → `[[FunctionLocation]]` → engine's script registry. `patch` mutates the live object behind a snapshot id via `Runtime.callFunctionOn` — the closure keeps the same object; only the field changes.

## Session lifecycle (api.py)

`attach()` builds the endpoint (token → `wss://browser.scrapeless.com/api/v2/browser?...`; an `http://` devtools URL is resolved to its `webSocketDebuggerUrl`), connects, starts the engine, opens the page and optionally navigates. `Session.__init__` also wires the network recorder, the console observer and the interceptor onto the connection — the last two are inert until their Session methods are used. `close()` closes the websocket — for Scrapeless that **ends the cloud session**: all heap state, hooks and un-drained evidence die with it. Hence the artifact discipline: `save()` before `close()`, `replay.apply()` to re-establish recorded hooks on the next session, `sanitize` before sharing.

## Extension points

- **New capability module**: `sbi/<subpackage>/foo.py` with pure functions over `(cdp, sid, ...)`, a thin `Session.foo()` facade method in `api.py`, coverage in `tests/test_offline.py`'s fake server, an example, a docs blurb. Stdlib-only.
- **Probes vs hooks**: probes (`sbi/hooks/probes.py`) are main-world wrappers — they see destructured references taken at load but are patching (detectable in principle; toString/name masqueraded). Hooks are breakpoints — invisible but only see call-time. Choose per target hardness.
- **MCP**: every `Session` method is one `@mcp.tool()` away; the skill files teach agents the loops.
