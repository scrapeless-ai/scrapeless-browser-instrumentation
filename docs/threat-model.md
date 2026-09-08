# Threat model: what the target can and cannot see

Honest accounting, grounded in the code. "Invisible" below means: no page-observable JavaScript surface changes. It never means "physically undetectable" — a paused debugger is still a paused debugger.

## Adversary model

Anti-bot / fingerprinting / captcha SDKs that routinely:

- verify function identity: `fn.toString() === "function...{ [native code] }"`, own-property scans, `Object.getOwnPropertyDescriptor` checks, `Proxy` trap canaries;
- detect monkeypatching: wrapper-source leaks, `Function.prototype.toString.call(fn)` (bypasses an own `toString` override), argument-shape probing;
- detect debugging: timing deltas around `Debugger.pause`, `Error().stack` anomalies, devtools-presence heuristics;
- scan for debug ports / CDP markers (irrelevant here — the instrumentation is remote, nothing listens locally).

## Per-mechanism accounting

| Mechanism | Page-observable surface | Residual risk | Rating |
|---|---|---|---|
| **Hooks** (`setBreakpointOnFunctionCall`) | None. The function object is never touched — same identity, same toString, same descriptor, same prototype | Pause duration: while `_paused` reads args the page's JS is frozen; a timing loop can notice long pauses | Invisible (timing side channel) |
| **Return capture** (breakpoints on return locations) | None, same as hooks | Same timing channel, one extra pause per call | Invisible (timing side channel) |
| **Network capture** (Network domain, `getResponseBody`) | None — server-side recording | Response-body fetch is out-of-band; no page-visible cost | Invisible |
| **Console capture** (`Runtime.consoleAPICalled` / `exceptionThrown`) | None — the Runtime domain is already enabled for instrumentation; these events were already being sent, the observer just keeps them | None known | Invisible |
| **Trusted input** (`Input.dispatchMouseEvent` / `insertText` / `dispatchKeyEvent`) | None at the JS level — events arrive with `isTrusted: true`, indistinguishable from user input (a synthetic `el.click()` would be `isTrusted: false`; CDP input is not) | Behavioural detection of automation (timing, cadence, trajectories) is real but **out of scope** — sbi sends real, unshaped events | Invisible at the JS level (behavioural automation detection out of scope) |
| **Request interception** (`Fetch` domain fulfill / abort / continue) | None — the interception itself is not observable, only its effects: the page sees a response (mock) or a network error (abort) | With a mock no real request leaves the browser, so server-side anomaly detection never sees it either | Invisible (effects are what's observable) |
| **Dialog auto-handling** (`Page.handleJavaScriptDialog`) | The dialog gets answered: `confirm()` / `prompt()` return the policy's answer — a page inspecting return values (or the answer latency) sees a decision nobody made | Record-only is invisible; auto-accept/dismiss is behaviourally visible if the page checks what was answered | Visible-by-effect (record-only: invisible) |
| **Heap snapshot** (`takeHeapSnapshot` + parse) | None directly; snapshot forces a GC/full pause | Large heaps → noticeable jank during capture | Near-invisible (perf) |
| **Allocation sampling** (`startSampling`) | None | Configurable overhead at sampling interval | Near-invisible |
| **Coverage** (`Profiler.startPreciseCoverage`) | None | V8 instrumentation overhead | Near-invisible |
| **Script dump** (`getScriptSource`) | None | Read-only | Invisible |
| **Boundary probes** (crypto/eval/net wrappers) | **Yes.** The wrapped functions are *our* functions: an own `toString` override exists, descriptors changed (`writable/configurable` on the property), and — critically — `Function.prototype.toString.call(wrapper)` returns the wrapper's real source, bypassing the masquerade | Any SDK calling the prototype path, or diffing descriptors pre/post load | **Visible** — use for observation, not stealth |
| **Oracle isolated page** | No. Private target, Runtime-only, shares nothing with the instrumented page | None known | Invisible |
| **Live patch** (`callFunctionOn` on a heap-resolved object) | Behavioural: the value changed while no setter ran — a canary field can catch the impossible transition | Detection by invariant checks | Visible-by-effect (by design: the flip is the proof) |
| **`eval`/`sbi_eval` into the page** | Whatever your expression does is page-visible | Trivially detectable if you touch globals | Depends on you |

## Known residual risks

1. **Pause-duration timing.** Every hook hit freezes JS for the handler's runtime. The code mitigates by design: `_paused` reads one stringified value and resumes; heavy work (corpus analysis, searching, verifying) never happens on the pump thread. Do not add work there.
2. **Masquerade bypass.** `probes._masq` redefines the wrapper's own `toString` — `wrapper.toString()` lies correctly, but `Function.prototype.toString.call(wrapper)` reveals the wrapper source. This is documented, tested behavior, and the reason probes are rated visible.
3. **Probe descriptors.** Replacing `crypto.subtle.digest` etc. changes the property's descriptor (value slot used). An SDK that snapshots descriptors at load and re-checks will see drift — probes are installed *before* page scripts precisely so the wrapper is what gets snapshotted, but the prototype-toString path still leaks.
4. **Cloud session death.** `close()` ends the Scrapeless session: evidence evaporates. `save()` first, always.

## Operational hygiene

- **Authorized targets only.** This toolkit is for testing systems you own or are contracted to test.
- **Audit your hooks** (`s.audit()`): re-reads each hooked function's toString and own-property count against the baseline recorded at hook time — drift means something noticed (or the page self-modified).
- **Sanitize artifacts** (`sbi/artifacts/sanitize.py`) before sharing captures: tokens, bearer headers, cookies and high-entropy secrets are redacted; stacks and names survive.
- **Prefer hooks over probes** whenever stealth matters; reach for probes only at boundaries you cannot hook (arguments destructured at load).
