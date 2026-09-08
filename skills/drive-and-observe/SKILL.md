---
name: drive-and-observe
description: >
  Environment-control loop for the Scrapeless instrumentation toolkit:
  throttle/cut the network, fake geolocation, plant cookies, answer dialogs,
  click like a user, and read console/metrics while the SDK reacts. Use when
  testing how hostile client-side code behaves under degraded or manipulated
  conditions rather than reverse-engineering one function.
---

# Drive the environment, observe the reaction

The verify-or-die law still applies (see verify-reimplementation). This skill
adds the *levers*: change the world the SDK lives in, then read what it does.

## 1. Degraded network

```
sbi_network_conditions latency_ms=400 download_kbps=50     # 3G-ish
... trigger the SDK flow, read sbi_captures / sbi_console ...
sbi_network_conditions offline=true                        # hard outage
sbi_network_conditions latency_ms=0                        # restore
```

Retries, backoff, and fallback endpoints show up as hook captures and
network records. `sbi_intercept` + `abort=true` while offline proves the SDK
survives total failure (or leaks secrets into its error path).

## 2. Location and permissions

```
sbi_grant_permissions permissions=["geolocation"]
sbi_geolocation lat=52.5 lon=13.4
sbi_eval expression="new Promise((res,rej)=>navigator.geolocation.getCurrentPosition(p=>res(p.coords),rej,4000))" await_promise=true
```

Region gates often pick the fingerprint/decryption set from here.

## 3. State manipulation

```
sbi_set_cookie name="session_seed" value="controlled" url="http://127.0.0.1/"
sbi_clear_storage origin="https://target"          # reproducible runs
sbi_storage                                        # read what the SDK kept
```

## 4. Interact and record

```
sbi_click selector="#checkout"                     # trusted events, not .click()
sbi_type text="..."
sbi_console                                        # anti-debug tells, decode mistakes
sbi_screenshot path="evidence.png"                 # PNG proof
sbi_metrics                                        # heap/listeners: leak & loop check
```

Dialog storms: `sbi_dialogs policy="accept"` so the renderer never blocks.

## 5. Survive the drop

Cloud sessions die with the websocket. On any connection error:
`sbi_reconnect` — hooks/probes/intercepts/dialog policy re-arm, corpora
survive, heap state is gone (re-run sbi_objects/sbi_origin as needed).
Finish with `sbi_save`, sanitize before sharing.
