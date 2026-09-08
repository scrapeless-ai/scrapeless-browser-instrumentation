---
name: find-and-hook
description: >
  Locate the function behind an observable behaviour (signer, decoder, token
  minter, fingerprint collector) in a hostile bundle without reading all of
  it: triage from the network/crypto boundary inward, shortlist with coverage
  and the closure index, follow values through the heap, then hook and confirm
  with one capture. Use when you know the artifact but not the function that
  produces it.
---

# Find what to hook

You know the artifact — a header value, a body field, a token — not the
function. Do not read the megabyte mangled bundle; interrogate the live page,
outside-in, until a hook capture proves the candidate.

## 1. Triage outside-in

Network first — find where the artifact leaves the page:

```
sbi_attach url="https://target/"
# reproduce the behaviour, then:
sbi_grep needle="x-signature"        # regex=true when the format varies
```

`sbi_grep` searches hook captures and network records/bodies; note the
request that carries the artifact and the script url that likely made it.

Crypto boundary next. Wrappers must exist before page scripts run, so make
the probe call your first (the session attaches lazily), then navigate:

```
sbi_probe action="install" names=["crypto", "net"]
sbi_attach url="https://target/"
# reproduce the behaviour, then:
sbi_probe action="drain"
```

- Drain shows plaintext entering `crypto.subtle` (op, args IN, output OUT).
  That plaintext is the artifact's pre-image: a distinctive fragment of it is
  your next `sbi_grep` needle.
- Probes are patched wrappers (masqueraded but detectable by a determined
  SDK) — observe the boundary with them, capture stealthily with `sbi_hook`.
  Runtime inspection comes last.

## 2. Coverage-guided shortlist

```
sbi_coverage action="start"
# reproduce the behaviour exactly once (navigate, click, sbi_eval the trigger)
sbi_coverage action="take"
sbi_coverage action="stop"
```

- `take` ranks executed functions by call count, each with url + script_id.
- Filter by heuristic: name matches /sign|token|hmac|enc|digest|finger/, url
  is the script the artifact came from.
- Call counts are signal: once per request = signer candidate; bursts = a
  retry/rotation loop you would otherwise miss.

## 3. Closure index

```
sbi_functions regex="sign|sig|hmac|token|encrypt"
```

- Live closures — including ones unreachable from `window` — with (mangled)
  name, url, location (script_id/line/column), and heap_object_id.
- Map script_id via `sbi_scripts`; read just that function's neighborhood
  with `sbi_source(script_id=...)`, or `sbi_dump_scripts` for offline files.
- Fully mangled names: try fragments (`contains="0x"`, chunk-name regexes) —
  the heap keeps names minifiers thought they dropped.

## 4. Value-first when names lie

Start from a known output value (the token seen on the wire):

```
sbi_origin value="eyJhbGciOi"
sbi_objects contains="signature" with_retainers=2
```

- Retainer paths name the objects and properties holding the value — the
  holder's methods are your hook candidates.
- Pin the minting moment: `sbi_heapdiff` around the action that produces the
  artifact (`action="document.querySelector('#go').click()"`) — allocated
  nodes with retainer paths are the material trail.

## 5. Workers and iframes

```
sbi_targets
```

The minting code is often not in the main page. Pass `target_url` (a url
substring): `sbi_hook expression="self.sign" target_url="worker.js"`, or the
shorthand `expression="self.sign@@worker.js"`.

## 6. Hook, trigger, confirm

```
sbi_hook expression="window.sign" capture_returns=true label="sign"
# trigger the behaviour
sbi_captures label="sign"
```

- `capture_returns=true` records (input -> output) pairs for the oracle.
- One confirmed capture beats an hour of reading: args match the boundary
  plaintext, call count matches the request count — found (`sbi_audit` to
  confirm the hooks left no trace).
- Hand off to the `verify-reimplementation` skill: reimplement the function
  and verify against the captured corpus until the diff is empty.
