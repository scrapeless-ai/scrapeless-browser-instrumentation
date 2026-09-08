---
name: verify-reimplementation
description: >
  Loop for reverse-engineering a hostile JS function (signer, decoder, token
  builder) in the Scrapeless browser: form a hypothesis from the source, hook
  the live function invisibly to capture ground truth, verify the
  reimplementation against it with the oracle, and iterate until the diff is
  empty. Use whenever about to trust a reading of obfuscated JavaScript.
---

# Verify before you trust

Reading obfuscated JS is a hypothesis, not a fact (LLMs: ~97% syntactic,
~61% semantic on JsDeObsBench). Never ship a reimplementation that has not
passed the oracle. Every step below uses the `sbi` MCP tools or the `sbi`
Python API against the live Scrapeless session.

## 1. Capture ground truth (invisible hooks)

```
sbi_attach url="https://target/"
sbi_hook expression="window.sign" capture_returns=true label="sign"
# trigger the page behaviour that calls the function (navigate, click, sbi_eval, ...)
sbi_captures label="sign"
```

The hook is a Debugger breakpoint on the live function object — nothing is
replaced, so anti-tamper checks (`fn.toString()`, Proxy traps) see nothing.

- Closure-internal functions: hook by expression reachable from the target,
  or find the holder with `sbi_objects(contains=...)` / `sbi_origin(value)`.
- Workers/iframes: pass `target_url` (a url substring) — auto-attach already
  follows the whole target graph.
- Rotated string arrays: do NOT copy the source array. Dump the real mapping:
  `sbi_strings(decoder_expr="window._0xab", n=64)`.
- Boundary truth: `sbi_probe action="install" names=["crypto"]` then drain —
  shows plaintext entering crypto.subtle (this one is patched, use to observe,
  not to be stealthy).

## 2. State the candidate

Write the reimplementation as a self-contained JS function expression. No
references to page globals — it must survive alone:

```
sbi_verify fn_expr="window.sign" candidate="(u,p)=>btoa(u+':'+(p*7+1))" label="sign"
```

It runs in an isolated page that cannot see the real function, against the
captured corpus plus `fresh_inputs` queried live.

## 3. Read the diff, fix, repeat

`verified: false` comes with concrete counterexamples (`input / expected /
got`). Fix the candidate, re-verify. Done only when `verified: true` AND
coverage is honest:

- If outputs are `unserialized` (objects, buffers), the corpus pair can't be
  compared — either make the candidate return primitives for testing, or
  verify on fresh primitives-only inputs.
- Grow the corpus with more varied calls before trusting a high `matched`
  count on thin data.
- Save the artifact for offline re-verification: `sbi_save path="trace.json"`.

## 4. Red-team the result

- Does the candidate hold for empty/unicode/large inputs? Add them to
  `fresh_inputs`.
- Is the live function time- or nonce-dependent? Then corpus pairs and fresh
  queries must be compared structurally (e.g. same length/charset), and you
  must hook the nonce source instead.
- Anything still inferred is untrusted. Say so explicitly in your answer.
