---
name: crack-string-table
description: >
  Loop for defeating obfuscator.io-style protections — rotated string arrays,
  key-dependent decoders, bytecode VMs — by recovering the runtime truth with
  sbi instead of reading the source. Use whenever the code under analysis is
  obfuscated with string arrays/wrappers or a dispatch VM, before trusting
  any reading of it.
---

# Crack the string table, not the source

obfuscator.io rotates its string array at load time, so the array order in
the source is a lie. A decoder reimplemented from the source matches the
runtime on ~0/10 indices and fails silently. The runtime is the only
authority: drive the page's own decoder and record what it actually returns.

## 1. Recognize the pattern

```
var _0x4c2f = ['guest', 'admin', ...];        // the array (a lie)
(function (_0x1, _0x2) { ... rotate ... })    // the rotating IIFE
function _0x1a2b(_0i, _0k) { ... }            // the decoder
```

## 2. Never copy the source array

State it explicitly in your reasoning: "source order is untrusted". Any
mapping you produce without runtime confirmation is a hypothesis.

## 3. Dump the runtime mapping

```
sbi_strings decoder_expr="window._0x1a2b" n=64
# python: s.strings("window._0x1a2b", n=64) -> {values: {0: 'craig', ...}, errors: {}}
```

The decoder expression must be the live binding (heap/global/worker —
`sbi_targets` first if it lives off-window).

## 4. Key-dependent decoders: hook, don't guess

If `decoder(index, key)` or errors dominate the dump, the mapping is not a
table — it's a function of inputs you don't control. Hook it and let the
page produce ground truth:

```
sbi_hook expression="window._0x1a2b" capture_returns=true label="dec"
# trigger real page behaviour
sbi_captures label="dec"    # [{input: [index, key], output: 'string'}]
```

Every real call is a verified (input → output) pair, free.

## 5. Bytecode VM branch

When strings decode into opcodes (a dispatch loop over a byte array):

1. `sbi_coverage start` → trigger → `take`: the hottest function is the
   dispatch step.
2. `sbi_hook` the step function; `sbi_vm` formats captures as
   (pc, opcode, operand) steps plus an opcode histogram — rare opcodes are
   the interesting handlers.
3. Rebuild op semantics from the steps, then hand off to the
   verify-reimplementation skill: candidate VM vs oracle, iterate.

## 6. Deliverable

- the runtime mapping table (or decoder corpus),
- a decoder/VM candidate with `sbi_verify` / `sbi_strings`-verified status,
- anything still inferred must be labeled a hypothesis in your answer.

Nothing inferred is trusted until the diff is empty.
