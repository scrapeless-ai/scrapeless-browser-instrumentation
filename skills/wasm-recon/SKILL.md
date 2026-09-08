---
name: wasm-recon
description: >
  WebAssembly recon loop for the Scrapeless instrumentation toolkit:
  enumerate the wasm modules a page loads, dump their bytes (from the wire
  or extracted from seed scripts), disassemble them, and read their export
  surface — the layer where Shape/Kasada-class engines hide fingerprint
  hashes and payload VMs. Use when a target's interesting logic is not in
  the JS sources.
---

# Recon the wasm layer

Shape-class engines don't put their logic in readable JS: they ship
WebAssembly, often embedded base64 inside a same-domain "seed" script whose
URL carries a per-session token. URL greps for vendor names find nothing —
the wasm layer must be enumerated directly.

## 1. Enumerate

```
sbi_wasm_modules                                    # script id + url per module
sbi_scripts                                         # JS scripts, for context
```

Zero modules on an anti-bot-protected page means the engine is pure-JS
(bytecode VM in JavaScript) — switch to the coverage + dispatch-hook flow in
skills/crack-string-table.

## 2. Get the bytes

Three routes, in order of reliability:

```
sbi_wasm_from_network directory="recon/"             # instantiateStreaming deliveries
sbi_wasm_dump script_id="7" path="recon/m.wasm"      # debugger route (build-dependent)
sbi_collect_script directory="recon/js" pattern="seed"   # then:
sbi_wasm_extract_embedded js_path="recon/js/<file>" directory="recon/"
```

`wasm_extract_embedded` tolerates JS string-concatenation junk around the
base64 blob. Verify every dump starts with the `\0asm` magic.

## 3. Read them

```
sbi_wasm_disasm script_id="7"                       # full disassembly + function names
sbi_wasm_meta module_expr="window.wasmInstance"     # exports/imports/custom sections
```

Feed the .wasm files to wabt (`wasm2wat`, `wasm-decompile`) or Ghidra for
deep analysis; the disassembly from sbi is the quick first look. Export
functions are the boundary: drive them through `sbi_verify` like any other
candidate — `sbi_eval` calling the export with controlled inputs is ground
truth.

## 4. Deliverable

- every module as a .wasm artifact + a .wat disassembly,
- the export surface mapped to the behaviour it explains,
- anything not verified at runtime labeled a hypothesis.
