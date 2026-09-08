"""WebAssembly recon: find, dump, and read the modules a page loads.

Anti-bot engines hide their hash/VM logic in wasm. This enumerates every
loaded module, dumps the bytecode for static analysis (wabt / Ghidra /
wasm-decompile), extracts the export surface, and pulls a disassembly.

    export SBI_TARGET=https://example.com/     # any page you're authorized to test
    python examples/wasm_recon.py
"""

import json
import os

from _common import require_config, target
import sbi

require_config()

OUT = os.environ.get("SBI_WASM_OUT", os.path.join(os.getcwd(), "wasm-dump"))
os.makedirs(OUT, exist_ok=True)

with sbi.attach(target(), wait=8) as s:
    scripts = s.scripts()
    print(f"scripts: {len(scripts)} total")
    shape_like = [sc for sc in scripts
                  if any(k in (sc.get("url") or "").lower()
                         for k in ("shape", "fingerprint", "kasada", "ips.js"))]
    for sc in shape_like:
        print(f"  anti-bot-looking: {sc['url']}")

    mods = s.wasm_modules()
    print(f"wasm modules: {len(mods)}")
    if not mods:
        print(f"SKIP: {target()!r} loads no WebAssembly — pick a wasm-using target "
              "(anti-bot-protected pages are the interesting ones)")
        raise SystemExit(0)

    for m in mods:
        d = s.wasm_dump(m["script_id"], os.path.join(OUT, f"{m['script_id']}.wasm"))
        print(f"  dumped {m['url'] or '<inline>'} -> {d['path']} ({d['bytes']}B, "
              f"magic={'OK' if d['is_wasm'] else 'BAD'})")
        dis = s.wasm_disassemble(m["script_id"])
        if "error" not in dis:
            uniq = list(dict.fromkeys(dis["functions"]))
            print(f"    functions: {len(uniq)} e.g. {uniq[:8]}")
        else:
            print(f"    disassembly: {dis['error']}")

    # live export surfaces: instances the page kept on window
    inst_exprs = json.loads(s.eval(
        "(() => { try { return JSON.stringify(Object.entries(window)"
        " .filter(([k, v]) => v instanceof WebAssembly.Instance)"
        " .map(([k]) => 'window.' + k)); } catch (e) { return '[]'; } })()") or "[]")
    for expr in inst_exprs:
        print(f"  {expr}: {json.dumps(s.wasm_meta(expr))[:200]}")

    print(f"PASS: {len(mods)} wasm module(s) dumped to {OUT}")
