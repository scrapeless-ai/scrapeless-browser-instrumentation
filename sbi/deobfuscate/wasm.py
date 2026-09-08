"""WebAssembly under the microscope.

Modern anti-bot engines (Shape, Kasada, Geetest, ...) hide their fingerprint
hashes and bytecode VMs behind WebAssembly — unreadable in the JS sources,
invisible to coverage, and immune to JS breakpoints. The protocol can still
see it: wasm modules appear as scripts (scriptLanguage WebAssembly),
Debugger.getScriptSource returns the raw bytecode (base64), and
disassembleWasmModule streams a full disassembly. Dump the .wasm to disk for
wabt/Ghidra, read exports/imports/custom sections from the live object, and
drive exported functions through the oracle like any other boundary.
"""

import base64
import json as _json
import re

WASM_MAGIC = b"\x00asm"


def modules(engine, sid):
    """Every loaded wasm module in the target: script id, url, size hint."""
    out = []
    for (psid, script_id), info in engine.scripts.items():
        if psid != sid:
            continue
        lang = info.get("language") if isinstance(info, dict) else "JavaScript"
        url = info.get("url", "") if isinstance(info, dict) else str(info)
        if lang == "WebAssembly" or url.endswith(".wasm") or url.startswith("wasm-"):
            out.append({"script_id": script_id, "url": url})
    return out


def dump(cdp, sid, script_id, path=None):
    """Write a module's raw bytecode to a .wasm file. Tries the debugger
    first; on builds that serve no bytecode (modern Chromium returns empty
    for wasm), fall back to the network-captured body via from_network —
    production wasm arrives over the network anyway."""
    r = cdp.send("Debugger.getScriptSource", {"scriptId": str(script_id)},
                 session_id=sid, timeout=60)
    source = r.get("scriptSource", "")
    try:
        data = base64.b64decode(source)
    except Exception:
        data = source.encode()
    if data[:4] != WASM_MAGIC:
        return {"path": None, "bytes": 0, "is_wasm": False,
                "note": "debugger serves no bytecode for this build; "
                        "use Session.wasm_from_network (network-delivered modules)"}
    if path is None:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(script_id))[-40:]
        path = f"wasm-{safe}.wasm"
    with open(path, "wb") as f:
        f.write(data)
    return {"path": path, "bytes": len(data), "is_wasm": True}


def from_network(network_observer, directory):
    """Dump every wasm module captured on the wire. Shape-class engines ship
    their wasm via instantiateStreaming — the bytes pass through the Network
    domain on the way in."""
    import os
    os.makedirs(directory, exist_ok=True)
    out = []
    with network_observer.lock:
        raws = list(network_observer.raw_bodies.items())
        meta = dict(network_observer.meta)
    for rid, raw in raws:
        if raw[:4] != WASM_MAGIC:
            continue
        url = (meta.get(rid) or {}).get("url") or rid
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", url)[-60:]
        path = os.path.join(directory, f"{safe}.wasm")
        with open(path, "wb") as f:
            f.write(raw)
        out.append({"path": path, "url": url, "bytes": len(raw)})
    return out


def disassemble(cdp, sid, script_id, max_lines=4000):
    """Full disassembly via the experimental Debugger wasm APIs. Returns the
    text plus extracted function names; unavailable builds report the error
    instead of raising."""
    try:
        r = cdp.send("Debugger.disassembleWasmModule", {"scriptId": str(script_id)},
                     session_id=sid, timeout=60)
    except Exception as e:
        return {"error": f"disassembly unavailable: {e}", "functions": [], "text": ""}
    chunk = r.get("chunk") or {}
    stream_id = chunk.get("streamId")
    lines = []
    func_names = []
    while True:
        chunk_lines = chunk.get("lines") or []
        lines.extend(chunk_lines)
        for ln in chunk_lines:
            m = re.search(r"func\s+\$?([A-Za-z0-9_.\-]+)", ln)
            if m:
                func_names.append(m.group(1))
        if len(lines) >= max_lines or not stream_id:
            break
        try:
            r = cdp.send("Debugger.nextWasmDisassemblyChunk",
                         {"streamId": stream_id}, session_id=sid, timeout=60)
        except Exception:
            break
        chunk = r.get("chunk") or {}
        if not chunk.get("lines"):
            break
    return {"functions": func_names[:200], "line_count": len(lines),
            "text": "\n".join(lines[:max_lines])}


def extract_embedded(path, directory, min_bytes=64):
    """Extract wasm modules embedded as base64 inside a collected JS file
    (the Shape-class delivery: same-domain 'seed' scripts carrying
    instantiate calls). Scans for base64 runs starting with the magic."""
    import os
    os.makedirs(directory, exist_ok=True)
    data = open(path, "rb").read()
    b64magic = base64.b64encode(WASM_MAGIC)[:4]          # b"AGFz" — short prefix,
    out = []                                             # then validate the full run
    b64chars = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    for m in re.finditer(re.escape(b"AGFzbQ"), data):
        start = m.start()
        # JS authors concatenate the blob across string literals: collect b64
        # chars, tolerating junk gaps (quotes, '+', newlines) up to 512 bytes
        run = bytearray()
        i = start
        gap = 0
        while i < len(data) and gap <= 512:
            c = data[i]
            if c in b64chars:
                run.append(c)
                gap = 0
            else:
                gap += 1
            i += 1
        try:
            raw = base64.b64decode(bytes(run) + b"=" * (-len(run) % 4))
        except Exception:
            continue
        if raw[:4] != WASM_MAGIC or len(raw) < min_bytes:
            continue
        out_path = os.path.join(directory,
                                f"embedded-{os.path.basename(path)}-{len(out) + 1}.wasm")
        with open(out_path, "wb") as f:
            f.write(raw)
        out.append({"path": out_path, "bytes": len(raw),
                    "b64_offset": start, "b64_length": len(run)})
    return out


def meta(cdp, sid, module_expr, timeout=30):
    """Exports/imports/custom sections of a live WebAssembly.Module — or the
    export surface of a live Instance. `module_expr` is any JS expression."""
    expr = (
        "(() => { const v = (" + module_expr + ");"
        " if (typeof WebAssembly === 'undefined') return JSON.stringify({error: 'no WebAssembly'});"
        " try {"
        "  if (v instanceof WebAssembly.Module) {"
        "   return JSON.stringify({kind: 'module',"
        "     exports: WebAssembly.Module.exports(v),"
        "     imports: WebAssembly.Module.imports(v),"
        "     custom: WebAssembly.Module.customSections(v)"
        "       .map(s => ({name: s.name, length: s.byteLength}))});"
        "  }"
        "  if (v instanceof WebAssembly.Instance) {"
        "   return JSON.stringify({kind: 'instance',"
        "     exports: Object.entries(v.exports)"
        "       .map(([n, f]) => ({name: n, kind: typeof f}))});"
        "  }"
        "  return JSON.stringify({error: 'not a Module/Instance: ' +"
        "    (v && v.constructor && v.constructor.name)});"
        " } catch (e) { return JSON.stringify({error: String(e)}); } })()"
    )
    r = cdp.send("Runtime.evaluate",
                 {"expression": "/*sbi*/" + expr, "returnByValue": True, "silent": True},
                 session_id=sid, timeout=timeout)
    try:
        return _json.loads(r.get("result", {}).get("value") or "{}")
    except Exception:
        return {"error": "unserializable"}
