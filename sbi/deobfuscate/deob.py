"""Runtime-driven deobfuscation helpers.

JsDeObsBench numbers the problem: LLMs read obfuscated JS with ~97% syntactic
but only ~61% semantic fidelity. obfuscator.io's rotated string array is the
canonical trap — the source order is a lie, so a reimplementation copied from
source is silently wrong. The fix is to stop reading and start asking: drive
the page's own decoder over the full index range and record what it actually
returns. That mapping is ground truth for the oracle.
"""

import json


def dump_strings(cdp, sid, decoder_expr, indices=range(0, 32), timeout=60):
    """Call the page's real decoder for each index; return {index: value}.

    decoder_expr must evaluate to the decoder function, e.g.
    '_0x4c2f' or 'window._0x1a2b["at"]' — the live binding, not a copy.
    """
    out, errors = {}, {}
    for i in indices:
        expr = (f"(()=>{{try{{return JSON.stringify(({decoder_expr})({i}))}}"
                f"catch(e){{return JSON.stringify({{__error__: String(e)}})}}}})()")
        r = cdp.send("Runtime.evaluate", {"expression": "/*sbi*/" + expr,
                                          "returnByValue": True, "awaitPromise": True},
                     session_id=sid, timeout=timeout)
        try:
            v = json.loads(r.get("result", {}).get("value") or "null")
        except Exception:
            v = {"__error__": "unserializable"}
        if isinstance(v, dict) and "__error__" in v:
            errors[i] = v["__error__"]
        else:
            out[i] = v
    return {"values": out, "errors": errors}


def compare_with_source_order(runtime_map, source_array):
    """Quantify the rotation: how many indices does the static source get right?"""
    match = sum(1 for i, v in enumerate(source_array) if i in runtime_map and runtime_map[i] == v)
    return {"runtime": runtime_map, "source_order_matches": f"{match}/{len(source_array)}"}


def vm_dispatch_trace_hint(dispatch_expr):
    """Recipe for bytecode-VM tracing: hook the dispatch loop's step function;
    every pause's args read as (pc, opcode, operand). Returns the hook call."""
    return {"hook": dispatch_expr, "read": "args per call == one dispatch step",
            "note": "replay args into your own VM model and verify with the oracle"}


def vm_steps(captures, max_steps=200):
    """Format arg-captures from a hooked VM dispatch loop as (pc, opcode, operand)
    steps. Anything the interpreter pushed per dispatch is one step; reorder to
    your target's convention once you've identified it from the first steps."""
    steps = []
    for rec in captures[:max_steps]:
        args = rec.get("args")
        if isinstance(args, list):
            steps.append({"step": len(steps), "args": args})
    return steps


def vm_histogram(captures, arg_index=1):
    """Opcode-ish frequency histogram over a captured dispatch stream — the
    dominant codes are the arithmetic/compare ops; rare ones are the
    interesting handlers (string build, crypto calls)."""
    from collections import Counter
    counts = Counter()
    for rec in captures:
        args = rec.get("args")
        if isinstance(args, list) and len(args) > arg_index:
            counts[str(args[arg_index])] += 1
    return counts.most_common()
