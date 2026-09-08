"""Tracing an obfuscator-style bytecode VM, then oracle-verifying a reimpl.

The page runs a register VM whose source comment claims r0=10; r0+=32; r0^=5.
The bytecode disagrees with its own comment — constants ride LOAD opcodes and
ADD/XOR dispatch with operand 0, so the program runs 5 dispatches, not 3. We
hook the dispatch step function (invisible breakpoint, no wrapping), read each
call's args as one (pc, opcode, operand) step, replay the arithmetic in a
Python model derived only from the trace, and let the oracle confirm the
resulting closed form against the live function.
"""

import json

from _common import require_config
import sbi

require_config()

# opcodes: 1=LOAD (r0=arg), 2=ADD (r0+=arg), 3=XOR (r0^=arg), 4=HALT
PAGE = """
<script>
(function(){
  const prog = [1,10, 1,32, 2,0, 1,5, 3,0, 4,0];
  window.regs = null;
  function step(pc, op, arg, regs) { regs[0] = op===1?arg: op===2? regs[0]+arg : op===3? regs[0]^arg : regs[0]; return pc+2; }
  window.runVM = () => { const regs=[0]; let pc=0; while (prog[pc]!==4) { pc = step(pc, prog[pc], prog[pc+1], regs); } window.regs = regs; return regs[0]; };
  window.__step = step;
})()
</script>
"""

with sbi.attach() as s:
    s.inject(PAGE)
    s.wait(0.3)

    s.hook("window.__step", label="vm")
    result = s.eval("window.runVM()")
    s.wait(0.5)

    steps = s.vm_steps()
    print("steps:", steps)
    hist = s.vm_histogram(arg_index=1)
    print("opcode histogram:", hist)

    # the trace, not the comment, is the truth: three LOADs carry the constants,
    # ADD/XOR dispatch with operand 0, and HALT (4) never reaches step()
    assert len(steps) == 5, "expected every executed dispatch to be captured"
    assert ("1", 3) in hist and ("2", 1) in hist and ("3", 1) in hist, "opcode profile off"
    assert all(isinstance(st["args"][0], int) for st in steps), "args[0] must be the int pc"

    # replay the captured dispatches in a Python model of the VM's arithmetic
    simulated = 0
    for st in steps:
        op, operand = st["args"][1], st["args"][2]
        if op == 1:
            simulated = operand        # LOAD: register takes the operand
        elif op == 2:
            simulated += operand       # ADD
        elif op == 3:
            simulated ^= operand       # XOR
    print("python replay:", simulated, "| VM returned:", result)
    assert simulated == result, "derived semantics do not reproduce the VM"

    # oracle finish: corpus from a return-capturing hook, then verify the
    # derived closed form in an isolated page that cannot see the real VM
    candidate = f"() => {simulated}"
    s.hook("window.runVM", capture_returns=True, label="run")
    s.eval("window.runVM()")
    s.wait(0.5)
    v = s.verify("window.runVM", candidate, label="run")
    print("verify:", v["verified"], f"({v['matched']}/{v['tested']})")
    assert v["verified"], "oracle rejected the derived reimplementation"
    print("PASS: VM traced, opcodes profiled, semantics replayed and oracle-verified")
