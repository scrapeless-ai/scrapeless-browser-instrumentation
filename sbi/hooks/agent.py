"""Frida-style agent scripting: inject a JS agent into the live page and
stream messages back to Python.

This is the Frida workflow, natively supported by CDP: `Runtime.addBinding`
exposes a `send` function inside the page — when the agent calls it, the
host receives a `Runtime.bindingCalled` event. The agent persists across
navigations (addScriptToEvaluateOnNewDocument) and is re-installed on every
new target the engine auto-attaches to. Agents get:

    send(data)                  # stream JSON-serializable data to Python
    rpc.myFn = (...) => ...     # Python calls it via Session.call_agent

Everything else stays the same: the agent runs in the page's own world, so
it can hook, wrap, and read exactly what the page can.
"""

import json
import threading

PREFIX = "__sbi_send_"


def install_on_session(cdp, sid, name, source):
    """Arm one agent on one session: expose the send binding, wrap the source
    with it, persist across navigations, and run in the current document."""
    binding = PREFIX + name
    cdp.send("Runtime.addBinding", {"name": binding}, session_id=sid)
    wrapped = (
        "(() => { const send = (data) => { try { " + binding + "(" +
        "typeof data === 'string' ? data : JSON.stringify(data)); } catch (e) {} };"
        " window.__sbi_agent_" + name + " = { send: send, rpc: {} };"
        " (function (send, rpc) {" + source + "})(send, window.__sbi_agent_" +
        name + ".rpc); })()"
    )
    cdp.send("Page.addScriptToEvaluateOnNewDocument",
             {"source": wrapped}, session_id=sid)
    try:
        cdp.send("Runtime.evaluate", {"expression": wrapped}, session_id=sid)
    except Exception:
        pass                          # context may be mid-navigation; script re-runs


class Agents:
    def __init__(self, cdp):
        self.cdp = cdp
        self.lock = threading.Lock()
        self.agents = {}             # name -> {records, callback, source}
        cdp.on("Runtime.bindingCalled", self._binding)

    def install(self, engine, sid, name, source, on_message=None):
        """Register + arm an agent on one session (binding + script + run)."""
        install_on_session(self.cdp, sid, name, source)
        with self.lock:
            self.agents[name] = {"records": [], "callback": on_message,
                                 "source": source}

    def _binding(self, params, session_id=None):
        name = (params.get("name") or "")
        if not name.startswith(PREFIX):
            return
        name = name[len(PREFIX):]
        payload = params.get("payload")
        try:
            payload = json.loads(payload)
        except Exception:
            pass
        with self.lock:
            agent = self.agents.get(name)
            if not agent:
                return
            agent["records"].append({"session": session_id, "payload": payload})
            callback = agent["callback"]
        if callback:
            try:
                callback(payload, session_id)
            except Exception as e:
                print(f"[sbi] agent {name!r} callback error: {e!r}")

    def drain(self, name):
        with self.lock:
            agent = self.agents.get(name)
            if not agent:
                return []
            out, agent["records"] = agent["records"], []
        return out
