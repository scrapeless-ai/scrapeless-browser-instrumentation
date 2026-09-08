"""Invisible function hooks.

Hooks are Debugger.setBreakpointOnFunctionCall on the live function object: it
is never wrapped or replaced, so fn.toString(), Proxy traps and monkeypatch
detectors see nothing, and evaluateOnCallFrame reads the real closure instead
of an isolated world.

For (input, output) corpus pairs we additionally breakpoint the function's own
return locations — found via getPossibleBreakpoints(restrictToFunction). At
those pauses the top frame is still the callee, so the arguments (in scope)
and callFrames[0].returnValue are read atomically: the pair belongs together
even when the page keeps running underneath us.
"""

import json
import threading

GW = "/*sbi*/"   # sentinel so our own evals stay out of the eval probe
# `arguments` exists in normal functions (sloppy and strict) but not in arrow
# functions — typeof probe keeps arrows from throwing; their parameters are
# then recovered from the paused frame's scope chain (see _args_from_scopes).
ARGS = (GW + "((typeof arguments !== 'undefined') ? "
        "JSON.stringify(Array.prototype.slice.call(arguments)) : null)")


def _own_props(engine, object_id, sid):
    """Baseline own-property count, recorded so the audit can detect drift."""
    try:
        props = engine.cdp.send("Runtime.getProperties",
                                {"objectId": object_id, "ownProperties": True},
                                session_id=sid)
        return len(props.get("result", []))
    except Exception:
        return None


class Tracer:
    def __init__(self):
        self.captures = []          # arg-only records, every hook
        self.pairs = {}             # label -> [{input, output, output_type}]
        self.lock = threading.Lock()
        self.verbose = False
        self.engine = None
        self.hooks = []
        self.ret_bps = {}           # return-location breakpointId -> label
        self.by_call_bp = {}        # call breakpointId -> hook (exact routing)
        self.by_location = {}       # (sid, scriptId, line, col) -> hook (fallback)

    def attach(self, engine):
        self.engine = engine
        engine.cdp.on("Debugger.paused", self._paused)
        return self

    def corpus(self, label):
        with self.lock:
            return list(self.pairs.get(label, []))

    def corpora(self):
        with self.lock:
            return {k: list(v) for k, v in self.pairs.items()}

    def hook(self, expression, target_url=None, capture_returns=False, label=None):
        sid = self.engine.resolve_session(target_url)
        obj = self.engine.cdp.send("Runtime.evaluate",
                                   {"expression": GW + expression, "silent": True},
                                   session_id=sid).get("result", {})
        if obj.get("type") != "function" or not obj.get("objectId"):
            raise RuntimeError(f"{expression!r} is not a function in "
                               f"{target_url or 'page'}: {obj.get('description') or obj.get('type')}")
        return self._arm(sid, obj, expression=expression, target_url=target_url,
                         label=label, capture_returns=capture_returns)

    def hook_remote(self, object_id, sid=None, label=None, capture_returns=False):
        """Hook a live function by objectId — for closures the heap resolved
        but no expression reaches (functions.py's live_object_id)."""
        if sid is None:
            sid = self.engine.page_session
        return self._arm(sid, {"objectId": object_id, "type": "function"},
                         expression=None, target_url=None,
                         label=label or f"object:{object_id}", capture_returns=capture_returns)

    def _arm(self, sid, obj, expression, target_url, label, capture_returns):
        hook = {"label": label, "expression": expression, "session": sid,
                "target_url": target_url, "returns": capture_returns, "ret_set": False,
                "signature": obj.get("description"), "own_props": _own_props(
                    self.engine, obj.get("objectId"), sid)}
        if capture_returns:
            # map the location BEFORE arming the call breakpoint: the first
            # entry pause fires the moment the breakpoint exists
            loc = self._location(obj["objectId"], sid)
            if loc:
                self.by_location[(sid, loc.get("scriptId"), loc.get("lineNumber"),
                                  loc.get("columnNumber"))] = hook
            with self.lock:
                self.pairs.setdefault(hook["label"], [])
                self.hooks.append(hook)
        else:
            with self.lock:
                self.hooks.append(hook)
        bp = self.engine.cdp.send("Debugger.setBreakpointOnFunctionCall",
                                  {"objectId": obj["objectId"]}, session_id=sid)
        if bp.get("breakpointId"):
            # route pauses by the arming breakpoint id: location matching alone
            # would misroute a second hook whose function shares a location
            self.by_call_bp[bp["breakpointId"]] = hook
        return hook

    def _location(self, object_id, sid):
        try:
            props = self.engine.cdp.send("Runtime.getProperties",
                                         {"objectId": object_id, "ownProperties": False},
                                         session_id=sid, timeout=5)
            for ip in props.get("internalProperties", []):
                if ip.get("name") == "[[FunctionLocation]]":
                    return (ip.get("value") or {}).get("value")
        except Exception:
            pass
        return None

    # -- event ------------------------------------------------------------

    def _paused(self, params, session_id=None):
        frames = params.get("callFrames", [])
        hit = set(params.get("hitBreakpoints") or [])
        labels = [self.ret_bps[b] for b in hit if b in self.ret_bps]
        if labels and frames:
            self._pair(labels[0], frames[0], session_id)
            return self._resume(session_id)
        hooked = [self.by_call_bp[b] for b in hit if b in self.by_call_bp]
        if hooked and frames:
            hook = hooked[0]
            if hook["returns"]:
                if not hook["ret_set"]:
                    self._set_return_bps(hook, frames[0], session_id)
            else:
                self._args(frames, session_id)
            return self._resume(session_id)
        if frames:
            hook = self._match(frames[0], session_id)
            if hook and hook["returns"]:
                if not hook["ret_set"]:
                    self._set_return_bps(hook, frames[0], session_id)
                return self._resume(session_id)
            self._args(frames, session_id)
        self._resume(session_id)

    def _match(self, frame, sid):
        loc = frame.get("functionLocation") or {}
        hook = self.by_location.get((sid, loc.get("scriptId"),
                                     loc.get("lineNumber"), loc.get("columnNumber")))
        if hook:
            return hook
        # entry pause before we could map the location: match if exactly one
        # return-capturing hook on this session is still pending
        pending = [h for h in self.hooks
                   if h["returns"] and not h["ret_set"] and h["session"] == sid]
        return pending[0] if len(pending) == 1 else None

    def _set_return_bps(self, hook, frame, sid):
        try:
            locations = self.engine.cdp.send(
                "Debugger.getPossibleBreakpoints",
                {"start": frame["functionLocation"], "restrictToFunction": True},
                session_id=sid, timeout=5).get("locations", [])
        except Exception:
            locations = []
        count = 0
        for rl in (l for l in locations if l.get("type") == "return"):
            try:
                bp = self.engine.cdp.send("Debugger.setBreakpoint", {"location": rl},
                                          session_id=sid, timeout=5).get("breakpointId")
            except Exception:
                bp = None
            if bp:
                self.ret_bps[bp] = hook["label"]
                count += 1
        hook["ret_set"] = True
        if not count:
            print(f"[sbi] no return location found for {hook['label']!r}; corpus stays empty")

    def _pair(self, label, frame, sid):
        args = self._eval_args(frame, sid)
        rv = frame.get("returnValue") or {}
        rec = {"input": args, "output": rv.get("value"), "output_type": rv.get("type")}
        if "value" not in rv and rv.get("type"):
            # objects/buffers don't come back by value; keep a description instead
            rec["output"], rec["unserialized"] = None, rv.get("description") or rv.get("subtype") or rv.get("type")
        with self.lock:
            self.pairs.setdefault(label, []).append(rec)
        if self.verbose:
            print(f"[pair] {label}({rec['input']}) -> {rec['output']!r}")

    def _args(self, frames, sid):
        frame = frames[0]
        rec = {"session": sid, "fn": frame.get("functionName") or "<anonymous>"}
        rec["args"] = self._eval_args(frame, sid)
        rec["stack"] = [f.get("functionName") or "<anon>" for f in frames[:6]]
        with self.lock:
            self.captures.append(rec)
        if self.verbose:
            print(f"[hook] {rec['fn']}({rec['args']})")

    def _eval_args(self, frame, sid):
        try:
            value = self.engine.cdp.send(
                "Debugger.evaluateOnCallFrame",
                {"callFrameId": frame["callFrameId"], "expression": ARGS,
                 "returnByValue": True, "silent": True},
                session_id=sid, timeout=5).get("result", {}).get("value")
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except Exception:
                    return value
            if value is None:
                # arrow function: no `arguments` binding — read the paused
                # frame's local scope, where the parameters live
                return self._args_from_scopes(frame, sid)
            return value
        except Exception as e:
            return f"<args error: {e}>"

    def _args_from_scopes(self, frame, sid):
        out = []
        try:
            for sc in frame.get("scopeChain", []):
                if sc.get("type") not in ("local", "closure"):
                    continue
                obj = sc.get("object") or {}
                if not obj.get("objectId"):
                    continue
                props = self.engine.cdp.send("Runtime.getProperties",
                                             {"objectId": obj["objectId"]},
                                             session_id=sid)
                for p in props.get("result", []):
                    if p["name"] in ("this", "arguments", "_arguments"):
                        continue
                    v = p.get("value") or {}
                    if "value" in v:
                        out.append(v["value"])
                    elif v.get("description"):
                        out.append(v["description"])
                if out:
                    break
        except Exception:
            return None
        return out or None

    def _resume(self, sid):
        try:
            self.engine.cdp.send("Debugger.resume", session_id=sid, timeout=5)
        except Exception:
            pass
