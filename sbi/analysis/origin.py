"""Where did this value come from?

Two techniques:

- retainer paths (heap.py): who currently holds the value — static view of
  the live graph, e.g. `.token on object:Response -> [0] on object:Array`.
- allocation sampling (here): start HeapProfiler.startSampling(includeStacks),
  trigger the action, stop, and read the allocation stacks. The deepest
  non-vendor frame in a stack is usually the user-land function that created
  the value.
"""

_PROBE_PATTERNS = ("chrome", "extensions/", "devtools")


def sampling_start(cdp, sid, interval=16384):
    try:
        cdp.send("HeapProfiler.startSampling",
                 {"samplingInterval": interval, "includeStacks": True}, session_id=sid)
    except Exception:  # older builds without includeStacks
        cdp.send("HeapProfiler.startSampling", {"samplingInterval": interval}, session_id=sid)
    return sid


def sampling_stop(cdp, sid, top=20, min_self_size=0):
    profile = cdp.send("HeapProfiler.stopSampling", session_id=sid).get("profile", {})
    sites = []

    def walk(node, stack):
        frame = node.get("callFrame", {})
        label = f"{frame.get('functionName') or '<anon>'}@{frame.get('url') or '?'}:{frame.get('lineNumber', '?')}"
        self_size = node.get("selfSize", 0) or 0
        if self_size > min_self_size:
            sites.append({"self_size": self_size, "frames": stack + [label]})
        for child in node.get("children", []):
            walk(child, stack + [label])

    walk(profile.get("head", {}), [])
    sites.sort(key=lambda s: -s["self_size"])
    return {"allocations": sites[:top], "total_tracked": len(sites)}


def is_vendor_frame(frame_label):
    low = frame_label.lower()
    return any(p in low for p in _PROBE_PATTERNS)


def userland_frame(frames):
    """Deepest frame that doesn't look like tooling — a heuristic, not a fact."""
    for f in reversed(frames):
        if not is_vendor_frame(f):
            return f
    return frames[-1] if frames else None
