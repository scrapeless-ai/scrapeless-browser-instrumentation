"""Live V8 heap search: find values the page never exposes on `window`.

takeHeapSnapshot streams the full snapshot over addHeapSnapshotChunk events;
we parse it and search string/number nodes by value and object/closure nodes
by constructor. Matches resolve back to a live object via
HeapProfiler.getObjectByHeapObjectId, and retainer paths show *who* is
holding the value — usually the fastest route from "the response contains a
token" to "the function that builds it".
"""

import json
import re

_SIZE_CAP = 800 * 1024 * 1024  # refuse to json-parse absurd snapshots


def take_snapshot(cdp, sid):
    chunks = []

    def on_chunk(params, event_sid=None):
        if event_sid == sid:
            chunks.append(params.get("chunk", ""))

    cdp.on("HeapProfiler.addHeapSnapshotChunk", on_chunk)
    cdp.send("HeapProfiler.enable", session_id=sid)
    try:
        cdp.send("HeapProfiler.takeHeapSnapshot", {"reportProgress": False}, session_id=sid)
        cdp.flush_events(90)   # chunks are events; the response alone doesn't prove we got them
    finally:
        cdp.off("HeapProfiler.addHeapSnapshotChunk")
    raw = "".join(chunks)
    if len(raw) > _SIZE_CAP:
        raise RuntimeError(f"heap snapshot is {len(raw) // 1048576}MB; refusing to parse")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # trailing chunks from an in-flight prior snapshot can tail the doc,
        # and busy pages can briefly serve an empty first snapshot: retry once
        if not raw:
            import time
            time.sleep(2)
            return take_snapshot(cdp, sid)
        doc, _ = json.JSONDecoder().raw_decode(raw)
        return doc


class Snapshot:
    def __init__(self, data):
        self.data = data
        meta = data["snapshot"]["meta"]
        self.node_fields = meta["node_fields"]
        self.node_types = meta["node_types"][0]
        self.edge_fields = meta["edge_fields"]
        self.edge_types = meta["edge_types"][0]
        self.strings = data["strings"]
        self.nodes = data["nodes"]
        self.edges = data["edges"]
        self.nstride = len(self.node_fields)
        self.estride = len(self.edge_fields)
        self._offset2idx = None
        self._rev = None

    # -- indexing ----------------------------------------------------------

    def _f(self, field):
        return self.node_fields.index(field)

    def node_at(self, byte_offset):
        return byte_offset // self.nstride

    def offset_of(self, node_idx):
        return node_idx * self.nstride

    def node_name(self, idx):
        o = idx * self.nstride
        t = self.node_types[self.nodes[o + self._f("type")]]
        name_idx = self.nodes[o + self._f("name")]
        if t == "string":
            return self.strings[name_idx]
        return self.strings[name_idx] if isinstance(name_idx, int) and name_idx < len(self.strings) else str(name_idx)

    def node_type(self, idx):
        return self.node_types[self.nodes[idx * self.nstride + self._f("type")]]

    def node_id(self, idx):
        return self.nodes[idx * self.nstride + self._f("id")]

    def node_size(self, idx):
        return self.nodes[idx * self.nstride + self._f("self_size")]

    # -- search --------------------------------------------------------------

    def find(self, contains=None, regex=None, ctor=None, kind=None, limit=25):
        """kind: 'string' | 'object' | 'closure' | None (any)."""
        rx = re.compile(regex) if regex else None
        out = []
        for i in range(len(self.nodes) // self.nstride):
            t = self.node_type(i)
            name = self.node_name(i)
            if kind and t != kind:
                continue
            if t == "string":
                if ctor:
                    continue
                hit = (contains and contains in name) or bool(rx and rx.search(name))
            elif t in ("object", "closure"):
                hit = (ctor and name == ctor) or (
                    not ctor and ((contains and contains in name) or bool(rx and rx.search(name))))
            else:
                continue
            if hit:
                out.append(i)
                if len(out) >= limit:
                    break
        return out

    # -- retainers -------------------------------------------------------------

    def _build_reverse(self):
        n = len(self.nodes) // self.nstride
        offset2idx = {i * self.nstride: i for i in range(n)}
        rev = {}
        type_idx = self.edge_fields.index("type")
        name_idx = self.edge_fields.index("name_or_index")
        to_idx = self.edge_fields.index("to_node")
        numeric = {"element", "hidden"}
        j = 0
        for i in range(n):
            ec = self.nodes[i * self.nstride + self._f("edge_count")]
            for _ in range(ec):
                base = j * self.estride
                target = offset2idx.get(self.edges[base + to_idx])
                if target is not None:
                    tname = self.edge_types[self.edges[base + type_idx]]
                    raw = self.edges[base + name_idx]
                    label = str(raw) if tname in numeric else (
                        self.strings[raw] if isinstance(raw, int) and raw < len(self.strings) else str(raw))
                    rev.setdefault(target, []).append((i, tname, label))
                j += 1
        self._rev = rev
        return rev

    def retainers(self, idx, depth=4):
        if self._rev is None:
            self._build_reverse()
        paths = []

        def walk(cur, acc, remaining):
            if remaining == 0 or len(paths) >= 8:
                return
            parents = self._rev.get(cur, [])
            if not parents:
                if acc:
                    paths.append(list(acc))
                return
            for parent, etype, label in parents[:6]:
                t = self.node_type(parent)
                name = self.node_name(parent)
                step = {"element": f"[{label}]", "property": f".{label}",
                        "internal": f"~{label}", "shortcut": f"=>{label}"}.get(etype, f" {etype}:{label}")
                entry = f"{step} on {t}:{name or '<anon>'}"
                if parent == cur:
                    continue
                walk(parent, acc + [entry], remaining - 1)
            if any(p == cur for p, _, _ in parents) and acc:
                paths.append(list(acc))

        walk(idx, [], depth)
        return paths[:8]

    def object_retainer(self, idx, depth=6):
        """Nearest object/closure ancestor holding this node — the resolvable
        live handle. String nodes themselves don't survive
        getObjectByHeapObjectId; their holders do."""
        if self._rev is None:
            self._build_reverse()

        def walk(cur, remaining):
            if remaining == 0:
                return None
            for parent, etype, label in self._rev.get(cur, []):
                t = self.node_type(parent)
                if t in ("object", "closure") and parent != idx:
                    return {"heap_object_id": str(self.node_id(parent)),
                            "name": self.node_name(parent),
                            "via": f"{etype}:{label}"}
            for parent, _, _ in self._rev.get(cur, []):
                if self.node_type(parent) == "string" or parent == cur:
                    continue
                found = walk(parent, remaining - 1)
                if found:
                    return found
            return None

        return walk(idx, depth)


def search(cdp, sid, contains=None, regex=None, ctor=None, kind=None, limit=25, with_retainers=0):
    snap = Snapshot(take_snapshot(cdp, sid))
    idxs = snap.find(contains=contains, regex=regex, ctor=ctor, kind=kind, limit=limit)
    matches = []
    for i in idxs:
        m = {"heap_object_id": str(snap.node_id(i)), "type": snap.node_type(i),
             "name": snap.node_name(i), "self_size": snap.node_size(i)}
        if with_retainers:
            m["retained_via"] = [[p for p in path] for path in snap.retainers(i, depth=with_retainers)]
        if snap.node_type(i) == "string":
            # strings aren't resolvable live; the nearest object holder is
            holder = snap.object_retainer(i)
            if holder:
                m["holder"] = holder
        matches.append(m)
    return {"matches": matches, "total_nodes": len(snap.nodes) // snap.nstride}


def get_object(cdp, sid, heap_object_id, props=12):
    """Resolve a snapshot node id back to the live object and preview its
    properties. Only object/closure nodes resolve — string nodes raise
    'Object is not available'; use their `holder` from search() instead."""
    r = cdp.send("HeapProfiler.getObjectByHeapObjectId",
                 {"objectId": str(heap_object_id), "objectGroup": "sbi"}, session_id=sid)
    remote = r.get("result", {})
    preview = {"description": remote.get("description") or remote.get("value"), "type": remote.get("type")}
    if remote.get("objectId"):
        try:
            rp = cdp.send("Runtime.getProperties",
                          {"objectId": remote["objectId"], "ownProperties": True}, session_id=sid)
            preview["properties"] = [
                {"name": p["name"], "value": (p.get("value") or {}).get("value",
                     (p.get("value") or {}).get("description")),
                 "type": (p.get("value") or {}).get("type")}
                for p in rp.get("result", [])[:props]]
        except Exception:
            pass
    return preview
