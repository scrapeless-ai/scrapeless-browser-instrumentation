"""On-disk store of trace artifacts with cross-artifact search.

One reverse-engineering effort spans many sessions (the cloud browser dies
with its websocket, so each run saves what it learned). The store keeps the
JSON artifacts, indexes their corpus labels, and answers "which capture ever
saw this token" — the multi-session memory that a single trace file isn't.
"""

import json
import os
import re
from datetime import datetime


def _sanitize_name(name):
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)


def _auto_name():
    return datetime.now().strftime("trace-%Y%m%d-%H%M%S-") + os.urandom(3).hex()


class ArtifactStore:
    def __init__(self, directory):
        self.dir = directory
        os.makedirs(directory, exist_ok=True)

    # -- write ----------------------------------------------------------

    def save(self, doc, name=None):
        name = _sanitize_name(name) if name else _auto_name()
        if not name.endswith(".json"):
            name += ".json"
        doc = dict(doc)
        meta = dict(doc.get("meta") or {})
        meta.setdefault("saved_at", datetime.now().isoformat(timespec="seconds"))
        doc["meta"] = meta
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, default=str)
        return path

    # -- read -------------------------------------------------------------

    def list(self):
        out = []
        for fn in os.listdir(self.dir):
            if not fn.endswith(".json"):
                continue
            path = os.path.join(self.dir, fn)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    doc = json.load(f)
            except Exception:
                continue
            pairs = doc.get("pairs") or {}
            out.append({"name": fn, "path": path,
                        "mtime": os.path.getmtime(path),
                        "corpus_labels": sorted(pairs),
                        "pairs_count": sum(len(v) for v in pairs.values())})
        out.sort(key=lambda e: -e["mtime"])
        return out

    def load(self, name):
        path = name if os.path.isabs(name) else os.path.join(self.dir, name)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def latest(self):
        entries = self.list()
        return self.load(entries[0]["name"]) if entries else None

    # -- search ------------------------------------------------------------

    def search(self, needle, regex=False, in_pairs=True, in_network=True, limit=50):
        rx = re.compile(needle) if regex else None
        hits = []
        for entry in self.list():
            doc = self.load(entry["name"])
            if in_pairs:
                for label, plist in (doc.get("pairs") or {}).items():
                    for p in plist:
                        text = json.dumps([p.get("input"), p.get("output")], default=str)
                        if (rx.search(text) if rx else needle in text):
                            hits.append({"file": entry["name"], "where": "pairs",
                                         "label": label, "input": p.get("input"),
                                         "output": p.get("output")})
                            if len(hits) >= limit:
                                return hits
            if in_network:
                for r in (doc.get("network") or []):
                    text = json.dumps({k: r.get(k) for k in
                                       ("url", "post_data", "payload", "snippet")}, default=str)
                    if (rx.search(text) if rx else needle in text):
                        hits.append({"file": entry["name"], "where": "network",
                                     "snippet": text[:400]})
                        if len(hits) >= limit:
                            return hits
        return hits

    # -- housekeeping ---------------------------------------------------------

    def prune(self, keep=20):
        entries = self.list()          # newest first
        removed = []
        for entry in entries[keep:]:
            try:
                os.unlink(entry["path"])
                removed.append(entry["path"])
            except OSError:
                pass
        return removed
