"""Console and exception capture.

Hostile SDKs talk to themselves: `console.debug` traces during anti-debug
checks, decoded values logged by mistake, and the exact exception a tamper
check throws when it notices you. The Runtime domain already streams all of
it (Runtime.enable is on for every instrumented session) — this observer just
keeps the tape: `console()` drains records, `grep()` correlates them with
hooks and network like any other source.
"""

import threading


def _arg_text(ro):
    if "value" in ro:
        return ro["value"]
    return ro.get("description") or ro.get("subtype") or ro.get("type")


class Console:
    def __init__(self, cdp):
        self.lock = threading.Lock()
        self.records = []
        cdp.on("Runtime.consoleAPICalled", self._console)
        cdp.on("Runtime.exceptionThrown", self._exception)

    def _console(self, params, session_id=None):
        self._add({
            "kind": "console", "level": params.get("type"), "session": session_id,
            "text": " ".join(str(_arg_text(a)) for a in params.get("args", [])),
            "stack": [f.get("functionName") or "<anon>"
                      for f in (params.get("stackTrace") or {}).get("callFrames", [])[:5]],
        })

    def _exception(self, params, session_id=None):
        d = params.get("exceptionDetails") or {}
        exc = d.get("exception") or {}
        self._add({
            "kind": "exception", "level": "exception", "session": session_id,
            "text": exc.get("description") or d.get("text"),
            "stack": [f.get("functionName") or "<anon>"
                      for f in (d.get("stackTrace") or {}).get("callFrames", [])[:5]],
        })

    def _add(self, rec):
        with self.lock:
            self.records.append(rec)

    def drain(self):
        with self.lock:
            out, self.records = self.records, []
        return out

    def grep(self, needle, regex=False):
        import re
        rx = re.compile(needle) if regex else None
        with self.lock:
            records = list(self.records)
        hits = []
        for r in records:
            text = r.get("text") or ""
            if (rx.search(text) if rx else needle in text):
                hits.append(r)
        return hits
