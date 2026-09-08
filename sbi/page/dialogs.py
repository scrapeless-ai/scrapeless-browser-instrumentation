"""Dialog capture and auto-handling.

Hostile pages `alert()` in a loop: every dialog blocks the renderer until
someone answers, so an unattended storm stalls the whole session. The Page
domain already reports each one via Page.javascriptDialogOpening — this
observer keeps the tape (capped) and, when a policy is set, answers from the
event thread so the page never gets to block on us.
"""

import threading

MAX_RECORDS = 500


class Dialogs:
    def __init__(self, cdp, auto=None):
        self.cdp = cdp
        self.lock = threading.Lock()
        self.records = []
        self.set_policy(auto)
        cdp.on("Page.javascriptDialogOpening", self._opening)

    def set_policy(self, auto):
        if auto not in (None, "accept", "dismiss"):
            raise ValueError(f"auto must be None, 'accept' or 'dismiss', got {auto!r}")
        with self.lock:
            self.auto = auto

    def _opening(self, params, session_id=None):
        with self.lock:
            auto = self.auto
            self.records.append({
                "session": session_id,
                "type": params.get("type"),
                "message": params.get("message"),
                "url": params.get("url"),
                "action": auto,
            })
            del self.records[:-MAX_RECORDS]
        if auto in ("accept", "dismiss"):
            try:
                self.cdp.send("Page.handleJavaScriptDialog",
                              {"accept": auto == "accept",
                               "promptText": params.get("defaultPrompt") or ""},
                              session_id=session_id)
            except Exception as e:
                print(f"[sbi] dialog auto-{auto} failed: {e!r}; continuing")

    def drain(self):
        with self.lock:
            out, self.records = self.records, []
        return out

    def pending(self):
        with self.lock:
            return len(self.records)
