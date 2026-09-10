"""Request interception via the Fetch domain: mock, edit, block, or pass.

Burp-grade rules at both stages: request-stage rules can MOCK a response,
ABORT, pass through untouched, or CONTINUE WITH EDITS (url/method/headers
overrides — the "intercept and edit" move); response-stage rules replace the
body on the way out. The page never sees the interception — a mock is
indistinguishable from the real server, an edit indistinguishable from the
origin's answer.

    s.intercept("*/telemetry", abort=True)
    s.intercept("https://api.target/v2/config", body='{"debug":1}')
    s.intercept("*/login", stage="request",
                modify={"method": "POST", "headers": {"X-Test": "1"}})
    s.intercept("*/feed", stage="response", body='[]')
"""

import base64
import fnmatch
import re
import threading

MAX_OBSERVED = 500              # cap the observation tape
MAX_BODY = 256 * 1024           # truncate large post bodies, like Network capture


class Interceptor:
    def __init__(self, cdp):
        self.cdp = cdp
        # reentrant: add() holds the lock while _arm() re-reads the rules
        self.lock = threading.RLock()
        self.rules = {}          # sid -> [rule dicts, in order]
        self.rule_log = []       # (pattern, kwargs) — replayed on reconnect
        self._enabled = set()
        # Fetch.requestPaused carries the REAL request headers and body — a
        # different capture point than the Network domain, so it still sees
        # them when a gateway strips Network-domain output. Record every pause
        # here so a passthrough rule doubles as an observer.
        self.observed = []       # [{session,stage,url,method,headers,post_data,...}]
        cdp.on("Fetch.requestPaused", self._paused)

    def add(self, sid, pattern, status=200, body="", headers=None,
            content_type="application/json", abort=False, passthrough=False,
            stage="request", modify=None, edit=None):
        kwargs = dict(status=status, body=body, headers=headers or {},
                      content_type=content_type, abort=abort, passthrough=passthrough,
                      stage=stage if stage in ("request", "response") else "request",
                      modify=modify or {}, edit=list(edit or []))
        with self.lock:
            rules = self.rules.setdefault(sid, [])
            rules.append({"pattern": pattern, **kwargs})
            self.rule_log.append((pattern, kwargs))
            self._arm(sid)
        return len(rules)

    def clear(self, sid=None):
        with self.lock:
            sids = [sid] if sid else list(self.rules)
            for s in sids:
                self.rules.pop(s, None)
                try:
                    self.cdp.send("Fetch.disable", session_id=s)
                except Exception:
                    pass
                self._enabled.discard(s)

    def _arm(self, sid):
        with self.lock:
            rules = self.rules.get(sid, [])
            patterns = [{"urlPattern": r["pattern"],
                         "requestStage": "Request" if r["stage"] == "request"
                         else "Response"}
                        for r in rules]
        # Fetch.enable replaces the pattern set: disarm once, then arm with all
        try:
            self.cdp.send("Fetch.disable", session_id=sid)
        except Exception:
            pass
        self.cdp.send("Fetch.enable",
                      {"patterns": patterns} if patterns else {"patterns": []},
                      session_id=sid)
        with self.lock:
            self._enabled.add(sid)

    def _record(self, params, sid, stage):
        """Capture what a pause reveals about the request — headers and body
        included — before any rule mutates or forwards it."""
        req = params.get("request") or {}
        rec = {"session": sid, "stage": stage,
               "url": req.get("url", ""), "method": req.get("method", ""),
               "headers": dict(req.get("headers") or {}),
               "post_data": req.get("postData"),
               "resource_type": params.get("resourceType")}
        # the body isn't always inlined (large/multipart) — recover it once,
        # only at the request stage where getRequestPostData is valid
        if stage == "request" and rec["post_data"] is None and req.get("hasPostData"):
            try:
                r = self.cdp.send("Fetch.getRequestPostData",
                                  {"requestId": params.get("requestId")},
                                  session_id=sid, timeout=10)
                rec["post_data"] = r.get("postData")
            except Exception:
                pass
        body = rec["post_data"]
        if isinstance(body, str) and len(body) > MAX_BODY:
            rec["post_data"] = body[:MAX_BODY] + f"...[{len(body)}B truncated]"
        with self.lock:
            self.observed.append(rec)
            if len(self.observed) > MAX_OBSERVED:
                del self.observed[:-MAX_OBSERVED]

    def drain_observed(self):
        """Read and clear the observed-request tape."""
        with self.lock:
            out, self.observed = self.observed, []
        return out

    def grep_observed(self, needle, regex=False):
        """Non-destructive search over observed URLs, methods, headers and
        bodies — recovers request-side values a Network-domain grep can't see."""
        needle = str(needle)
        rx = re.compile(needle) if regex else None
        with self.lock:
            records = list(self.observed)
        out = []
        for rec in records:
            hay = " ".join([rec.get("url", ""), rec.get("method", ""),
                            rec.get("post_data") or "",
                            " ".join(f"{k}: {v}" for k, v
                                     in (rec.get("headers") or {}).items())])
            if (rx.search(hay) if rx else needle in hay):
                out.append(rec)
        return out

    def _match(self, sid, url, stage):
        with self.lock:
            rules = list(self.rules.get(sid, []))
        for r in rules:
            if r["stage"] != stage:
                continue
            if fnmatch.fnmatch(url, r["pattern"]) or url.startswith(r["pattern"]):
                return r
        return None

    def _read_stream(self, rid, sid):
        """Original response body of a response-stage pause, via the
        interception stream."""
        r = self.cdp.send("Fetch.takeResponseBodyForInterceptionAsStream",
                          {"requestId": rid}, session_id=sid, timeout=30)
        stream_id = r.get("streamId")
        parts = []
        while stream_id:
            r = self.cdp.send("IO.read", {"handle": stream_id}, session_id=sid,
                              timeout=30)
            data = r.get("data", "")
            if r.get("base64Encoded"):
                data = base64.b64decode(data).decode("utf-8", "replace")
            parts.append(data)
            if r.get("eof"):
                break
        try:
            self.cdp.send("IO.close", {"handle": stream_id}, session_id=sid)
        except Exception:
            pass
        return "".join(parts)

    def _paused(self, params, session_id=None):
        sid = session_id
        rid = params.get("requestId")
        url = (params.get("request") or {}).get("url", "")
        # response-stage pauses fire with responseStatusCode/responseHeaders
        stage = "response" if params.get("responseStatusCode") is not None else "request"
        try:
            self._record(params, sid, stage)   # observe before we forward/mutate
        except Exception:
            pass                               # recording must never break interception
        rule = self._match(sid, url, stage)
        try:
            if rule is None or rule["passthrough"]:
                self.cdp.send("Fetch.continueRequest", {"requestId": rid},
                              session_id=sid)
            elif rule["abort"]:
                self.cdp.send("Fetch.failRequest",
                              {"requestId": rid, "errorReason": "Failed"},
                              session_id=sid)
            elif rule["stage"] == "request" and rule["modify"]:
                edits = {}
                mod = rule["modify"]
                if mod.get("url"):
                    edits["url"] = mod["url"]
                if mod.get("method"):
                    edits["method"] = mod["method"]
                if mod.get("headers"):
                    edits["headers"] = [{"name": k, "value": str(v)}
                                        for k, v in mod["headers"].items()]
                if mod.get("body"):
                    edits["postData"] = base64.b64encode(
                        mod["body"].encode()).decode()
                self.cdp.send("Fetch.continueRequest",
                              dict({"requestId": rid}, **edits), session_id=sid)
            elif rule["stage"] == "response" and rule["edit"]:
                # match/replace on the ORIGINAL body: pull it from the
                # interception stream, edit, re-fulfill
                original = self._read_stream(rid, sid)
                for pat, rep in rule["edit"]:
                    original = re.sub(pat, rep, original)
                body_b64 = base64.b64encode(original.encode()).decode()
                headers = [{"name": "Content-Type",
                            "value": rule["content_type"]}]
                self.cdp.send("Fetch.fulfillRequest",
                              {"requestId": rid, "responseCode": rule["status"],
                               "body": body_b64, "responseHeaders": headers},
                              session_id=sid)
            else:
                body_b64 = base64.b64encode(
                    rule["body"].encode() if isinstance(rule["body"], str)
                    else rule["body"]).decode()
                headers = [{"name": k, "value": str(v)}
                           for k, v in rule["headers"].items()]
                headers.append({"name": "Content-Type", "value": rule["content_type"]})
                self.cdp.send("Fetch.fulfillRequest",
                              {"requestId": rid, "responseCode": rule["status"],
                               "body": body_b64, "responseHeaders": headers},
                              session_id=sid)
        except Exception as e:
            print(f"[sbi] interception of {url[:80]!r} failed: {e!r}; continuing")
            try:
                self.cdp.send("Fetch.continueRequest", {"requestId": rid},
                              session_id=sid)
            except Exception:
                pass
