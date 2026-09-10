"""Network capture at the CDP layer: requests, responses, bodies, WS frames.

Runs on every instrumented session (engine enables the Network domain on
attach). Response bodies are fetched once on loadingFinished when capture is
on — signed SDKs often build payloads in a worker and only appear here as a
POST body or a websocket frame, which is exactly the correlation point with
runtime hooks.
"""

import base64
import re
import threading


class Network:
    MAX_BODY = 256 * 1024       # per-body truncation
    MAX_RECORDS = 5000          # cap the event tape
    MAX_BODIES = 500            # cap retained bodies (drain() never clears these)
    MAX_META = 5000             # cap the requestId -> {url, method} map

    def __init__(self, engine, capture_bodies=True):
        self.engine = engine
        self.capture_bodies = capture_bodies
        self.lock = threading.Lock()
        self.records = []            # ordered event records
        self.bodies = {}             # requestId -> decoded body text
        self.raw_bodies = {}         # requestId -> raw bytes (base64 bodies only)
        self.meta = {}               # requestId -> {url, method}
        cdp = engine.cdp
        cdp.on("Network.requestWillBeSent", self._req)
        cdp.on("Network.responseReceived", self._resp)
        cdp.on("Network.loadingFinished", self._finished)
        cdp.on("Network.loadingFailed", self._failed)
        cdp.on("Network.webSocketFrameReceived", self._ws_recv)
        cdp.on("Network.webSocketFrameSent", self._ws_sent)

    def _req(self, params, session_id=None):
        req = params.get("request", {})
        rid = params.get("requestId")
        post = req.get("postData")
        if not post and req.get("hasPostData") and session_id:
            try:
                r = self.engine.cdp.send("Network.getRequestPostData",
                                         {"requestId": rid}, session_id=session_id)
                post = r.get("post_data") or r.get("postData")
            except Exception:
                pass
        with self.lock:
            self.meta[rid] = {"url": req.get("url"), "method": req.get("method")}
            while len(self.meta) > self.MAX_META:
                self.meta.pop(next(iter(self.meta)), None)   # evict oldest
        self._add({"kind": "request", "session": session_id, "request_id": rid,
                   "url": req.get("url"), "method": req.get("method"),
                   "type": params.get("type"), "post_data": post})

    def _resp(self, params, session_id=None):
        resp = params.get("response", {})
        self._add({"kind": "response", "session": session_id,
                   "request_id": params.get("requestId"),
                   "url": resp.get("url"), "status": resp.get("status"),
                   "mime": resp.get("mimeType"), "remote_ip": resp.get("remoteIPAddress"),
                   "headers": {k: v for k, v in (resp.get("headers") or {}).items()
                               if k.lower() in ("content-type", "set-cookie", "authorization",
                                                "x-signature", "signature", "x-requested-with")}})

    def _finished(self, params, session_id=None):
        rid, sid = params.get("requestId"), session_id
        if not self.capture_bodies or not sid:
            return
        try:
            r = self.engine.cdp.send("Network.getResponseBody", {"requestId": rid}, session_id=sid)
            body = r.get("body") or ""
            if r.get("base64Encoded"):
                self.raw_bodies_keep(rid, body)
                body = base64.b64decode(body).decode("utf-8", "replace")
            if len(body) > self.MAX_BODY:
                body = body[: self.MAX_BODY] + f"...[{len(body)}B truncated]"
            with self.lock:
                self.bodies[rid] = body
                while len(self.bodies) > self.MAX_BODIES:
                    self.bodies.pop(next(iter(self.bodies)), None)   # evict oldest
        except Exception:
            pass

    def raw_bodies_keep(self, rid, b64_text):
        """Binary bodies (wasm, protobuf, images) must survive as bytes — the
        utf-8 text copy corrupts them."""
        try:
            raw = base64.b64decode(b64_text)
            with self.lock:
                self.raw_bodies[rid] = raw
                while len(self.raw_bodies) > self.MAX_BODIES:
                    self.raw_bodies.pop(next(iter(self.raw_bodies)), None)
        except Exception:
            pass

    def _failed(self, params, session_id=None):
        self._add({"kind": "failed", "session": session_id, "request_id": params.get("requestId"),
                   "error": params.get("errorText"), "canceled": params.get("canceled")})

    def _ws_recv(self, params, session_id=None):
        self._ws_frame(params, session_id, "received")

    def _ws_sent(self, params, session_id=None):
        self._ws_frame(params, session_id, "sent")

    def _ws_frame(self, params, session_id, direction):
        rid = params.get("requestId")
        with self.lock:
            url = (self.meta.get(rid) or {}).get("url")
        payload = (params.get("response") or {}).get("payloadData", "")
        self._add({"kind": "ws", "session": session_id, "request_id": rid, "url": url,
                   "direction": direction, "payload": payload[:8192]})

    # -- storage / query ----------------------------------------------------

    def _add(self, rec):
        with self.lock:
            self.records.append(rec)
            if len(self.records) > self.MAX_RECORDS:
                del self.records[:-self.MAX_RECORDS]

    def drain(self):
        with self.lock:
            out, self.records = self.records, []
        return out

    def grep(self, needle, regex=False, include_bodies=True):
        rx = re.compile(needle) if regex else None
        hits = []
        with self.lock:
            records = list(self.records)
            bodies = dict(self.bodies)
        for r in records:
            for h in (r.get("url"), r.get("payload"), r.get("post_data")):
                if not h:
                    continue
                if (rx and rx.search(h)) or (not rx and needle in h):
                    hits.append(r)
                    break
        if include_bodies:
            for rid, body in bodies.items():
                pos = -1
                if rx:
                    m = rx.search(body)
                    if m:
                        pos = m.start()
                elif needle in body:
                    pos = body.find(needle)
                if pos >= 0:
                    hits.append({"kind": "body", "request_id": rid,
                                 "snippet": body[max(0, pos - 80): pos + 240]})
        return hits
