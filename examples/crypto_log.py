"""Recover the plaintext fed to crypto.subtle.* at the boundary.

The probe wraps crypto.subtle before page scripts run, recording (alg, input,
output) for digest/encrypt/sign/... Unlike hooks this IS patching — use it to
observe boundaries, then hook the function that feeds them.

crypto.subtle exists only in secure contexts, and about:blank isn't one —
so this example serves its own page on 127.0.0.1 (a secure context) instead
of injecting into about:blank.
"""

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from _common import require_config
import sbi

require_config()

PAGE = """<!doctype html><html><body><script>
  async function fingerprint(tok) {
    const data = new TextEncoder().encode(tok + '|v2');
    const h = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  window.fingerprint = fingerprint;
</script></body></html>"""


def b64(s):
    return base64.b64encode(s.encode()).decode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
srv.daemon_threads = True
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

try:
    with sbi.attach(url=f"http://127.0.0.1:{port}/", wait=1.0) as s:
        s.probe_install(("crypto",))          # before the call; also re-installs per document
        s.eval("window.fingerprint('tok_9f27')")
        s.wait(0.6)

        events = [e for e in s.probe_drain() if e.get("probe") == "crypto"]
        print(json.dumps(events, indent=2))

        digest_in = next(e for e in events if e["op"] == "digest" and e["phase"] == "in")
        assert digest_in["args"][1]["b64"] == b64("tok_9f27|v2"), "plaintext not recovered"
        print("PASS: plaintext fed to crypto.subtle.digest recovered at the boundary")
finally:
    srv.shutdown()
