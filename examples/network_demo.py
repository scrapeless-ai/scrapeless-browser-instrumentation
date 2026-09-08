"""Network capture + grep correlation against the real web.

httpbin.org/get is a one-fetch page: the navigation itself produces a document
request/response whose JSON body echoes the request headers back. The CDP-layer
recorder sees all of it without touching the page, and grep correlates urls
and response bodies with runtime captures by value.
"""

import json
import os
import sys
from urllib.parse import urlsplit

from _common import require_config, target
import sbi

require_config()

# _common.target() defaults to example.com, which makes no fetch of its own
url = target() if os.environ.get("SBI_TARGET") else "https://httpbin.org/get"

with sbi.attach(url) as s:
    s.wait(6)
    recs = s.network_records()

    kinds = {}
    for r in recs:
        kinds[r.get("kind")] = kinds.get(r.get("kind"), 0) + 1
    print("kinds:", json.dumps(kinds))
    print("first urls:", [r.get("url") for r in recs if r.get("url")][:5])

    hits = s.grep("httpbin")
    for _ in range(3):                       # httpbin can be flaky: re-drain, retry
        if hits["network"] and any(r.get("kind") == "request" for r in recs):
            break
        s.wait(3)
        recs.extend(s.network_records())
        hits = s.grep("httpbin")

    if not (hits["network"] and any(r.get("kind") == "request" for r in recs)):
        host = urlsplit(url).hostname or ""
        if not any(host and host in u for _, _t, u in s.targets() if u):
            print(f"SKIP: {url} itself failed to load (targets: {s.targets()}); nothing to capture")
            sys.exit(0)
        assert hits["network"], "grep found no network url/body mentioning 'httpbin'"
        assert any(r.get("kind") == "request" for r in recs), "no 'request' record captured"

    print("PASS: CDP-layer capture recorded the request and grep matched 'httpbin'")
