"""Scrapeless Browser Instrumentation (sbi).

Stealth runtime instrumentation for reverse-engineering hostile client-side
JavaScript (anti-bot, captcha, fingerprinting, fraud, payment SDKs) running in
the Scrapeless Scraping Browser.

Hooks are set through the Chrome DevTools Protocol on the live function object
— the function is never wrapped or replaced, so `fn.toString()` checks, Proxy
traps and monkeypatch detectors see nothing. Nothing inferred is trusted: every
reimplementation hypothesis is checked against captured ground truth with
`sbi.Session.verify`.

Quick start:

    import sbi
    with sbi.attach("https://target/") as s:
        s.hook("window.sign", capture_returns=True, label="sign")
        s.wait(3)
        print(s.verify("window.sign", "(u,p)=>btoa(u+':'+p)", label="sign"))

The API token is read from the SCRAPELESS_API_TOKEN environment variable (or
passed explicitly / replaced by any raw CDP websocket endpoint).
"""

__version__ = "1.3.0"

from .api import Session, attach, endpoint

__all__ = ["Session", "attach", "endpoint", "__version__"]
