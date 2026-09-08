"""Pre-flight doctor: one call that answers "is everything ready?".

Failures that surface five minutes into a live session — a missing token, an
absent optional dependency, a devtools port nobody is listening on — cost the
whole session setup. `check()` gathers the environment picture up front
(interpreter/package versions, optional tooling, env configuration), resolves
the CDP endpoint exactly the way `sbi.attach` would, and — for http devtools
endpoints — probes the browser's /json/version with a short timeout so a dead
port is known now, not later. `print_report()` renders the result for humans
with plain OK/FAIL/-- markers (no unicode, safe on any console). Everything is
defensive: a broken environment produces a report, never an exception.
"""

import importlib.util
import json
import os
import re
import shutil
import sys
import urllib.request

from . import __version__ as _SBI_VERSION
from .api import endpoint as _resolve_endpoint

_WSS_NOTE = "wss endpoint not probed"


def _websockets_version():
    """websockets is a hard dependency of sbi.cdp, but report None rather
    than trusting that it always imports."""
    try:
        import websockets
        return getattr(websockets, "__version__", None)
    except Exception:                                    # noqa: BLE001
        return None


def _mcp_available():
    try:
        return importlib.util.find_spec("mcp") is not None
    except Exception:                                    # noqa: BLE001
        return False


def _probe_http(base_url, timeout=3.0):
    """GET <base_url>/json/version. Proxies are bypassed: devtools ports are
    local/LAN and a configured proxy would only distort the health verdict."""
    url = base_url.rstrip("/") + "/json/version"
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=timeout) as resp:
            data = json.load(resp)
        return {"browser": data.get("Browser") if isinstance(data, dict) else None,
                "ok": True}
    except Exception as e:                               # noqa: BLE001
        return {"ok": False, "error": str(e)}


def check(cdp=None, token=None, probe_browser=True):
    """Collect environment, dependency and endpoint readiness in one dict.

    Never raises. Returns:
        python / sbi / websockets : versions ("websockets" is None if absent)
        node                      : shutil.which("node") result or None
        mcp                       : True if the `mcp` package is importable
        token_env / cdp_env       : SCRAPELESS_API_TOKEN presence / raw CDP url
        endpoint                  : the url resolved by sbi.api.endpoint with
                                    the given cdp/token, or None plus
                                    "error": str(e) when resolution raised
        browser                   : only when probe_browser —
                                    {"browser": <Browser>, "ok": True} when an
                                    http endpoint answered /json/version,
                                    {"ok": False, "error": str} when it did not,
                                    {"ok": None, "note": ...} for wss (skipped:
                                    only a real connection could validate it)
        ok                        : endpoint resolved AND (probe ok or skipped)
    """
    report = {
        "python": sys.version.split()[0],
        "sbi": _SBI_VERSION,
        "websockets": _websockets_version(),
        "node": shutil.which("node"),
        "mcp": _mcp_available(),
        "token_env": bool(os.environ.get("SCRAPELESS_API_TOKEN")),
        "cdp_env": os.environ.get("SCRAPELESS_CDP_URL"),
        "endpoint": None,
    }
    try:
        report["endpoint"] = _resolve_endpoint(token=token, cdp=cdp)
    except Exception as e:              # RuntimeError (nothing configured) is the
        report["error"] = str(e)        # expected path; a dead http endpoint makes
        report["endpoint"] = None       # endpoint() raise urllib errors — both
                                        # become report data, never an exception
    if probe_browser:
        target = None
        if cdp and cdp.startswith("http://"):
            # endpoint() converts a live http devtools url to its websocket url
            # after its own fetch; probe the original url the caller gave us
            target = cdp
        elif report["endpoint"] and report["endpoint"].startswith("http://"):
            target = report["endpoint"]
        if target is not None:
            report["browser"] = _probe_http(target)
        elif report["endpoint"] and report["endpoint"].startswith("wss://"):
            report["browser"] = {"ok": None, "note": _WSS_NOTE}

    browser = report.get("browser")
    probe_ok = not (isinstance(browser, dict) and browser.get("ok") is False)
    report["ok"] = bool(report["endpoint"]) and probe_ok
    return report


def _redact(url):
    """Mask credential query values so printed reports never leak tokens."""
    try:
        return re.sub(r"(token=)[^&]+", r"\1***", str(url))
    except Exception:                                    # noqa: BLE001
        return url


def print_report(report):
    """Render a check() report as a human-readable multi-line string.

    Every status row carries a plain-text marker: OK (good), FAIL (blocks a
    session), -- (informational / not applicable). Returns the string; never
    prints, never raises on partial reports."""
    lines = [f"sbi doctor {_SBI_VERSION}"]

    def row(status, label, detail):
        lines.append(f"  {status:<4} {label:<11} {detail}")

    row("OK" if report.get("python") else "--",
        "python", report.get("python") or "unknown")
    row("OK" if report.get("sbi") else "--",
        "sbi", report.get("sbi") or "unknown")
    ws = report.get("websockets")
    row("OK" if ws else "--", "websockets", ws or "not installed")
    node = report.get("node")
    row("OK" if node else "--", "node", node or "not found")
    row("OK" if report.get("mcp") else "--",
        "mcp", "installed" if report.get("mcp") else "not installed")
    row("OK" if report.get("token_env") else "--", "token",
        "SCRAPELESS_API_TOKEN set" if report.get("token_env")
        else "SCRAPELESS_API_TOKEN not set")
    cdp_env = report.get("cdp_env")
    row("OK" if cdp_env else "--", "cdp_env",
        _redact(cdp_env) if cdp_env else "SCRAPELESS_CDP_URL not set")
    ep = report.get("endpoint")
    if ep:
        row("OK", "endpoint", _redact(ep))
    else:
        row("FAIL", "endpoint", report.get("error") or "not resolved")
    browser = report.get("browser")
    if browser is None:
        row("--", "browser", "not probed")
    elif browser.get("ok") is True:
        row("OK", "browser", browser.get("browser") or "reachable")
    elif browser.get("ok") is False:
        row("FAIL", "browser", browser.get("error") or "unreachable")
    else:
        row("--", "browser", browser.get("note") or "skipped")
    if report.get("ok"):
        row("OK", "overall", "ready")
    else:
        row("FAIL", "overall", "not ready (see FAIL lines above)")
    return "\n".join(lines)


if __name__ == "__main__":
    print(print_report(check()))
