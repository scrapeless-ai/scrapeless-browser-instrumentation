"""Present the session as another environment: UA, locale, timezone, viewport.

Region- and device-gated behavior is everywhere — a page that only ships to
DE, a checkout that only renders its mobile flow, a SDK branch keyed on
`Intl.DateTimeFormat().resolvedOptions().timeZone`. These overrides flip all
of that per-session without touching Scrapeless's fingerprint stack: they are
in-page visible (JS and HTTP headers both) but stay inside this CDP session.
Note they can contradict the gateway's own fingerprint — a DE locale on a US
exit IP is exactly the kind of mismatch hostile SDKs score — so combining
them is the caller's choice, not something this module reconciles.
"""


def set_user_agent(cdp, sid, user_agent, metadata=None):
    """Override the UA string (Network.setUserAgentOverride); `metadata`
    (a Client Hints dict) is attached as userAgentMetadata when given."""
    params = {"userAgent": user_agent}
    if metadata is not None:
        params["userAgentMetadata"] = metadata
    cdp.send("Network.setUserAgentOverride", params, session_id=sid)


def set_locale(cdp, sid, locale):
    """Override navigator.language(s) and Intl defaults (Emulation.setLocaleOverride)."""
    cdp.send("Emulation.setLocaleOverride", {"locale": locale}, session_id=sid)


def set_timezone(cdp, sid, timezone_id):
    """Override the IANA timezone the page sees, e.g. 'Europe/Berlin'
    (Emulation.setTimezoneOverride)."""
    cdp.send("Emulation.setTimezoneOverride",
             {"timezoneId": timezone_id}, session_id=sid)


def set_device(cdp, sid, width, height, mobile=False, scale=1):
    """Override viewport metrics (Emulation.setDeviceMetricsOverride);
    `scale` is deviceScaleFactor, `mobile` toggles mobile viewport behavior."""
    cdp.send("Emulation.setDeviceMetricsOverride",
             {"width": width, "height": height,
              "deviceScaleFactor": float(scale), "mobile": bool(mobile)},
             session_id=sid)


def clear_device(cdp, sid):
    """Undo set_device, back to the real viewport (Emulation.clearDeviceMetricsOverride)."""
    cdp.send("Emulation.clearDeviceMetricsOverride", session_id=sid)


def set_script_execution(cdp, sid, enabled):
    """Enable/disable JS in the target (Emulation.setScriptExecutionDisabled);
    note the wire value is inverted: enabled=True sends value=False."""
    cdp.send("Emulation.setScriptExecutionDisabled",
             {"value": not enabled}, session_id=sid)
