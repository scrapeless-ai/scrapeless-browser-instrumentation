"""CLI:

    export SCRAPELESS_API_TOKEN=...

    # observe: hooks + probes + grep + save a trace artifact
    python -m sbi https://target/ --seconds 10 --grep token --out trace.json
    python -m sbi https://target/ --hook 'window.sign' --capture-returns
    python -m sbi https://target/ --hook 'enc@@worker.js' --probe crypto

    # locate: coverage-guided hooking, function index, script dump
    python -m sbi https://target/ --coverage --seconds 8 --functions sign
    python -m sbi https://target/ --dump-scripts src/ --seconds 5

    # act: heap diff around an action, then a markdown report
    python -m sbi https://target/ --heapdiff-action "window.checkout()" --report report.md
    python -m sbi https://target/ --repl
"""

import argparse
import json
import sys

from .api import attach


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sbi",
                                 description="Stealth runtime instrumentation of the Scrapeless browser via CDP")
    ap.add_argument("url", nargs="?", help="page to open")
    ap.add_argument("--token", help="Scrapeless API token (default: $SCRAPELESS_API_TOKEN)")
    ap.add_argument("--cdp", help="raw CDP endpoint (wss://... or local Chrome http://127.0.0.1:9222)")
    ap.add_argument("--proxy-country", help="Scrapeless proxyCountry, e.g. US")
    ap.add_argument("--session-ttl", type=int, default=300)
    ap.add_argument("--session-name", default="sbi")
    ap.add_argument("--hook", action="append", default=[],
                    help="function expression to hook; 'expr@@url-substr' targets a specific frame/worker")
    ap.add_argument("--capture-returns", action="store_true",
                    help="also breakpoint return locations to build (input, output) corpora")
    ap.add_argument("--probe", action="append", default=[],
                    choices=["crypto", "eval", "net", "fingerprint", "dom", "api"],
                    help="boundary recorder to install before page scripts (patched, not stealth)")
    ap.add_argument("--seconds", type=float, default=5.0, help="settle/observe time after navigation")
    ap.add_argument("--grep", help="search captures + network for this value")
    ap.add_argument("--out", help="save full trace JSON to this path")
    ap.add_argument("--report", help="also render a markdown report to this path")
    ap.add_argument("--coverage", action="store_true",
                    help="precise coverage while observing: print executed functions by call count")
    ap.add_argument("--functions", metavar="PATTERN",
                    help="index live closures matching this substring (with url + location)")
    ap.add_argument("--heapdiff-action", metavar="JS",
                    help="heap snapshot -> eval JS -> snapshot; print what it allocated")
    ap.add_argument("--dump-scripts", metavar="DIR",
                    help="write all parsed script sources to DIR for static analysis")
    ap.add_argument("--blackbox", action="append", default=[],
                    help="url patterns to skip in stacks/stepping (repeatable)")
    ap.add_argument("--repl", action="store_true", help="drop into an interactive shell after setup")
    ap.add_argument("--doctor", action="store_true",
                    help="readiness self-check (deps, token, endpoint, browser) and exit")
    ap.add_argument("--dialog-policy", choices=["accept", "dismiss"],
                    help="auto-answer JS dialogs so alert() storms can't stall the session")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = ap.parse_args(argv)

    if args.doctor:
        from . import doctor
        print(doctor.print_report(doctor.check(cdp=args.cdp, token=args.token)))
        return 0

    pre_coverage = args.coverage or args.heapdiff_action
    try:
        # navigate explicitly so coverage/heapdiff can bracket the page load
        session = attach(None, token=args.token, cdp=args.cdp,
                         proxy_country=args.proxy_country, session_ttl=args.session_ttl,
                         session_name=args.session_name, probes=args.probe or None)
    except RuntimeError as e:
        ap.error(str(e))

    tracer = session.tracer
    tracer.verbose = args.verbose
    if args.dialog_policy:
        session.set_dialog_policy(args.dialog_policy)
    if args.blackbox:
        session.blackbox(args.blackbox)

    summary = {"url": args.url, "hooks": [], "captures": 0, "pairs": {}, "grep": None}
    try:
        if pre_coverage:
            session.coverage("start")
        if args.url:
            session.navigate(args.url)
            session.wait(args.seconds if not args.hook else 0.5)

        for h in args.hook:
            session.hook(h, capture_returns=args.capture_returns)
        summary["hooks"] = [h["label"] for h in tracer.hooks]
        if args.hook:
            session.wait(args.seconds)

        if args.functions:
            summary["functions"] = session.functions(contains=args.functions)["functions"]
        if args.dump_scripts:
            summary["scripts_written"] = len(session.dump_scripts(args.dump_scripts))
        if pre_coverage and args.url:
            summary["coverage_top"] = session.coverage("take", only_executed=True, limit=20)["functions"]
        if args.heapdiff_action:
            summary["heapdiff"] = session.heapdiff(action=args.heapdiff_action)
        if args.grep:
            summary["grep"] = session.grep(args.grep)
        summary["audit"] = session.audit() if tracer.hooks else None
        with tracer.lock:
            summary["captures"] = len(tracer.captures)
            summary["pairs"] = {k: len(v) for k, v in tracer.pairs.items()}
        if args.out:
            session.save(args.out)
            summary["saved"] = args.out
        if args.report:
            summary["report"] = session.report(args.report)["report"]

        if args.json:
            print(json.dumps(summary, indent=2, default=str))
        else:
            print(f"[sbi] targets: {session.targets()}")
            print(f"[sbi] hooks: {summary['hooks']}")
            print(f"[sbi] arg captures: {summary['captures']}")
            print(f"[sbi] corpus sizes: {summary['pairs']}")
            for fn in summary.get("functions") or []:
                loc = fn.get("location") or {}
                print(f"[sbi] fn: {fn['name']}  {fn.get('url') or '?'}:{loc.get('line')}:{loc.get('column')}"
                      f"  heap={fn.get('heap_object_id')}")
            for f in summary.get("coverage_top") or []:
                print(f"[sbi] ran {f['count']}x: {f['function']}  {f['url']}:{f.get('size', '?')}B")
            hd = summary.get("heapdiff")
            if hd:
                print(f"[sbi] heapdiff: {hd['total_new_tracked']} new tracked nodes")
                for n in hd["new_nodes"][:10]:
                    print(f"[sbi]   +{n['type']} {n['name']!r} ({n['self_size']}B)")
            if summary.get("grep") is not None:
                g = summary["grep"]
                print(f"[sbi] grep {args.grep!r}: {len(g['hook_captures'])} hook hits, "
                      f"{len(g['pairs'])} pair hits, {len(g['network'])} network hits")
            if summary.get("audit"):
                print(f"[sbi] audit: all_intact={summary['audit']['all_intact']}")
            if args.out:
                print(f"[sbi] trace saved: {args.out}")
            if args.report:
                print(f"[sbi] report: {args.report}")

        if args.repl:
            session.repl()
    finally:
        session.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
