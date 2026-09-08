"""One-command live validation: launch a throwaway headless Chromium, run
every example plus the live tests against it, print a summary.

    python scripts/live_battery.py            # finds Chrome/Edge automatically
    CHROME="..." python scripts/live_battery.py --keep

Exit code 0 only if everything passed. This is the pre-release gate the
offline suite cannot replace.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CANDIDATES = [
    os.environ.get("CHROME", ""),
    shutil.which("chrome"), shutil.which("google-chrome"), shutil.which("chromium"),
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def find_browser():
    for c in CANDIDATES:
        if c and os.path.exists(c):
            return c
    return None


def wait_endpoint(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9223)
    ap.add_argument("--keep", action="store_true", help="keep the browser alive after")
    args = ap.parse_args()

    browser = find_browser()
    if not browser:
        print("no Chrome/Edge found; set CHROME=/path/to/chrome")
        return 2

    profile = tempfile.mkdtemp(prefix="sbi_battery_")
    proc = subprocess.Popen(
        [browser, "--headless=new", f"--remote-debugging-port={args.port}",
         f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
         "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_endpoint(args.port):
            print(f"browser did not open CDP on {args.port}")
            return 2
        print(f"[battery] {browser} on :{args.port}")

        env = dict(os.environ, SCRAPELESS_CDP_URL=f"http://127.0.0.1:{args.port}")
        results = []
        examples = sorted(f for f in os.listdir(os.path.join(ROOT, "examples"))
                          if f.endswith(".py") and not f.startswith("_"))
        for ex in examples:
            t0 = time.time()
            p = subprocess.run([sys.executable, os.path.join("examples", ex)],
                               cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
            ok = p.returncode == 0 and ("PASS" in p.stdout or "SKIP" in p.stdout)
            if ok and "SKIP" in p.stdout:
                results.append((ex + " (skip)", True, time.time() - t0))
                print(f"[battery] SKIP {ex} ({time.time() - t0:.1f}s)")
                continue
            results.append((ex, ok, time.time() - t0))
            print(f"[battery] {'PASS' if ok else 'FAIL'} {ex} ({time.time() - t0:.1f}s)")
            if not ok:
                print(p.stdout[-1500:], p.stderr[-1500:])

        p = subprocess.run([sys.executable, "-m", "unittest", "tests.test_live", "-v"],
                           cwd=ROOT, env=env, capture_output=True, text=True, timeout=600)
        ok = p.returncode == 0
        results.append(("tests.test_live", ok, 0))
        print(f"[battery] {'PASS' if ok else 'FAIL'} tests.test_live")
        if not ok:
            print(p.stdout[-2000:], p.stderr[-2000:])

        passed = sum(1 for _, ok, _ in results if ok)
        print(f"[battery] {passed}/{len(results)} passed")
        return 0 if passed == len(results) else 1
    finally:
        if not args.keep:
            proc.terminate()
            shutil.rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
