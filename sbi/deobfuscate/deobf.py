"""Static deobfuscation bridge: the collected scripts meet webcrack.

Runtime truth (hooks, string-table dumps) proves behaviour; webcrack makes
the collected bundle readable — deobfuscates obfuscator.io output (string
arrays, rotation, control flow), unminifies, and can split webpack bundles.
This is the bridge between sbi's runtime captures and the node deobfuscation
ecosystem: everything stays local, and the runtime tools remain the source of
truth (webcrack output is a reading aid, verified against captures).
"""

import os
import shutil
import subprocess
import tempfile


def available():
    return bool(shutil.which("node"))


def deobfuscate(source_path, out_dir=None, timeout=300):
    """Deobfuscate a collected JS file with webcrack (npm). Returns
    {output, files:[...]} — webcrack may emit multiple chunks for bundles."""
    if not available():
        raise RuntimeError("node is required for deobfuscation")
    source_path = os.path.abspath(source_path)
    if not os.path.exists(source_path):
        raise FileNotFoundError(source_path)
    npx = shutil.which("npx")
    out_dir = os.path.abspath(out_dir or tempfile.mkdtemp(prefix="sbi-deobf-"))
    os.makedirs(out_dir, exist_ok=True)
    proc = subprocess.run(
        [npx, "--yes", "webcrack", source_path, "-o", out_dir],
        capture_output=True, text=True, timeout=timeout, cwd=tempfile.gettempdir())
    if proc.returncode != 0:
        raise RuntimeError(f"webcrack failed: {(proc.stderr or proc.stdout)[-400:]}")
    files = []
    for root, _, names in os.walk(out_dir):
        for n in names:
            p = os.path.join(root, n)
            files.append({"path": p, "bytes": os.path.getsize(p)})
    files.sort(key=lambda f: -f["bytes"])
    return {"output": out_dir, "files": files,
            "source": source_path, "tool": "webcrack"}


def beautify(source_path, out_path=None, timeout=120):
    """Format a minified file with prettier (npm) — the cheap readable view."""
    if not available():
        raise RuntimeError("node is required for beautification")
    source_path = os.path.abspath(source_path)
    out_path = os.path.abspath(out_path or source_path + ".pretty.js")
    npx = shutil.which("npx")
    with open(source_path, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()
    proc = subprocess.run(
        [npx, "--yes", "prettier", "--parser", "babel"],
        input=src, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"prettier failed: {(proc.stderr or proc.stdout)[-400:]}")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(proc.stdout)
    return {"path": out_path, "bytes": len(proc.stdout), "tool": "prettier"}
