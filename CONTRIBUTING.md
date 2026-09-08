# Contributing

## Dev setup

```bash
git clone <repo> && cd Scrapeless-Browser-Instrumentation
pip install -r requirements.txt        # just websockets
pip install mcp                        # optional: MCP server
python -m unittest discover -s tests -v
```

Everything is offline: the suite runs a fake in-process CDP websocket server
and executes the page-side probe snippets under Node. No Scrapeless token, no
browser. Node on PATH is recommended (offline-verify and probe-js tests skip
cleanly without it).

## Running against the real thing

```bash
export SCRAPELESS_API_TOKEN=...        # or SCRAPELESS_CDP_URL / --cdp
python examples/selftest.py            # hook invisibility, live
python -m sbi https://target/ --hook 'window.sign' --capture-returns
```

Examples are executable proof: each asserts its own outcome and prints PASS.

## Adding a capability

1. `sbi/<subpackage>/<module>.py` — pure functions over `(cdp, sid, ...)`; stdlib only;
   module docstring states the WHY first.
2. Facade method on `Session` in `sbi/api.py`.
3. Coverage: extend the fake CDP server + tests in `tests/test_offline.py`
   (zero-padded test names — the suite is order-dependent by design).
4. An `examples/<name>.py` that proves it end to end.
5. Docs: a recipe in `docs/recipes.md` if there's a workflow, an entry in
   `docs/mcp-tools.md` if you expose an MCP tool.
6. Keep stealth accounting current: `docs/threat-model.md` must say what the
   page can observe about your feature.

## Style

- Module docstring first, explaining why the module exists.
- Comments only for constraints the code can't show (ordering races, protocol
  quirks, invisibility requirements). No narration.
- Core (`sbi/`) stays dependency-free except `websockets`; `mcp` is optional
  and imported lazily inside `mcp_server.main()`.
- Handlers that run on the CDP event pump must stay fast: the page is paused
  while they run. Do heavy work on the caller's thread.

## Tests

`python -m unittest discover -s tests -v` — must stay green on Windows and
Linux. New modules ship with their own `tests/test_<module>.py` (pure,
no browser) unless the fake server covers them.

Before merging behavioural changes, run the live battery against a real
Chromium — it catches what fakes can't:

```bash
chrome --headless=new --remote-debugging-port=9222 --user-data-dir=%TEMP%\sbi
python -m unittest tests.test_live -v          # skips if no endpoint answers
for ex in examples/*.py; do SCRAPELESS_CDP_URL=http://127.0.0.1:9222 python $ex; done
```

## Release checklist

1. Bump `__version__` in `sbi/__init__.py` and the `[project]` version in
   `pyproject.toml`.
2. Update `CHANGELOG.md` (Keep a Changelog format).
3. Full suite green on both OSes; tag `vX.Y.Z`.

## Ground rules

Authorized targets only. If your change touches what pages can observe,
document it in the threat model — never silently.
