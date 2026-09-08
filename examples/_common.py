import os
import sys


def require_config():
    if not (os.environ.get("SCRAPELESS_API_TOKEN") or os.environ.get("SCRAPELESS_CDP_URL")):
        print("set SCRAPELESS_API_TOKEN (or SCRAPELESS_CDP_URL) to run this example")
        sys.exit(1)


def target():
    return os.environ.get("SBI_TARGET", "https://example.com")
