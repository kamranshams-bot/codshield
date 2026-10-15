"""Upload the generated test data through the API.

    set CODSHIELD_API_KEY=cs_test_...        (Windows)   export CODSHIELD_API_KEY=cs_test_...   (Mac/Linux)
    python testdata/upload.py                 # 5 x 1,000 outcomes, then 500 checks
    python testdata/upload.py --checks-only
    python testdata/upload.py --base http://127.0.0.1:8000
    python testdata/upload.py --key2 cs_live_...   # second store sends batches 3-5 (gives high-risk results)

A cs_test_ key validates everything and stores nothing (safe on the live site).
A cs_live_ key with the 'report' scope stores the outcomes for real. Remove them later with:
    python -m codshield.testdata purge
"""
import argparse
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

import httpx

OUT = Path(__file__).parent / "out"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", default=os.environ.get("CODSHIELD_BASE_URL", "https://codshield-sx1i.onrender.com"))
    p.add_argument("--key", default=os.environ.get("CODSHIELD_API_KEY"))
    p.add_argument("--key2", default=os.environ.get("CODSHIELD_API_KEY_2"),
                   help="a second store's key: batches 3-5 go through it, so customers are reported by two stores "
                        "and can reach the high band (one store alone is capped at medium)")
    p.add_argument("--checks-only", action="store_true")
    a = p.parse_args()
    if not a.key:
        sys.exit("Set CODSHIELD_API_KEY (or pass --key).")
    if not (OUT / "outcomes_batch1.json").exists():
        sys.exit("Run python testdata/generate.py first.")
    test = a.key.startswith("cs_test_")
    print(f"{a.base}  key {a.key[:12]}…  ({'test mode: nothing stored' if test else 'LIVE: data will be stored'})")
    with httpx.Client(base_url=a.base, headers={"X-API-Key": a.key}, timeout=120) as c:
        print("waking the server…", c.get("/health").json())
        if not a.checks_only:
            totals = Counter()
            for i in range(1, 6):
                body = json.loads((OUT / f"outcomes_batch{i}.json").read_text())
                t = time.time()
                hdr = {"X-API-Key": a.key2} if a.key2 and i >= 3 else {}
                r = c.post("/v1/events/batch", json=body, headers=hdr)
                if r.status_code != 200:
                    sys.exit(f"batch {i}: HTTP {r.status_code} {r.text[:300]}")
                got = Counter(x["outcome"] for x in r.json()["results"])
                totals += got
                print(f"batch {i}{' (store 2)' if hdr else ''}: {dict(got)}  ({time.time() - t:.1f}s)")
            print("outcomes total:", dict(totals))
        body = json.loads((OUT / "checks_500.json").read_text())
        r = c.post("/v1/check/batch", json=body)
        if r.status_code != 200:
            sys.exit(f"checks: HTTP {r.status_code} {r.text[:300]}")
        res = r.json()["results"]
        print("checks:", dict(Counter(x.get("band", "error") for x in res)))


if __name__ == "__main__":
    main()
