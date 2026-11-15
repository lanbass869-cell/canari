# -*- coding: utf-8 -*-
"""log_daily.py - append a daily snapshot commitment to the public log.

What this does NOT do: it does not claim the upstream data is true. It records
"this exact byte string, with this SHA-256, was published at this URL on this
date, and I saw it". That is the one claim an append-only signed log can make
honestly, and the one claim that gets stronger every day it runs: after N days
a consumer can prove a dataset hash predates any later revision, without
trusting this server or having network access.

Why per-source and not per-row: mcpcost publishes 62k rows daily. Hashing the
whole published file commits to all of them at once and keeps the log small
enough to audit by hand. Row-level inclusion is a separate concern and needs
the upstream to publish stable row ids.

Usage:
  python scripts/log_daily.py --log-dir docs/log --out docs/log/snapshots
  python scripts/log_daily.py --log-dir docs/log --no-network   # audit only
"""
import argparse
import gzip
import hashlib
import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from canari.logstore import open_log  # noqa: E402

SOURCES = [
    {
        "name": "mcpcost-evidence",
        "url": "https://mcpcost.ulehla.dev/data/mcpcost-evidence-latest.json.gz",
        "license": "CC BY 4.0",
        "shape": "modelcontextprotocol/registry#1715 rows: entry, version, checked_at, check, state, evidence",
    },
]

MAX_BYTES = 64 * 1024 * 1024


def fetch(url, timeout=600):
    req = urllib.request.Request(url, headers={"User-Agent": "canari-log/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("response exceeds %d bytes" % MAX_BYTES)
    return raw


def summarize(src, raw, now):
    rec = {"source": src["name"], "url": src["url"], "license": src["license"],
           "fetched_at": now, "bytes": len(raw),
           "sha256": hashlib.sha256(raw).hexdigest()}
    try:
        plain = gzip.decompress(raw) if src["url"].endswith(".gz") else raw
    except Exception as e:
        rec["parse_error"] = "not gzip: %s" % e
        return rec
    rec["plain_bytes"] = len(plain)
    rec["plain_sha256"] = hashlib.sha256(plain).hexdigest()
    try:
        data = json.loads(plain)
    except Exception as e:
        rec["parse_error"] = "not JSON: %s" % e
        return rec
    rows = data if isinstance(data, list) else data.get("entries") or data.get("rows")
    if isinstance(rows, list):
        rec["rows"] = len(rows)
        states = {}
        for row in rows:
            if isinstance(row, dict) and "state" in row:
                states[str(row["state"])] = states.get(str(row["state"]), 0) + 1
        if states:
            rec["states"] = dict(sorted(states.items()))
    return rec


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", default=os.path.join(ROOT, "docs", "log"))
    ap.add_argument("--log-id", default="canari-snapshot-log")
    ap.add_argument("--out", default=None, help="write a copy of the newest head here")
    ap.add_argument("--no-network", action="store_true", help="audit existing log only")
    ap.add_argument("--url", action="append", default=None, help="override source URL")
    a = ap.parse_args(argv)

    L = open_log(a.log_dir, log_id=a.log_id)
    if a.no_network:
        rep = L.audit()
        print(json.dumps(rep, ensure_ascii=False, indent=1, sort_keys=True))
        return 0 if rep["ok"] else 2

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    appended = []
    for i, src in enumerate(SOURCES):
        url = (a.url[i] if a.url and i < len(a.url) else src["url"])
        try:
            raw = fetch(url)
        except Exception as e:
            print("fetch failed for %s: %s" % (src["name"], e), file=sys.stderr)
            return 3
        rec = summarize(dict(src, url=url), raw, now)
        appended.append(L.append(rec, kind="source-snapshot",
                                 timestamp=now)["index"])
        print("%s  %d bytes  sha256=%s  rows=%s"
              % (src["name"], rec["bytes"], rec["sha256"],
                 rec.get("rows", "?")))
    head = L.seal(timestamp=now)
    audit = L.audit()
    out = {"appended": appended, "head": head, "audit": audit}
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.write("\n")
    print(json.dumps(out, ensure_ascii=False, indent=1, sort_keys=True))
    return 0 if audit["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
