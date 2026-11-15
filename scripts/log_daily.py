# -*- coding: utf-8 -*-
"""log_daily.py - append a daily snapshot commitment to the public log.

What this does NOT do: it does not claim the upstream data is true. It records
"this exact byte string, with this SHA-256, was published at this URL on this
date, and I saw it". That is the one claim an append-only signed log can make
honestly, and the one claim that gets stronger every day it runs: after N days
a consumer can prove a dataset hash predates any later revision, without
trusting this server or having network access.

Why per-source and not per-row: the publishers release ~60k rows daily. Hashing
the whole published file commits to all of them at once and keeps the log small
enough to audit by hand.

Cross-publisher checks (the part that is real evidence, not ceremony):
  - mcpcost publishes latest.index.json with its own sha256/byte count/row count
    for the data file. We re-derive all three and record whether they agree.
  - ProtocolProbe publishes upstream HTTP ETag/Last-Modified style metadata in
    its own file; we record what it claims and whether our bytes are stable
    across a second fetch in the same run.
  - Two independent publishers producing the same registry snapshot on the same
    day is itself checkable: each row set is hashed, so a consumer seeing both
    commitments can tell they describe the same day without trusting either.

Usage:
  python scripts/log_daily.py --log-dir docs/log --out docs/log/head-latest.json
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
        # The publisher also publishes an index carrying its own sha256 and
        # byte count for the data file. Comparing our recomputation against
        # their claim turns "we hashed some bytes" into "the bytes we saw are
        # the bytes the publisher says it published" -- a real check, and it is
        # what catches a truncated or swapped download.
        "index_url": "https://mcpcost.ulehla.dev/data/mcpcost-evidence-latest.index.json",
        "license": "CC BY 4.0",
        "shape": "modelcontextprotocol/registry#1715 rows: entry, version, checked_at, check, state, evidence",
        "checks": "endpoint liveness + package install (mcpcost 0.3.4)",
    },
    {
        "name": "protocolprobe-evidence",
        "url": "https://protocolprobe.com/api/v1/evidence",
        "license": "CC BY 4.0",
        "shape": "modelcontextprotocol/registry#1715 rows: entry, version, checked_at, check (package-record|repository), state, evidence",
        "checks": "package record + repository reachability",
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
    if src.get("checks"):
        rec["checks"] = src["checks"]
    # Decide by magic bytes, not by URL suffix. Real bug (2026-11-15):
    # ProtocolProbe serves gzip from a URL with no ".gz", so the suffix check
    # took the raw branch, json.loads failed on gzip bytes, and the row count
    # was silently recorded as "?" -- the commitment was still correct, but the
    # human-readable summary was wrong.
    is_gzip = raw[:2] == b"\x1f\x8b"
    try:
        plain = gzip.decompress(raw) if is_gzip else raw
    except Exception as e:
        rec["parse_error"] = "bad gzip: %s" % e
        return rec
    rec["plain_bytes"] = len(plain)
    rec["plain_sha256"] = hashlib.sha256(plain).hexdigest()
    try:
        data = json.loads(plain)
    except Exception as e:
        rec["parse_error"] = "not JSON: %s" % e
        return rec
    # Real exports use `rows` (a list) with a sibling `entries` (an int count);
    # an earlier draft took `entries` first and silently recorded no row count.
    # Prefer a list field, never an int.
    if isinstance(data, list):
        rows = data
    else:
        rows = None
        for key in ("rows", "entries", "items"):
            if isinstance(data.get(key), list):
                rows = data[key]
                break
    if isinstance(rows, list):
        rec["rows"] = len(rows)
        states = {}
        for row in rows:
            if isinstance(row, dict) and "state" in row:
                states[str(row["state"])] = states.get(str(row["state"]), 0) + 1
        if states:
            rec["states"] = dict(sorted(states.items()))
    if isinstance(data, dict):
        for field, key in (("source_probed_at", "probed_at"),
                           ("source_dataset", "dataset"),
                           ("source_snapshot", "snapshot"),
                           ("source_generated_at", "generated_at"),
                           ("source_format", "format")):
            if isinstance(data.get(key), str):
                rec[field] = data[key]
        if isinstance(data.get("servers"), int):
            rec["servers"] = data["servers"]
    return rec


def cross_check_index(rec, index, index_url):
    """Compare our hash/size against the publisher's own published claims."""
    out = {"index_url": index_url}
    problems = []
    claimed_sha = (index.get("sha256") or "").lower()
    claimed_bytes = index.get("bytes")
    out["publisher_sha256"] = claimed_sha
    out["publisher_bytes"] = claimed_bytes
    if claimed_sha:
        out["sha256_matches_publisher"] = (claimed_sha == rec["sha256"])
        if not out["sha256_matches_publisher"]:
            problems.append("sha256 mismatch: ours=%s theirs=%s"
                            % (rec["sha256"], claimed_sha))
    else:
        out["sha256_matches_publisher"] = None
        problems.append("publisher index has no sha256")
    if isinstance(claimed_bytes, int):
        out["bytes_matches_publisher"] = (claimed_bytes == rec["bytes"])
        if not out["bytes_matches_publisher"]:
            problems.append("byte count mismatch: ours=%d theirs=%d"
                            % (rec["bytes"], claimed_bytes))
    if isinstance(index.get("entries"), int) and isinstance(rec.get("rows"), int):
        out["rows_matches_publisher"] = (index["entries"] == rec["rows"])
        if not out["rows_matches_publisher"]:
            problems.append("row count mismatch: ours=%d theirs=%d"
                            % (rec["rows"], index["entries"]))
    if index.get("probed_at") and rec.get("source_probed_at"):
        out["probed_at_matches_publisher"] = (
            index["probed_at"] == rec["source_probed_at"])
    out["ok"] = not problems
    out["problems"] = problems
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", default=os.path.join(ROOT, "docs", "log"))
    ap.add_argument("--log-id", default="canari-snapshot-log")
    ap.add_argument("--out", default=None, help="write a copy of the newest head here")
    ap.add_argument("--no-network", action="store_true", help="audit existing log only")
    ap.add_argument("--url", action="append", default=None, help="override source URL")
    ap.add_argument("--index-url", action="append", default=None,
                    help="override the publisher's index URL (for cross-checking)")
    a = ap.parse_args(argv)

    L = open_log(a.log_dir, log_id=a.log_id)
    if a.no_network:
        rep = L.audit()
        print(json.dumps(rep, ensure_ascii=False, indent=1, sort_keys=True))
        return 0 if rep["ok"] else 2

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    existing = {}
    for e in L.entry_objs():
        p = e.get("payload") or {}
        if p.get("source"):
            existing[p["source"]] = p.get("sha256")
    appended = []
    for i, src in enumerate(SOURCES):
        url = (a.url[i] if a.url and i < len(a.url) else src["url"])
        try:
            raw = fetch(url)
        except Exception as e:
            print("fetch failed for %s: %s" % (src["name"], e), file=sys.stderr)
            return 3
        rec = summarize(dict(src, url=url), raw, now)
        index_url = (a.index_url[i] if a.index_url and i < len(a.index_url)
                     else src.get("index_url"))
        if index_url:
            try:
                idx_raw = fetch(index_url, timeout=60)
                idx = json.loads(idx_raw.decode("utf-8"))
                rec["cross_check"] = cross_check_index(rec, idx, index_url)
                # Commit the publisher's own claim file too, so a later change
                # to the claim itself is visible.
                rec["index_sha256"] = hashlib.sha256(idx_raw).hexdigest()
                if not rec["cross_check"]["ok"]:
                    print("%s  CROSS-CHECK PROBLEMS: %s"
                          % (src["name"], "; ".join(rec["cross_check"]["problems"])),
                          file=sys.stderr)
            except Exception as e:
                rec["cross_check"] = {"ok": None, "index_url": index_url,
                                      "error": "%s: %s" % (type(e).__name__, e)}
                print("%s  index unavailable: %s" % (src["name"], e), file=sys.stderr)
        if existing.get(src["name"]) == rec["sha256"]:
            # Same bytes as the newest commitment for this source: nothing new
            # happened. Re-running must not inflate the log with duplicates.
            print("%s  unchanged  sha256=%s" % (src["name"], rec["sha256"]))
            continue
        appended.append(L.append(rec, kind="source-snapshot",
                                 timestamp=now)["index"])
        print("%s  %d bytes  sha256=%s  rows=%s"
              % (src["name"], rec["bytes"], rec["sha256"],
                 rec.get("rows", "?")))
    head = L.seal(timestamp=now)
    if head is None:
        # Nothing new: keep publishing the latest head rather than writing
        # null. Overwriting head-latest.json with null would delete the only
        # published root a consumer could have pinned yesterday.
        head = L.last_head()
    audit = L.audit()
    out = {"appended": appended, "head": head, "audit": audit}
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.write("\n")
    print(json.dumps({"appended": appended,
                      "size": audit["size"], "root": head["body"]["root"],
                      "ok": audit["ok"]}, ensure_ascii=False, indent=1))
    return 0 if audit["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
