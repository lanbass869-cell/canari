# -*- coding: utf-8 -*-
"""drift_cli.py - canari-drift: what changed between scan generations."""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

from canari.drift import compute_drift, format_report


def main(argv=None):
    ap = argparse.ArgumentParser(prog="canari-drift",
                                 description="Compare each component's newest attestation with its previous one.")
    ap.add_argument("--store", default="out")
    ap.add_argument("--since", default=None, help="ISO timestamp; skip components older than this")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--write", default=None, help="write JSON to DIR (default name drift-YYYYMMDD.json)")
    a = ap.parse_args(argv)

    rep = compute_drift(a.store, since=a.since)
    if a.write:
        os.makedirs(a.write, exist_ok=True)
        name = "drift-%s.json" % datetime.now(timezone.utc).strftime("%Y%m%d")
        fp = os.path.join(a.write, name)
        rep["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=1)
        print("[drift] written to %s" % fp)
    print(json.dumps(rep, ensure_ascii=False, indent=1) if a.json else format_report(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
