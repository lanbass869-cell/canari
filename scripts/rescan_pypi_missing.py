# -*- coding: utf-8 -*-
"""rescan_pypi_missing.py - fill gaps without re-walking the whole cohort.

Usage: python scripts/rescan_pypi_missing.py [--limit N]
Reads the names from a file (one per line) and reuses run_multi's machinery by
temporarily attaching them to a synthetic enumeration result, so the attestation
format, heuristics and supersession behaviour stay identical to a normal scan.
"""
import argparse
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import canari.baseline as bl
from canari.npm_enum import _fetch_pypi_meta_bulk


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--names-file", default=r"E:\Temp\_missing_pypi.txt")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default="out")
    a = ap.parse_args()

    names = [l.strip() for l in open(a.names_file, encoding="utf-8") if l.strip()]
    if a.limit:
        names = names[:a.limit]
    print("targets: %d" % len(names))

    # Fetch metadata with the same bounded-concurrency helper a normal scan uses.
    pkgs = _fetch_pypi_meta_bulk(names)
    ok = [p for p in pkgs if "error" not in p]
    bad = [p for p in pkgs if "error" in p]
    print("metadata ok: %d | error: %d" % (len(ok), len(bad)))
    for b in bad[:8]:
        print("   !", b["name"], b["error"][:60])

    # Reuse run_multi by patching the PyPI enumerator for this one call.
    orig = bl.pypi_enumerate
    bl.pypi_enumerate = lambda limit=0, cache_path=None: ok
    try:
        res = bl.run_multi(npm_limit=0, pypi_limit=len(ok), registry_limit=0,
                           dsh_limit=0, out_dir=a.out)
    finally:
        bl.pypi_enumerate = orig
    print(json.dumps({"total": res.get("total"), "errors": res.get("errors"),
                      "by_registry": res.get("by_registry")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
