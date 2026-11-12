# -*- coding: utf-8 -*-
"""build_snapshot.py - vendor the newest attestation per component into the package.

Why this exists: `canari-mcp` is published on PyPI and listed in the MCP
Registry. A fresh `pip install canari-mcp` has no `out/` store, so every
gate_check would answer "no attestation" - a listed server that always BLOCKs
is worse than no listing. So the wheel ships a snapshot of the most recent
signed attestation per component (883 of 3251 bundles, ~3.9 MB) and the server
reads it by default. Full history (supersession chains) stays in dataset/.

The snapshot is a PROJECTION of dataset/attestations, built by the same rule the
consumers use (newest generated_at per registry:name), so it cannot disagree
with the ledger.
"""
import glob
import json
import os
import shutil
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from canari.signing import read_signed_payload

SRC = os.path.join(REPO, "dataset")
DST = os.path.join(REPO, "canari", "_snapshot")


def main():
    latest = {}
    for fp in sorted(glob.glob(os.path.join(SRC, "attestations", "*.bundle.json"))):
        with open(fp, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        payload, err = read_signed_payload(bundle)
        if payload is None:
            continue
        s = payload.get("subject", {})
        key = (s.get("registry", "?"), s.get("name", "?"))
        gen = payload.get("generated_at", "")
        if key not in latest or gen > latest[key][0]:
            latest[key] = (gen, fp)

    shutil.rmtree(DST, ignore_errors=True)
    os.makedirs(os.path.join(DST, "attestations"))
    for _key, (_gen, fp) in sorted(latest.items()):
        shutil.copy2(fp, os.path.join(DST, "attestations", os.path.basename(fp)))

    # public keys are needed for anyone verifying the bundled bundles offline
    for name in ("public_key.json", "public_key_20261108.json", "key_registry.json"):
        s = os.path.join(SRC, name)
        if os.path.exists(s):
            shutil.copy2(s, os.path.join(DST, name))

    n = len(glob.glob(os.path.join(DST, "attestations", "*.bundle.json")))
    size = sum(os.path.getsize(f) for f in glob.glob(os.path.join(DST, "**", "*"), recursive=True)
               if os.path.isfile(f))
    print(json.dumps({"components": n, "bytes": size, "mb": round(size / 1024 / 1024, 2)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
