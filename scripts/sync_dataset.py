# -*- coding: utf-8 -*-
"""sync_dataset.py - keep dataset/ in sync with the live store.

dataset/ is the public CC-BY-4.0 snapshot; out/ is the working store. Running
this after a scan republishes the snapshot with a MANIFEST of sha256 digests.
"""
import glob
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "out")
DS = os.path.join(REPO, "dataset")


def _copy_tree(src, dst, pattern="*.json"):
    shutil.rmtree(dst, ignore_errors=True)
    os.makedirs(dst, exist_ok=True)
    n = 0
    for f in sorted(glob.glob(os.path.join(src, pattern))):
        shutil.copy2(f, os.path.join(dst, os.path.basename(f)))
        n += 1
    return n


def sync():
    n_att = _copy_tree(os.path.join(OUT, "attestations"), os.path.join(DS, "attestations"),
                       "*.bundle.json")
    n_feed = _copy_tree(os.path.join(OUT, "feed"), os.path.join(DS, "feeds"))
    drift_src = os.path.join(OUT, "drift")
    if os.path.isdir(drift_src):
        _copy_tree(drift_src, os.path.join(DS, "drift"))
    for name in ("public_key.json", "public_key_20261108.json"):
        src = os.path.join(OUT, name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(DS, name))
    # key_registry is published, but without the operator's local private-key path
    reg_src = os.path.join(OUT, "key_registry.json")
    if os.path.exists(reg_src):
        reg = json.load(open(reg_src, encoding="utf-8"))
        reg.pop("private_key_path", None)
        with open(os.path.join(DS, "key_registry.json"), "w", encoding="utf-8") as f:
            json.dump(reg, f, ensure_ascii=False, indent=1)
    shutil.copy2(os.path.join(REPO, "canari", "attestation-v0.1.json"),
                 os.path.join(DS, "attestation-v0.1.json"))

    manifest = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "license": "CC-BY-4.0", "attestations": n_att, "feeds": n_feed,
                "sha256": {}}
    for root, _, files in os.walk(DS):
        for fn in files:
            if fn == "MANIFEST.json":
                continue
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, DS).replace("\\", "/")
            manifest["sha256"][rel] = hashlib.sha256(open(fp, "rb").read()).hexdigest()
    with open(os.path.join(DS, "MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)
    return {"attestations": n_att, "feeds": n_feed, "files": len(manifest["sha256"])}


if __name__ == "__main__":
    print(json.dumps(sync(), ensure_ascii=False))
