# -*- coding: utf-8 -*-
"""verify_live_sample.py - re-derive stored attestations from live registries.

For a random sample of attestations, re-fetch the artifact the bundle claims to
bind (npm tarball for the exact version / PyPI file digest) and compare the
sha256. A mismatch means the ledger bound a hash that does not match reality.
Nothing is written; this is a read-only data audit.
"""
import glob
import hashlib
import json
import os
import random
import sys
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from canari.npm_enum import _opener, UA, fetch_packument, latest_version_info  # noqa: E402

N_NPM = int(os.environ.get("SAMPLE_NPM", "10"))
N_PYPI = int(os.environ.get("SAMPLE_PYPI", "8"))


def bundles():
    out = []
    for f in glob.glob(os.path.join(HERE, "out", "attestations", "*.bundle.json")):
        try:
            p = json.load(open(f, encoding="utf-8"))["payload"]
            out.append((f, p))
        except Exception:
            pass
    return out


def npm_hash(name, version, timeout=60):
    pack = fetch_packument(name)
    info = (pack.get("versions") or {}).get(version)
    if not info:
        return None, "version not found"
    url = (info.get("dist") or {}).get("tarball")
    if not url:
        return None, "no tarball"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    h = hashlib.sha256()
    with _opener().open(req, timeout=timeout) as r:
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest(), None


def pypi_hash(name, version):
    url = "https://pypi.org/pypi/%s/%s/json" % (name, version)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with _opener().open(req, timeout=30) as r:
        d = json.loads(r.read().decode())
    urls = d.get("urls") or []
    if not urls:
        return None, "no files"
    return urls[0]["digests"]["sha256"], None


def main():
    allb = bundles()
    npm = [(f, p) for f, p in allb if p["subject"]["registry"] == "npm"
           and p["subject"].get("version") and p["subject"]["artifact_sha256"] != "0" * 64]
    pypi = [(f, p) for f, p in allb if p["subject"]["registry"] == "pypi"
            and p["subject"].get("version") and p["subject"]["artifact_sha256"] != "0" * 64]
    random.seed(42)
    sample_npm = random.sample(npm, min(N_NPM, len(npm)))
    sample_pypi = random.sample(pypi, min(N_PYPI, len(pypi)))

    ok = mismatch = errored = 0
    for f, p in sample_npm:
        s = p["subject"]
        try:
            live, err = npm_hash(s["name"], s["version"])
        except Exception as e:
            live, err = None, str(e)[:60]
        if live is None:
            errored += 1
            print("  [ERR ] npm:%s@%s -> %s" % (s["name"], s["version"], err))
        elif live == s["artifact_sha256"]:
            ok += 1
        else:
            mismatch += 1
            print("  [MISMATCH] npm:%s@%s stored=%s live=%s" % (
                s["name"], s["version"], s["artifact_sha256"][:12], live[:12]))
    for f, p in sample_pypi:
        s = p["subject"]
        try:
            live, err = pypi_hash(s["name"], s["version"])
        except Exception as e:
            live, err = None, str(e)[:60]
        if live is None:
            errored += 1
            print("  [ERR ] pypi:%s@%s -> %s" % (s["name"], s["version"], err))
        elif live == s["artifact_sha256"]:
            ok += 1
        else:
            mismatch += 1
            print("  [MISMATCH] pypi:%s@%s stored=%s live=%s" % (
                s["name"], s["version"], s["artifact_sha256"][:12], live[:12]))

    total = ok + mismatch + errored
    print("\nchecked=%d ok=%d mismatch=%d errored=%d" % (total, ok, mismatch, errored))
    return 0 if mismatch == 0 and errored == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
