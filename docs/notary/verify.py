#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent check of the notary record in this directory.

Does not import Canari. Re-derives:
  1. the DSSE/Ed25519 signature over the envelope
  2. that the record's subject.artifact_sha256 equals the sha256 published in
     source_index.json (the producer's own claim)
  3. that the producer's summary adds up (states and checks each sum to entries)

Usage: python verify.py     (needs: pip install cryptography)
"""
import base64, hashlib, json, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
SEP = b"DSSEv1 "


def pae(pt: bytes, payload: bytes) -> bytes:
    return SEP + str(len(pt)).encode() + b" " + pt + b" " + str(len(payload)).encode() + b" " + payload


def main():
    pubdoc = json.load(open(os.path.join(HERE, "public_key.json"), encoding="utf-8"))
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubdoc["keyval"]["public"]))
    idx = json.load(open(os.path.join(HERE, "source_index.json"), encoding="utf-8"))
    recdir = os.path.join(HERE, "records")
    bundles = [f for f in sorted(os.listdir(recdir)) if f.endswith(".bundle.json")]
    if not bundles:
        print("no records"); return 1

    failures = 0
    for name in bundles:
        problems = []
        b = json.load(open(os.path.join(recdir, name), encoding="utf-8"))
        env = b["envelope"]
        payload = base64.b64decode(env["payload"])
        try:
            pub.verify(base64.b64decode(env["signatures"][0]["sig"]),
                       pae(env["payloadType"].encode(), payload))
        except Exception:
            problems.append("signature")
        pred = json.loads(payload)["predicate"]
        if pred["subject"]["artifact_sha256"] != idx.get("sha256"):
            problems.append("record sha256 != producer index sha256")
        entries = idx.get("entries")
        for key in ("states", "checks"):
            d = idx.get(key) or {}
            if d and sum(d.values()) != entries:
                problems.append("%s do not sum to entries" % key)
        print("%-5s %s %s" % ("PASS" if not problems else "FAIL", name, "; ".join(problems)))
        failures += 0 if not problems else 1
    print("\n%d/%d records passed" % (len(bundles) - failures, len(bundles)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())