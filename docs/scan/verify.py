#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent re-derivation of the 20 records in this directory.

This deliberately does NOT import canari. It re-implements the three steps a
sceptical reader needs:

  1. DSSE/Ed25519 signature check over the envelope, using only `cryptography`
  2. artifact binding: the record's subject.artifact_sha256 equals the sha256
     recorded in MANIFEST.json
  3. verdict re-derivation: recompute the verdict straight from the raw bandit
     JSON and compare it with what the signed record claims

If step 3 fails, the record is signed but wrong - which is the failure mode a
signature alone can never catch.

Usage:  python verify.py
Requires: cryptography  (pip install cryptography)
Exit code 0 only if every record passes all three checks.
"""
import base64
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
DSSE_PREFIX = b"DSSEv1 "

SEV_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def pae(payload_type: bytes, payload: bytes) -> bytes:
    return (DSSE_PREFIX + str(len(payload_type)).encode() + b" " + payload_type
            + b" " + str(len(payload)).encode() + b" " + payload)


def load_pubkey(path):
    doc = json.load(open(path, encoding="utf-8"))
    raw = bytes.fromhex(doc["keyval"]["public"])
    if len(raw) != 32:
        raise ValueError("expected a 32-byte raw Ed25519 key, got %d" % len(raw))
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_envelope(envelope, pub) -> bool:
    payload = base64.b64decode(envelope["payload"])
    ptype = envelope["payloadType"].encode()
    signed = pae(ptype, payload)
    for sig in envelope.get("signatures", []):
        try:
            pub.verify(base64.b64decode(sig["sig"]), signed)
            return True
        except Exception:
            continue
    return False


def canonical_sha256(obj) -> str:
    canon = json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def derive_verdict(report) -> str:
    """Recompute the verdict from bandit JSON without using canari's code."""
    results = report.get("results") or []
    errors = report.get("errors") or []
    if errors:
        return "error"
    if not results:
        return "pass"
    highest = min(SEV_RANK.get(str(r.get("issue_severity", "")).upper(), 3)
                  for r in results)
    return "fail" if highest == 0 else "pass-with-findings"


def main():
    manifest = json.load(open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8"))
    pub = load_pubkey(os.path.join(HERE, "public_key.json"))

    failures = 0
    for rec in manifest["records"]:
        name = rec["package"]
        problems = []

        bundle = json.load(open(os.path.join(HERE, rec["bundle"]), encoding="utf-8"))
        if not verify_envelope(bundle["envelope"], pub):
            problems.append("signature")

        payload = json.loads(base64.b64decode(bundle["envelope"]["payload"]))
        predicate = payload.get("predicate") or {}

        subject_digest = ((payload.get("subject") or [{}])[0].get("digest") or {}).get("sha256")
        if subject_digest and subject_digest != rec["artifact_sha256"]:
            problems.append("artifact digest mismatch")

        report = json.load(open(os.path.join(HERE, rec["input"]), encoding="utf-8"))
        if predicate.get("scenario_sha256") != canonical_sha256(report):
            problems.append("scenario hash does not match the published scanner output")

        expected = derive_verdict(report)
        claimed = predicate.get("verdict")
        if expected != claimed:
            problems.append("verdict: record says %r, scanner output implies %r"
                            % (claimed, expected))

        status = "PASS" if not problems else "FAIL"
        if problems:
            failures += 1
        print("%-4s %-38s %s" % (status, name, "; ".join(problems)))

    total = len(manifest["records"])
    print("\n%d/%d records passed all checks" % (total - failures, total))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())