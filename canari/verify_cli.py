# -*- coding: utf-8 -*-
"""verify_cli.py - M0 task 2: offline verifier CLI.

Input: a signed bundle (JSON file containing {"envelope": {...}, "payload": {...}})
        + a public key JSON file.
Output: per-check pass/fail lines + overall verdict + exit code.

Exit codes (stable, documented - MemTether cli_health discipline):
  0 = bundle valid, signature PASS, schema PASS
  1 = signature FAIL (tampered or wrong key)
  2 = schema FAIL (payload violates attestation-v0.1)
  3 = usage / file errors

Failure/skip counts are printed explicitly (plan section 4: "failure/skip
counters public - anti pass-rate-inflation", RUSE lesson).
"""
import argparse
import hashlib
import json
import sys

from canari.schema import load_schema, validate_attestation, is_gate_passing
from canari.signing import verify_signed


def _fail(msg):
    sys.stderr.write("[verify] FAIL: %s\n" % msg)


def verify_bundle(bundle_path: str, key_path: str, verbose: bool = False) -> int:
    # 1. load files
    try:
        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as e:
        _fail("cannot read bundle: %s" % e)
        return 3
    try:
        with open(key_path, "r", encoding="utf-8") as f:
            pub = json.load(f)
    except Exception as e:
        _fail("cannot read public key: %s" % e)
        return 3

    env = bundle.get("envelope")
    if not env:
        _fail("bundle has no 'envelope' object")
        return 3

    # 2. verify signature (offline - no network calls anywhere in this module)
    ok, payload, err = verify_signed(env, pub)
    print("signature: %s" % ("PASS" if ok else "FAIL - %s" % err))
    if not ok:
        return 1

    # 3. schema validate payload
    errors = validate_attestation(payload)
    if errors:
        print("schema:    FAIL (%d error(s))" % len(errors))
        for e in errors:
            print("  - %s" % e)
        return 2
    print("schema:    PASS (attestation-v0.1)")

    # 4. per-check breakdown (the actual value:逐项 pass/fail)
    checks = payload.get("checks", [])
    n_pass = n_fail = n_skip = n_unsupported = n_error = 0
    for c in checks:
        v = c.get("verdict")
        marker = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP",
                  "unsupported": "UNSUP", "error": "ERROR"}.get(v, "?%s" % v)
        if v == "pass":
            n_pass += 1
        elif v == "fail":
            n_fail += 1
        elif v == "skip":
            n_skip += 1
        elif v == "unsupported":
            n_unsupported += 1
        else:
            n_error += 1
        if verbose or v != "pass":
            ev = c.get("evidence_ref", "")
            dur = c.get("duration_ms", "")
            print("  [%s] %-38s tool=%-22s %sms %s" % (
                marker, c.get("id", "<no-id>"), c.get("tool", "?"), dur,
                ("ev=%s" % ev[:40]) if ev else ""))
    print("-" * 60)
    print("checks: %d total | PASS %d | FAIL %d | SKIP %d | UNSUP %d | ERROR %d"
          % (len(checks), n_pass, n_fail, n_skip, n_unsupported, n_error))
    print("run verdict: %s | gate: %s"
          % (payload.get("verdict"), "ALLOW" if is_gate_passing(payload) else "BLOCK"))

    # 5. payload integrity echo (what the signature actually covers)
    payload_sha = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    print("payload sha256: %s..." % payload_sha[:16])
    subj = payload.get("subject", {})
    print("subject: %s@%s (%s) sha256:%s..."
          % (subj.get("name"), subj.get("version"), subj.get("registry"),
             (subj.get("artifact_sha256") or "?")[:16]))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="canari-verify",
        description="Offline verifier for canari attestation bundles (DSSE/in-toto).")
    ap.add_argument("bundle", help="path to signed bundle JSON")
    ap.add_argument("--key", required=True, help="path to signer public key JSON")
    ap.add_argument("--verbose", "-v", action="store_true", help="print PASS checks too")
    a = ap.parse_args(argv)
    return verify_bundle(a.bundle, a.key, a.verbose)


if __name__ == "__main__":
    sys.exit(main())
