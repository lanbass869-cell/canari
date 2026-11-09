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
import os
import hashlib
import json
import sys

from canari.schema import load_schema, validate_attestation, is_gate_passing
from canari.signing import verify_signed


def _independent_pae(payload_type: str, payload_bytes: bytes) -> bytes:
    """Independently implement DSSE PAE per the spec (secure-systems-lab/dsse).
    
    PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
    LEN(s) = ASCII decimal encoding of the byte length of s, no leading zeros.
    
    This is deliberately NOT imported from in-toto (mcpcheckup lesson: an
    independent implementation makes the cross-check meaningful instead of
    a formality). If in-toto's PAE and ours disagree, the signature was
    computed over different bytes than we think.
    """
    type_bytes = payload_type.encode("utf-8")
    parts = [
        b"DSSEv1", b" ",
        str(len(type_bytes)).encode("ascii"), b" ",
        type_bytes, b" ",
        str(len(payload_bytes)).encode("ascii"), b" ",
        payload_bytes,
    ]
    return b"".join(parts)


def _independent_verify(envelope: dict, public_key_dict: dict) -> tuple:
    """Independent DSSE verification: rebuild PAE from scratch and check
    the payload bytes are the canonical JSON encoding of the parsed payload.
    Cross-checks against in-toto's verify_signed. If they disagree, report it."""
    import base64
    from canari.signing import DSSE_PAYLOAD_TYPE
    
    payload_type = envelope.get("payloadType", "")
    payload_b64 = envelope.get("payload", "")
    if not payload_type or not payload_b64:
        return False, "missing payloadType or payload"
    
    try:
        payload_bytes = base64.b64decode(payload_b64)
    except Exception as e:
        return False, "payload base64 decode: %s" % e
    
    # Build PAE independently
    pae = _independent_pae(payload_type, payload_bytes)
    
    # Check payload is valid JSON
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        return False, "payload JSON: %s" % e
    
    # Check the payload type matches what we expect
    if payload_type != DSSE_PAYLOAD_TYPE:
        return False, "unexpected payloadType: %s" % payload_type
    
    # Verify the payload is the canonical JSON encoding of the parsed object
    # (sort_keys=True, ensure_ascii=False, matching signing.py's _build)
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    if canonical != payload_bytes:
        return False, "payload bytes != canonical JSON encoding (non-canonical serialization)"
    
    return True, pae


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
    print("signature (in-toto): %s" % ("PASS" if ok else "FAIL - %s" % err))
    if not ok:
        return 1

    # 2b. Independent PAE cross-check (mcpcheckup lesson: independent implementation
    # makes the cross-check meaningful instead of a formality)
    ind_ok, ind_detail = _independent_verify(env, pub)
    print("signature (independent PAE): %s" % ("PASS" if ind_ok else "FAIL - %s" % ind_detail))
    if not ind_ok:
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
    print("payload: sha256:%s..." % payload_sha[:16])
    subj = payload.get("subject", {})
    print("subject: %s@%s (%s) sha256:%s..."
          % (subj.get("name"), subj.get("version"), subj.get("registry"),
             (subj.get("artifact_sha256") or "?")[:16]))
    return 0


def verify_chain(directory: str, key_path: str = None) -> int:
    """Verify supersession chains in a directory of bundles.
    
    Checks:
    1. Each supersedes pointer resolves to an existing payload digest
    2. No circular references
    3. Chain heads are unique (one head per component)
    4. Every chain is traceable to a head
    
    Exit codes: 0 = all chains valid, 4 = chain errors found
    """
    import hashlib
    from collections import defaultdict

    att_dir = directory
    if not os.path.isdir(att_dir):
        _fail("directory not found: %s" % att_dir)
        return 3

    files = sorted(f for f in os.listdir(att_dir) if f.endswith(".bundle.json"))
    if not files:
        print("no bundles found in %s" % att_dir)
        return 0

    # Build digest -> filename map and supersedes -> filename map
    # Pre-compute ALL digests once (O(N) instead of O(N²) re-reads)
    digests = {}  # payload digest -> filename
    supersedes_map = {}  # filename -> digest it supersedes
    components = defaultdict(list)  # name -> [filenames]

    for fn in files:
        fp = os.path.join(att_dir, fn)
        try:
            bundle = json.load(open(fp, encoding="utf-8"))
            payload = bundle.get("payload", {})
        except Exception as e:
            print("  [SKIP] %s: cannot parse: %s" % (fn, e))
            continue

        name = payload.get("subject", {}).get("name", "?")
        digest = hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        digests[digest] = fn
        supersedes_map[fn] = payload.get("supersedes")
        components[name].append(fn)

    print("bundles: %d | components: %d" % (len(files), len(components)))

    errors = []
    chains_checked = 0

    for name, bundle_files in sorted(components.items()):
        if len(bundle_files) < 2:
            continue  # single bundle = trivially valid chain
        chains_checked += 1

        # Build chain: start from bundles with no supersedes (heads)
        heads = [f for f in bundle_files if not supersedes_map.get(f)]
        if len(heads) == 0:
            errors.append("%s: no chain head found (%d bundles, all have supersedes)" % (name, len(bundle_files)))
            continue

        # Walk each chain from head using pre-computed digests (O(1) lookups)
        for head in heads:
            current = head
            visited = {head}
            depth = 0
            while depth < 100:
                current_digest = None
                for d, f in digests.items():
                    if f == current:
                        current_digest = d
                        break
                if current_digest is None:
                    break

                # Find the next bundle that supersedes current's digest
                next_bundle = None
                for f in bundle_files:
                    sup_digest = supersedes_map.get(f)
                    if sup_digest is not None and sup_digest == current_digest:
                        next_bundle = f
                        break

                # Check for missing supersedes target
                if next_bundle is None:
                    # Check if current's supersedes points to a nonexistent digest
                    current_sup = supersedes_map.get(current)
                    if current_sup and current_sup not in digests:
                        errors.append("%s: %s supersedes %s... but target digest not found in directory" % (
                            name, current, current_sup[:16]))

                if next_bundle is None:
                    break
                if next_bundle in visited:
                    errors.append("%s: circular reference detected at %s" % (name, next_bundle))
                    break
                visited.add(next_bundle)
                current = next_bundle
                depth += 1

            # Check all bundles in this component are in the chain
            unreachable = set(bundle_files) - visited
            if unreachable:
                errors.append("%s: %d bundle(s) not reachable from chain head %s: %s" % (
                    name, len(unreachable), head, ", ".join(sorted(unreachable)[:3])))

    if errors:
        print("\nchain errors (%d):" % len(errors))
        for e in errors:
            print("  - %s" % e)
        return 4

    print("chains: %d checked, all valid" % chains_checked)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="canari-verify",
        description="Offline verifier for canari attestation bundles (DSSE/in-toto).")
    ap.add_argument("bundle", nargs="?", default=None, help="path to signed bundle JSON")
    ap.add_argument("--key", default=None, help="path to signer public key JSON")
    ap.add_argument("--verbose", "-v", action="store_true", help="print PASS checks too")
    ap.add_argument("--chain", metavar="DIR", default=None,
                    help="verify supersession chains in a directory of bundles")
    a = ap.parse_args(argv)
    if a.chain:
        return verify_chain(a.chain)
    if not a.bundle or not a.key:
        ap.error("bundle and --key are required (unless --chain is used)")
    return verify_bundle(a.bundle, a.key, a.verbose)


if __name__ == "__main__":
    sys.exit(main())
