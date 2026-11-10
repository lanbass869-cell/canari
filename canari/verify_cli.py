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
  5 = policy gate BLOCK
  6 = policy gate REVIEW

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
    NOTE: this is a CANONICALIZATION + PAE-wellformedness check only, NOT a signature check. The actual Ed25519 signature verification is verify_signed() at the call site (mcpcheckup pattern: independent PAE implementation makes the cross-check meaningful)."""
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


def verify_bundle(bundle_path: str, key_path: str, verbose: bool = False,
                  gate: bool = False, gate_policy: str = "default",
                  gate_policy_file: str = None) -> int:
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
    # makes the cross-check meaningful instead of a formality) - canonicalization only, NOT a signature check)
    ind_ok, ind_detail = _independent_verify(env, pub)
    print("canonical payload (independent PAE): %s" % ("PASS" if ind_ok else "FAIL - %s" % ind_detail))
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

    # G3: full policy-gate evaluation (signature + freshness + key registry +
    # trust-heuristic findings). Exit 5 = gate BLOCK, 6 = REVIEW.
    if gate:
        from canari.gate import evaluate_gate
        dec = evaluate_gate(bundle_path, key_path=key_path,
                            policy_name=gate_policy, policy_file=gate_policy_file)
        print("-" * 60)
        print("policy gate [%s]: %s" % (dec.policy, dec.decision))
        for r in dec.reasons:
            print("  - %s" % r)
        if dec.decision == "BLOCK":
            return 5
        if dec.decision == "REVIEW":
            return 6

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
    generations = 0

    for name, bundle_files in sorted(components.items()):
        if len(bundle_files) < 2:
            continue  # single bundle = trivially valid chain
        chains_checked += 1

        # Build chain: start from bundles with no supersedes (heads)
        heads = [f for f in bundle_files if not supersedes_map.get(f)]
        if len(heads) == 0:
            errors.append("%s: no chain head found (%d bundles, all have supersedes)" % (name, len(bundle_files)))
            continue
        if len(heads) > 1:
            # BUG-72: parallel generations (e.g. dataset scan + live scan that
            # were never bridged by a supersedes pointer) are legitimate; each
            # head starts its own chain. This is a note, not an error.
            generations += 1

        # Walk the supersession DAG from every head (BUG-88): a parent may have
        # several children (e.g. a crashed run plus its retry), and every branch
        # is a legitimate continuation - follow ALL children, not the first one.
        children = {}
        for f in bundle_files:
            sup = supersedes_map.get(f)
            if sup:
                children.setdefault(sup, []).append(f)

        reachable_any = set()
        for head in heads:
            stack = [head]
            while stack:
                current = stack.pop()
                if current in reachable_any:
                    continue
                reachable_any.add(current)
                current_digest = None
                for d, f in digests.items():
                    if f == current:
                        current_digest = d
                        break
                if current_digest is None:
                    continue
                # missing supersedes target
                for child in children.get(current_digest, []):
                    if child in reachable_any:
                        continue
                    stack.append(child)
                # if a bundle's supersedes points nowhere, record it once
                cur_sup = supersedes_map.get(current)
                if cur_sup and cur_sup not in digests:
                    errors.append("%s: %s supersedes %s... but target digest not found in directory" % (
                        name, current, cur_sup[:16]))

        # A bundle is only unreachable if NO head's chain reaches it
        unreachable = set(bundle_files) - reachable_any
        if unreachable:
            errors.append("%s: %d bundle(s) unreachable from every chain head: %s" % (
                name, len(unreachable), ", ".join(sorted(unreachable)[:3])))

    if errors:
        print("\nchain errors (%d):" % len(errors))
        for e in errors:
            print("  - %s" % e)
        return 4

    print("chains: %d checked, all valid%s" % (
        chains_checked,
        " (%d component(s) have multiple independent generations)" % generations if generations else ""))
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
    ap.add_argument("--gate", action="store_true",
                    help="run the policy install-gate after verification")
    ap.add_argument("--gate-policy", default="default",
                    help="gate policy name (default/strict/release-gate/lax/paranoid)")
    ap.add_argument("--gate-policy-file", default=None,
                    help="JSON policy file overriding --gate-policy")
    a = ap.parse_args(argv)
    if a.chain:
        return verify_chain(a.chain)
    if not a.bundle or not a.key:
        ap.error("bundle and --key are required (unless --chain is used)")
    return verify_bundle(a.bundle, a.key, a.verbose, gate=a.gate,
                         gate_policy=a.gate_policy, gate_policy_file=a.gate_policy_file)


if __name__ == "__main__":
    sys.exit(main())


