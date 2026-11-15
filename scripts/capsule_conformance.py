# -*- coding: utf-8 -*-
"""capsule_conformance.py - run draft-templeman-scitt-measurement-capsule-01 vectors.

The draft is Experimental because its UNCHECKABLE handling "has not been shown
useful by more than one implementation". This is an attempt to be that second
implementation, so the honest output is not "we conform" but a per-vector table
with every disagreement spelled out.

Usage:
    python scripts/capsule_conformance.py [--vectors PATH] [--json OUT]

Exit 0 when every vector passes, 1 when any fails, 2 on usage error.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from canari import capsule as cap  # noqa: E402


def _hex_or_none(x):
    try:
        return bytes.fromhex(x)
    except Exception:
        return None


def run(vectors):
    results = []

    def add(group, name, ok, detail=""):
        results.append({"group": group, "case": name, "ok": bool(ok),
                        "detail": detail})

    key = vectors["test_key"]
    pub = bytes.fromhex(key["public_hex"])

    # ---- V1: capsule_id over the published JCS bytes
    v1 = vectors.get("V1_capsules", [])
    for c in v1:
        doc = json.loads(c["jcs_utf8"])
        stated = c["capsule_id"]
        got = cap.capsule_id(doc)
        canon = cap.jcs(doc).decode("utf-8") == c["jcs_utf8"]
        add("V1", "%s capsule_id" % doc.get("subject_id", "?"),
            got == stated and canon,
            "" if got == stated else "claimed %s got %s" % (stated[:16], got[:16]))
        problems = cap.validate_capsule(doc)
        add("V1", "%s validate" % doc.get("subject_id", "?"),
            not problems, "; ".join(p["rule"] for p in problems))

    # ---- V2: batch root, audit path, record digest
    b = vectors.get("V2_batch", {})
    ids = b.get("leaves_sorted", [])
    claimed_root = b.get("merkle_root")
    got_root = cap.batch_root(ids)
    add("V2", "merkle_root", got_root == claimed_root,
        "" if got_root == claimed_root else "claimed %s got %s" % (claimed_root[:16], got_root[:16]))
    add("V2", "states cover every capsule",
        sum(b.get("record_jcs_utf8") and json.loads(b["record_jcs_utf8"]).get("states", {}).values() or [0])
        == len(ids), "")

    ap = b.get("audit_path") or {}
    if ap:
        idx = ap["leaf_index"]
        sorted_ids = sorted(ids)
        target = ap["leaf"]
        theirs = ap["path"]
        ours = cap.audit_path(ids, target) if target in sorted_ids else None
        add("V2", "audit_path reproduced byte-for-byte",
            ours == theirs,
            "" if ours == theirs else "theirs %r ours %r" % (theirs, ours))
        leaf = cap._leaf(target)
        proof = [bytes.fromhex(p) for p in theirs]
        add("V2", "audit_path verifies against root",
            cap._recompute(leaf, idx, len(ids), proof) == claimed_root, "")

    rec = b.get("record_jcs_utf8")
    if rec:
        import hashlib
        add("V2", "record_sha256", hashlib.sha256(rec.encode("utf-8")).hexdigest()
            == b.get("record_sha256"), "")
        add("V2", "record.merkle_root agrees",
            json.loads(rec).get("merkle_root") == claimed_root, "")

    # ---- V3: COSE_Sign1 with an attached payload
    #
    # V3 and V4 are single objects, not maps of named cases. An earlier version
    # of this runner iterated .items() over them, skipped every string value
    # with `if not isinstance(v, dict): continue`, and therefore reported
    # "22/22 pass" while contributing zero COSE checks. A conformance runner
    # that silently skips the hardest group is worse than no runner.
    v3 = vectors.get("V3_cose_sign1_attached") or {}
    if isinstance(v3, dict) and "cose_sign1_hex" in v3:
        blob = _hex_or_none(v3.get("cose_sign1_hex"))
        try:
            info = cap.verify_cose_sign1(blob, pub)
            add("V3", "cose_sign1 attached verifies", True, "kid=%s" % info.get("kid"))
        except Exception as e:
            add("V3", "cose_sign1 attached verifies", False,
                "%s: %s" % (type(e).__name__, e))
        try:
            import cbor2
            prot = cbor2.loads(_hex_or_none(v3["protected_hex"]))
            add("V3", "protected header decodes", isinstance(prot, dict),
                "alg=%r" % (prot.get(1) if isinstance(prot, dict) else None))
        except Exception as e:
            add("V3", "protected header decodes", False, str(e))

    # ---- V4: hash envelope
    v4 = vectors.get("V4_cose_hash_envelope") or {}
    if isinstance(v4, dict) and "cose_sign1_hex" in v4:
        blob = _hex_or_none(v4.get("cose_sign1_hex"))
        try:
            info = cap.verify_cose_sign1(blob, pub, hash_envelope=True)
            ok = info["payload"].hex() == v4.get("payload_hex")
            add("V4", "hash envelope verifies", ok,
                "payload=%s" % info["payload"].hex()[:16])
        except Exception as e:
            add("V4", "hash envelope verifies", False, "%s: %s" % (type(e).__name__, e))

    # ---- N: negative controls must be rejected for the stated rule
    for n in vectors.get("N_controls", []):
        want = n["expected"]
        # N3 supplies only the stored line; parse it so the byte comparison can
        # run against the document it claims to be.
        jcs_text = n.get("capsule_jcs_utf8") or n.get("stored_line_utf8")
        try:
            doc = json.loads(jcs_text) if jcs_text else None
        except Exception:
            doc = None
        hit = []
        if doc is not None:
            hit = [p["rule"] for p in cap.validate_capsule(doc)]
        # N3: the violation is in the stored bytes, not the parsed document
        if n.get("stored_line_utf8") is not None and doc is not None:
            hit += [p["rule"] for p in
                    cap.check_stored_bytes(n["stored_line_utf8"].encode("utf-8"), doc)]
        # N6: the violation is in the leaf set
        if n.get("leaves") is not None:
            try:
                got = cap.batch_root(n["leaves"])
                hit.append("leaf-set-root-mismatch" if got != n.get("root") else "none")
            except cap.CapsuleError as e:
                hit.append(str(e).split(":")[0])
        blob_hex = n.get("cose_sign1_hex")
        if blob_hex:
            try:
                cap.verify_cose_sign1(_hex_or_none(blob_hex), pub,
                                      hash_envelope=("rfc9995" in want.get("rule", "")))
            except cap.CapsuleError as e:
                hit.append(str(e).split(":")[0])
            except Exception as e:
                hit.append(type(e).__name__)
        ok = any(want["rule"] in h for h in hit)
        add("N", n["id"], ok,
            "expected %s, got %r" % (want["rule"], hit) if not ok else "")

    return results


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors", default=os.path.join(
        ROOT, "docs", "spec", "measurement-capsule-vectors.json"))
    ap.add_argument("--json", default=None)
    a = ap.parse_args(argv)
    if not os.path.exists(a.vectors):
        print("vectors not found: %s" % a.vectors, file=sys.stderr)
        return 2
    vectors = json.load(open(a.vectors, encoding="utf-8"))
    res = run(vectors)
    width = max(len(r["case"]) for r in res) + 2
    for r in res:
        print("%-4s %-*s %s %s" % (r["group"], width, r["case"],
                                   "PASS" if r["ok"] else "FAIL", r["detail"]))
    passed = sum(1 for r in res if r["ok"])
    print("\n%d/%d vectors pass" % (passed, len(res)))
    if a.json:
        json.dump({"total": len(res), "passed": passed, "results": res},
                  open(a.json, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    return 0 if passed == len(res) else 1


if __name__ == "__main__":
    raise SystemExit(main())
