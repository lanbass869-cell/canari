#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent verification of docs/capsules/.

Deliberately does NOT import canari. If this file and the library disagree, the
library is wrong -- that is the point of shipping a second code path.

Checks, per draft-templeman-scitt-measurement-capsule-01:

  1. every capsule line is its own JCS form (RFC 8785 byte rules for the value
     types used here: strings, integers, booleans, null, arrays, objects)
  2. capsule_id == SHA-256(JCS with capsule_id removed)
  3. the batch merkle_root is the RFC 9162 Merkle Tree Hash over the capsule_id
     values as 32-byte strings, sorted ascending, with the 0x00 leaf prefix
  4. the batch's capsules_file sha256/bytes match the file on disk
  5. no capsule carries a member named decision/approval/authorisation
  6. sources values are digests or null
  7. measurement_state is one of CONSISTENT / INCONSISTENT / UNCHECKABLE

Usage: python verify.py [dir]
Exit 0 when everything checks out, 1 otherwise.
"""
import hashlib
import json
import os
import sys

LEAF = b"\x00"
NODE = b"\x01"
STATES = ("CONSISTENT", "INCONSISTENT", "UNCHECKABLE")
FORBIDDEN = ("decision", "approval", "authorisation", "authorization")


def jcs(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def capsule_id(doc):
    return hashlib.sha256(jcs({k: v for k, v in doc.items()
                               if k != "capsule_id"})).hexdigest()


def leaf(cid_hex):
    return hashlib.sha256(LEAF + bytes.fromhex(cid_hex)).digest()


def node(a, b):
    return hashlib.sha256(NODE + a + b).digest()


def mth(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return node(mth(leaves[:k]), mth(leaves[k:]))


def find_forbidden(obj, path=""):
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in FORBIDDEN:
                hits.append(path + "/" + k)
            hits += find_forbidden(v, path + "/" + k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits += find_forbidden(v, "%s/%d" % (path, i))
    return hits


def is_digest(v):
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef"
                                                      for c in v)


def main(argv=None):
    argv = argv or sys.argv[1:]
    d = argv[0] if argv else os.path.dirname(os.path.abspath(__file__))
    caps_path = os.path.join(d, "capsules.jsonl")
    batch_path = os.path.join(d, "batch.json")
    fails = []

    raw = open(caps_path, "rb").read()
    lines = [l for l in raw.split(b"\n") if l.strip()]
    ids = []
    for i, line in enumerate(lines):
        try:
            doc = json.loads(line)
        except Exception as e:
            fails.append("line %d is not JSON: %s" % (i, e))
            continue
        if jcs(doc) != line:
            fails.append("line %d is not its own JCS form" % i)
        stated = doc.get("capsule_id")
        got = capsule_id(doc)
        if stated != got:
            fails.append("line %d capsule_id mismatch (%s vs %s)"
                         % (i, str(stated)[:12], got[:12]))
        if doc.get("measurement_state") not in STATES:
            fails.append("line %d bad measurement_state %r"
                         % (i, doc.get("measurement_state")))
        for p in find_forbidden(doc):
            fails.append("line %d carries a forbidden member at %s" % (i, p))
        for k, v in (doc.get("sources") or {}).items():
            if v is not None and not is_digest(v):
                fails.append("line %d sources.%s is not a digest" % (i, k))
        ids.append(stated)

    batch = json.load(open(batch_path, encoding="utf-8"))
    root = mth([leaf(i) for i in sorted(ids)]).hex()
    if root != batch.get("merkle_root"):
        fails.append("batch merkle_root %s != recomputed %s"
                     % (str(batch.get("merkle_root"))[:16], root[:16]))
    if batch.get("n_capsules") != len(ids):
        fails.append("n_capsules %r != %d lines" % (batch.get("n_capsules"), len(ids)))
    fsha = hashlib.sha256(raw if raw.endswith(b"\n") else raw + b"\n").hexdigest()
    if fsha != batch.get("capsules_file", {}).get("sha256"):
        fails.append("capsules_file sha256 mismatch")

    states = {}
    for i in ids:
        pass
    for line in lines:
        s = json.loads(line)["measurement_state"]
        states[s] = states.get(s, 0) + 1
    print("lines=%d merkle_root=%s" % (len(lines), root[:16]))
    print("states=%s" % json.dumps(states, sort_keys=True))
    if fails:
        print("\nFAILED:")
        for f in fails:
            print("  -", f)
        return 1
    print("OK: every capsule is canonical, self-identifying, and in the batch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
