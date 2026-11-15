#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent verifier for docs/spec/merkle-vectors.json.

Deliberately does NOT import canari. Any implementation of the log should be
able to pass this file; that is the point of publishing vectors.

    leaf = SHA-256(0x00 || data)
    node = SHA-256(0x01 || left || right)
    empty tree root = SHA-256("")

Usage: python verify_vectors.py [path-to-vectors.json]
"""
import hashlib
import json
import os
import sys

LEAF = b"\x00"
NODE = b"\x01"


def h(b):
    return hashlib.sha256(b).digest()


def node(l, r):
    return h(NODE + l + r)


def verify_inclusion(data_hex, index, size, root_hex, proof_hex):
    r = h(LEAF + bytes.fromhex(data_hex))
    fn, sn = index, size - 1
    for p_hex in proof_hex:
        p = bytes.fromhex(p_hex)
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            r = node(p, r)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r.hex() == root_hex


def verify_consistency(first, second, first_root_hex, second_root_hex, proof_hex):
    if first == second:
        return not proof_hex and first_root_hex == second_root_hex
    if first == 0:
        return not proof_hex
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    proof = [bytes.fromhex(x) for x in proof_hex]
    if fn == 0:
        fr = sr = bytes.fromhex(first_root_hex)
    else:
        if not proof:
            return False
        fr = sr = proof[0]
        proof = proof[1:]
    for c in proof:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            fr = node(c, fr)
            sr = node(c, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr.hex() == first_root_hex and sr.hex() == second_root_hex


def main(argv):
    path = argv[1] if len(argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "merkle-vectors.json")
    v = json.load(open(path, encoding="utf-8"))
    bad = 0
    for x in v["inclusion"]:
        if not verify_inclusion(x["data_hex"], x["index"], x["size"],
                                x["root"], x["proof"]):
            bad += 1
            print("FAIL inclusion", x["index"], x["size"])
    for x in v["consistency"]:
        if not verify_consistency(x["first"], x["second"], x["first_root"],
                                  x["second_root"], x["proof"]):
            bad += 1
            print("FAIL consistency", x["first"], x["second"])
    total = len(v["inclusion"]) + len(v["consistency"])
    print("%d/%d vectors passed" % (total - bad, total))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))