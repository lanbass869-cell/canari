# -*- coding: utf-8 -*-
"""merkle.py - RFC 9162 style append-only Merkle tree.

Why this exists: a signature on a single record proves who said it, not that
the set of records was never rewritten. A log with inclusion and consistency
proofs lets a third party prove, offline, that (a) a record is in the log and
(b) a later log is a strict extension of an earlier one.

Domain separation follows RFC 9162 section 2.1.1 exactly:
    leaf hash   = SHA-256(0x00 || data)
    node hash   = SHA-256(0x01 || left || right)
    empty tree  = SHA-256("")
Getting this wrong is the classic way to make a log that verifies forged
entries, so the constants are named and tested against independently derived
known answers.
"""
import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

HASH_SIZE = 32
EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    """Hash one entry. `data` is the raw record bytes, not an already-hashed value."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("leaf data must be bytes")
    return hashlib.sha256(LEAF_PREFIX + bytes(data)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != HASH_SIZE or len(right) != HASH_SIZE:
        raise ValueError("node children must be %d-byte hashes" % HASH_SIZE)
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    if n < 2:
        raise ValueError("n must be >= 2")
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaf_hashes) -> bytes:
    """Merkle Tree Hash over an ordered sequence of leaf hashes."""
    leaves = list(leaf_hashes)
    if not leaves:
        return EMPTY_ROOT
    if len(leaves) == 1:
        return leaves[0]
    k = _largest_power_of_two_below(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def root_from_data(items) -> bytes:
    return merkle_root([leaf_hash(d) for d in items])


def _audit_path(leaves, index):
    """RFC 6962 audit path for one leaf, recursive form.

    Deliberately not the SUBPROOF pseudocode: that form carries a boolean whose
    meaning inverts at the base case, and using it for inclusion produced
    proofs that verified only for index 0. The plain recursion below was checked
    against every index of trees of size 1..32 before being adopted.
    """
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return _audit_path(leaves[:k], index) + [merkle_root(leaves[k:])]
    return _audit_path(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def _subproof(m, leaves, include_first):
    """RFC 9162 SUBPROOF, used for consistency proofs (m = prefix size)."""
    n = len(leaves)
    if m == n:
        return [] if include_first else [merkle_root(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(m, leaves[:k], include_first) + [merkle_root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]


def inclusion_proof(leaves, index):
    """Proof that leaves[index] is in the tree. `leaves` are leaf hashes."""
    leaves = list(leaves)
    if not leaves:
        raise ValueError("empty tree has no inclusion proofs")
    if not (0 <= index < len(leaves)):
        raise IndexError("index out of range")
    return _audit_path(leaves, index)


def verify_inclusion(leaf, index, size, root, proof):
    """RFC 9162 section 2.1.3.2 verification, iterative."""
    if size <= 0 or index < 0 or index >= size:
        return False
    fn, sn = index, size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            r = node_hash(p, r)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_proof(leaves, first):
    """Proof that the tree of size `first` is a prefix of the whole tree."""
    leaves = list(leaves)
    n = len(leaves)
    if not (0 <= first <= n):
        raise ValueError("first must be between 0 and the tree size")
    if first == 0 or first == n:
        return []
    return _subproof(first, leaves, True)


def verify_consistency(first, second, first_root, second_root, proof):
    """RFC 9162 section 2.1.4.2 verification.

    The subtle branch is `fn == 0`: the verifier then starts from the trusted
    first_root rather than from a proof element. Getting this wrong makes every
    real consistency proof fail while still accepting forged same-size logs.
    """
    if first < 0 or second < first:
        return False
    if first == second:
        return len(proof) == 0 and first_root == second_root
    if first == 0:
        return len(proof) == 0
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn == 0:
        fr = sr = first_root
        rest = list(proof)
    else:
        if not proof:
            return False
        fr = sr = proof[0]
        rest = list(proof[1:])
    for c in rest:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


def tree_head(items):
    """Minimal tree head over raw record bytes: size plus root."""
    items = list(items)
    return {"size": len(items), "root": root_from_data(items).hex()}