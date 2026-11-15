# -*- coding: utf-8 -*-
"""Adversarial tests for the append-only log.

The point is not "does it produce 32 bytes". It is:
  - known-answer vectors computed independently (constants below were derived
    with plain hashlib, not with merkle.py)
  - tampering with a leaf, a proof element, an index, or a tree head must fail
  - a consistency proof must reject a second tree that is not an extension
"""
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari.merkle import (EMPTY_ROOT, consistency_proof, inclusion_proof,
                           leaf_hash, merkle_root, node_hash, root_from_data,
                           tree_head, verify_consistency, verify_inclusion)

# Independently derived with hashlib only:
#   empty  = SHA256("")
#   leaf   = SHA256(0x00 || data)
#   node   = SHA256(0x01 || left || right)
KAT = {
    "empty": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "leaf_a": "022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c",
    "root_ab": "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb",
    "root_abc": "36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1",
    "root_abcd": "33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0",
}


class TestKnownAnswers:
    def test_empty_root(self):
        assert EMPTY_ROOT.hex() == KAT["empty"]

    def test_single_leaf(self):
        assert leaf_hash(b"a").hex() == KAT["leaf_a"]

    def test_two_leaves(self):
        assert root_from_data([b"a", b"b"]).hex() == KAT["root_ab"]

    def test_three_leaves_odd_promotion(self):
        assert root_from_data([b"a", b"b", b"c"]).hex() == KAT["root_abc"]

    def test_four_leaves(self):
        assert root_from_data([b"a", b"b", b"c", b"d"]).hex() == KAT["root_abcd"]

    def test_domain_separation(self):
        """A leaf and a node must never collide even with the same 32-byte payload."""
        payload = b"\x11" * 32
        assert leaf_hash(payload) != node_hash(payload, payload)


class TestInclusion:
    @pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17])
    def test_every_leaf_verifies(self, n):
        data = [b"item-%d" % i for i in range(n)]
        leaves = [leaf_hash(d) for d in data]
        root = merkle_root(leaves)
        for i in range(n):
            proof = inclusion_proof(leaves, i)
            assert verify_inclusion(leaves[i], i, n, root, proof), (n, i)

    def test_wrong_index_fails(self):
        leaves = [leaf_hash(b"x%d" % i) for i in range(8)]
        root = merkle_root(leaves)
        proof = inclusion_proof(leaves, 2)
        assert not verify_inclusion(leaves[2], 3, 8, root, proof)

    def test_tampered_leaf_fails(self):
        leaves = [leaf_hash(b"x%d" % i) for i in range(8)]
        root = merkle_root(leaves)
        proof = inclusion_proof(leaves, 5)
        forged = leaf_hash(b"forged")
        assert not verify_inclusion(forged, 5, 8, root, proof)

    def test_tampered_proof_fails(self):
        leaves = [leaf_hash(b"x%d" % i) for i in range(8)]
        root = merkle_root(leaves)
        proof = list(inclusion_proof(leaves, 5))
        proof[0] = bytes([proof[0][0] ^ 0xFF]) + proof[0][1:]
        assert not verify_inclusion(leaves[5], 5, 8, root, proof)

    def test_truncated_proof_fails(self):
        leaves = [leaf_hash(b"x%d" % i) for i in range(8)]
        root = merkle_root(leaves)
        proof = inclusion_proof(leaves, 5)
        assert not verify_inclusion(leaves[5], 5, 8, root, proof[:-1])

    def test_size_larger_than_tree_fails(self):
        leaves = [leaf_hash(b"x%d" % i) for i in range(4)]
        root = merkle_root(leaves)
        proof = inclusion_proof(leaves, 0)
        assert not verify_inclusion(leaves[0], 0, 8, root, proof)


class TestConsistency:
    @pytest.mark.parametrize("total", [1, 2, 3, 4, 5, 8, 9, 16])
    def test_every_prefix_is_consistent(self, total):
        leaves = [leaf_hash(b"e%d" % i) for i in range(total)]
        for first in range(0, total + 1):
            proof = consistency_proof(leaves, first)
            assert verify_consistency(
                first, total, merkle_root(leaves[:first]), merkle_root(leaves),
                proof), (first, total)

    def test_rewritten_history_fails(self):
        """Same size, different content: must not be reported as consistent."""
        old = [leaf_hash(b"e%d" % i) for i in range(4)]
        new = [leaf_hash(b"e%d" % i) for i in range(3)] + [leaf_hash(b"EVIL")]
        proof = consistency_proof(new, 4)
        assert not verify_consistency(4, 4, merkle_root(old), merkle_root(new), proof)

    def test_shorter_second_tree_fails(self):
        leaves = [leaf_hash(b"e%d" % i) for i in range(8)]
        assert not verify_consistency(8, 4, merkle_root(leaves), merkle_root(leaves[:4]),
                                      consistency_proof(leaves[:4], 8) if False else [])

    def test_tampered_consistency_proof_fails(self):
        leaves = [leaf_hash(b"e%d" % i) for i in range(8)]
        proof = list(consistency_proof(leaves, 3))
        assert proof, "expected a non-empty proof"
        proof[-1] = bytes([proof[-1][0] ^ 0x01]) + proof[-1][1:]
        assert not verify_consistency(3, 8, merkle_root(leaves[:3]),
                                      merkle_root(leaves), proof)

    def test_empty_prefix_is_always_consistent(self):
        leaves = [leaf_hash(b"e%d" % i) for i in range(5)]
        assert verify_consistency(0, 5, EMPTY_ROOT, merkle_root(leaves), [])


class TestTreeHead:
    def test_head_shape(self):
        head = tree_head([b"a", b"b"])
        assert head["size"] == 2
        assert len(head["root"]) == 64
        int(head["root"], 16)

    def test_head_is_deterministic(self):
        assert tree_head([b"a", b"b"]) == tree_head([b"a", b"b"])

class TestPublishedVectors:
    """The published vector file must stay in sync with the implementation."""

    def test_vectors_pass_independent_verifier(self, tmp_path):
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        script = os.path.join(root, "docs", "spec", "verify_vectors.py")
        vectors = os.path.join(root, "docs", "spec", "merkle-vectors.json")
        assert os.path.isfile(script) and os.path.isfile(vectors)
        p = subprocess.run([sys.executable, script, vectors],
                           capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr
        assert "vectors passed" in p.stdout
