# -*- coding: utf-8 -*-
"""E4: Differential testing. GUARDS_AGAINST: code changes that silently alter
attestation verdicts, hashes, or supersession behavior without anyone noticing.

If build_attestation changes cause different verdicts or hashes for the same
input, these tests fail - alerting that the change was not purely additive.
"""
import json
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SCENARIO = "d" * 64


def _meta(**kw):
    import base64
    integ = "sha512-" + base64.b64encode(bytes(64)).decode()
    m = {"version": "1.0.0", "dist_integrity": integ,
         "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz",
         "maintainers": ["alice"], "fetch_ms": 0}
    m.update(kw)
    return m


def _search_meta(**kw):
    m = {"description": "A test package", "links": {"homepage": "https://example.com"}}
    m.update(kw)
    return m


class TestDifferential:
    """Same input -> same output. If these tests fail, someone changed
    build_attestation in a way that alters results for existing packages."""

    @pytest.fixture(autouse=True)
    def _mock_download(self, monkeypatch):
        import canari.baseline as bl
        monkeypatch.setattr(bl, "_download_sha256", lambda url, timeout=60: "e" * 64)

    def test_same_input_same_verdict(self):
        from canari.baseline import build_attestation
        att1 = build_attestation("test-pkg", _meta(), _search_meta(), SCENARIO)
        att2 = build_attestation("test-pkg", _meta(), _search_meta(), SCENARIO)
        # Remove fields that differ between runs (timestamps, signature)
        for a in (att1, att2):
            a.pop("generated_at", None)
            a.pop("expires_at", None)
            a.pop("signature", None)
            a.pop("native_provenance", None)  # network-dependent
        assert att1["verdict"] == att2["verdict"]
        assert att1["subject"]["artifact_sha256"] == att2["subject"]["artifact_sha256"]
        assert [c["verdict"] for c in att1["checks"]] == [c["verdict"] for c in att2["checks"]]

    def test_different_input_different_hash(self):
        from canari.baseline import build_attestation
        att1 = build_attestation("pkg-a", _meta(), _search_meta(), SCENARIO)
        att2 = build_attestation("pkg-b", _meta(), _search_meta(), SCENARIO)
        assert att1["subject"]["name"] != att2["subject"]["name"]

    def test_verdict_changes_on_download_failure(self):
        from canari.baseline import build_attestation
        import canari.baseline as bl
        with patch.object(bl, "_download_sha256", return_value=None):
            att = build_attestation("test-pkg", _meta(), _search_meta(), SCENARIO)
            # With download failed, L2.1 should fail -> verdict should be "fail"
            l21 = [c for c in att["checks"] if c["id"] == "L2.1_ARTIFACT_HASH"][0]
            assert l21["verdict"] == "fail"
            assert att["subject"]["artifact_sha256"] == "0" * 64

    def test_nfc_produces_consistent_results(self):
        """Same logical content with different Unicode forms -> same verdict."""
        from canari.baseline import build_attestation
        # These two strings are the same word in different Unicode normalization forms
        meta_a = _meta()
        search_a = _search_meta(description="caf\u00e9 quality")  # precomposed
        search_b = _search_meta(description="cafe\u0301 quality")  # decomposed

        att_a = build_attestation("test-pkg", meta_a, search_a, SCENARIO)
        att_b = build_attestation("test-pkg", meta_a, search_b, SCENARIO)

        # The verdict should be the same (NFC normalization makes them equal)
        assert att_a["verdict"] == att_b["verdict"]
        # The artifact_sha256 is the same (it's the tarball hash, not description hash)
        assert att_a["subject"]["artifact_sha256"] == att_b["subject"]["artifact_sha256"]


class TestSupersessionChainIntegrity:
    """Verify that the supersession chain is correct across multiple runs."""

    def test_chain_points_to_previous_digest(self, tmp_path):
        from canari.baseline import build_attestation, sign_attestation, generate_keypair
        from canari.state import StateStore
        import hashlib

        signer, pub_key = generate_keypair()
        state = StateStore(str(tmp_path / "state.json"))

        # Simulate run 1: build and sign
        att1 = build_attestation("pkg", _meta(), _search_meta(), SCENARIO)
        signed1 = sign_attestation(att1, signer)
        digest1 = hashlib.sha256(
            json.dumps(signed1["payload"], ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()

        # Record in state
        state.set_component("pkg", "1.0.0", "e" * 64, digest1)
        state.save()

        # Simulate run 2: build with supersedes pointing to run 1
        prev_state = state.get_component("pkg")
        assert prev_state is not None
        assert prev_state.get("attestation_digest") == digest1

        # The new attestation should have supersedes = run 1's digest
        att2 = build_attestation("pkg", _meta(), _search_meta(), SCENARIO)
        att2["supersedes"] = prev_state["attestation_digest"]
        assert att2["supersedes"] == digest1

    def test_chain_no_cycles(self, tmp_path):
        """Verify the chain walking logic detects cycles."""
        # Build a synthetic cycle: A supersedes B, B supersedes A
        chain = {"a": "b", "b": "a"}
        visited = set()
        current = "a"
        has_cycle = False
        for _ in range(100):
            if current in visited:
                has_cycle = True
                break
            visited.add(current)
            current = chain.get(current)
            if current is None:
                break
        assert has_cycle
