# -*- coding: utf-8 -*-
"""T2: native provenance ingestion tests.

Live-network tests: express@5.3.0 is pinned (a stable, high-profile package
whose provenance has been verified in this round's research).
Offline tests use the recorded bundle structure (no network).
"""

# GUARDS_AGAINST: false signing claim (v0.1 publicKey-hint bundles treated as verified), credential leakage into attestation payload
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canari.native import _classify_entries, verify_v1_cert, ingest, fetch_attestations
from canari.schema import validate_attestation


# -- offline: classification logic --

class TestClassify:
    def test_empty_no_attestations(self):
        r = _classify_entries([])
        assert r["present"] is False
        assert r["v1_cert_entries"] == []
        assert r["v0_key_entries"] == []

    def test_v1_certificate_detected(self):
        entries = [{"predicateType": "https://slsa.dev/provenance/v1",
                     "bundle": {"verificationMaterial": {"certificate": "cert", "tlogEntries": []}}}]
        r = _classify_entries(entries)
        assert r["present"] is True
        assert len(r["v1_cert_entries"]) == 1
        assert "v1" in r["predicate_types"]

    def test_v0_publickey_detected(self):
        entries = [{"predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
                     "bundle": {"verificationMaterial": {"publicKey": {"hint": "sha256:..."}, "tlogEntries": []}}}]
        r = _classify_entries(entries)
        assert r["present"] is True
        assert len(r["v0_key_entries"]) == 1
        assert "v0.1" in r["predicate_types"]

    def test_mixed_entries(self):
        entries = [
            {"predicateType": ".../publish/v0.1", "bundle": {"verificationMaterial": {"publicKey": {"hint": "x"}, "tlogEntries": []}}},
            {"predicateType": ".../provenance/v1", "bundle": {"verificationMaterial": {"certificate": "c", "tlogEntries": []}}},
        ]
        r = _classify_entries(entries)
        assert len(r["v1_cert_entries"]) == 1
        assert len(r["v0_key_entries"]) == 1
        assert r["predicate_types"] == ["v0.1", "v1"]


# -- offline: schema accepts native_provenance --

class TestSchemaNative:
    def _valid_att(self):
        return {
            "_type": "https://agentcheck.dev/attestation/v0.1",
            "subject": {"name": "x", "version": "1.0", "registry": "npm",
                        "artifact_sha256": "a" * 64},
            "host": {"class": "mcp", "host_version": "h1"},
            "scenario_sha256": "b" * 64,
            "checks": [{"id": "L1.1_X", "verdict": "pass", "tool": "t"}],
            "verdict": "pass",
            "checker": {"kind": "automation", "id": "c1"},
            "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
            "generated_at": "2026-11-08T00:00:00Z",
            "signature": {"envelope": "DSSE", "keyid": "k", "sig": "s",
                          "payload_type": "https://agentcheck.dev/attestation/v0.1"},
        }

    def test_native_provenance_ok(self):
        att = self._valid_att()
        att["native_provenance"] = {"present": True, "v1_verified": True,
                                     "predicate_types": ["v1"], "verifier": "sigstore-python/4.5.1"}
        assert validate_attestation(att) == []

    def test_native_provenance_absent_ok(self):
        assert validate_attestation(self._valid_att()) == []

    def test_native_provenance_missing_present_field(self):
        att = self._valid_att()
        att["native_provenance"] = {"v1_verified": True}
        errs = validate_attestation(att)
        assert any("present" in e for e in errs)


# -- live network: express@5.3.0 real verification --

HAS_SIGSTORE = True
try:
    import sigstore  # noqa
except ImportError:
    HAS_SIGSTORE = False


@pytest.mark.skipif(not HAS_SIGSTORE, reason="sigstore-python not installed")
class TestLiveExpress:
    """Live npm-registry tests.

    These hit the network. A failed FETCH is not a product defect - it means the
    link is down, so the tests skip rather than fail. Without this, a routine
    network hiccup failed the whole suite and looked like a code regression
    (observed 2026-11-13: 'NoneType object is not subscriptable').
    """

    @staticmethod
    def _fetch():
        raw = fetch_attestations("express", "5.3.0")
        if raw is None:
            pytest.skip("npm registry unreachable or returned no attestations")
        return raw

    def test_fetch_returns_bundle(self):
        raw = self._fetch()
        assert "attestations" in raw
        assert len(raw["attestations"]) >= 1

    def test_classify_express(self):
        raw = self._fetch()
        cls = _classify_entries(raw["attestations"])
        assert cls["present"] is True
        assert len(cls["v1_cert_entries"]) >= 1

    def test_verify_v1_crypto_passes(self):
        """The core T2 acceptance: sigstore DSSE verification of a real npm provenance bundle."""
        raw = self._fetch()
        cls = _classify_entries(raw["attestations"])
        if not cls["v1_cert_entries"]:
            pytest.skip("no v1 provenance entry in the live bundle")
        r = verify_v1_cert(cls["v1_cert_entries"][0])
        assert r["ok"] is True, "expected v1 verification to pass, got: %s" % r.get("error")
        assert r["identity"] is not None
        assert "expressjs" in r["identity"]

    def test_ingest_full_flow(self):
        np = ingest("express", "5.3.0")
        if np is None:
            pytest.skip("npm registry unreachable")
        assert np["present"] is True
        assert np["v1_verified"] is True
        assert np["v0_presence_only"] >= 1

    def test_ingest_no_attestation_returns_none(self):
        # a package that almost certainly has no provenance
        np = ingest("left-pad", "1.3.0")
        assert np is None
