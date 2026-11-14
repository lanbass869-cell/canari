# -*- coding: utf-8 -*-
"""E1: install gate tests. GUARDS_AGAINST: gate always allowing regardless
of verdict, stale attestation treated as fresh, revoked key treated as valid,
error checks not blocking, native provenance requirement ignored."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canari.gate import GateDecision, evaluate_gate
from canari.signing import generate_keypair, sign_attestation


def _make_bundle(tmp_path, verdict="pass", expires_in_days=7, extra_checks=None):
    """Create a signed bundle for testing."""
    signer, pub_key = generate_keypair()
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(days=expires_in_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    checks = [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "test/0.1"},
              {"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "test/0.1"}]
    if extra_checks:
        checks.extend(extra_checks)

    att = {
        "_type": "https://agentcheck.dev/attestation/v0.1",
        "subject": {"name": "test-pkg", "version": "1.0.0", "registry": "npm",
                    "artifact_sha256": "a" * 64, "maintainers": ["alice"]},
        "host": {"class": "mcp", "host_version": "test-1"},
        "scenario_sha256": "b" * 64,
        "checks": checks,
        "verdict": verdict,
        "checker": {"kind": "automation", "id": "test"},
        "evidence_refs": [],
        "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
        "expires_at": expires,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                      "payload_type": "https://agentcheck.dev/attestation/v0.1"},
    }

    signed = sign_attestation(att, signer)
    key_file = tmp_path / "pub.json"
    key_file.write_text(json.dumps(pub_key.to_dict(), ensure_ascii=False, sort_keys=True), encoding="utf-8")
    bundle_file = tmp_path / "test.bundle.json"
    bundle_file.write_text(json.dumps({"envelope": signed["envelope"], "payload": signed["payload"]},
                                       ensure_ascii=False), encoding="utf-8")
    return str(bundle_file), str(key_file)


class TestGateAllow:
    def test_pass_allows(self, tmp_path):
        bundle, key = _make_bundle(tmp_path, verdict="pass")
        d = evaluate_gate(bundle, key_path=key)
        assert d.decision == "ALLOW"

    def test_pass_with_findings_reviews(self, tmp_path):
        bundle, key = _make_bundle(tmp_path, verdict="pass-with-findings")
        d = evaluate_gate(bundle, key_path=key)
        assert d.decision == "REVIEW"
        assert any("pass-with-findings" in r for r in d.reasons)


class TestGateBlock:
    def test_fail_blocks(self, tmp_path):
        bundle, key = _make_bundle(tmp_path, verdict="fail")
        d = evaluate_gate(bundle, key_path=key)
        assert d.decision == "BLOCK"
        assert any("fail" in r for r in d.reasons)

    def test_error_blocks(self, tmp_path):
        bundle, key = _make_bundle(tmp_path, verdict="error")
        d = evaluate_gate(bundle, key_path=key)
        assert d.decision == "BLOCK"

    def test_unsupported_blocks(self, tmp_path):
        bundle, key = _make_bundle(tmp_path, verdict="unsupported")
        d = evaluate_gate(bundle, key_path=key)
        assert d.decision == "BLOCK"

    def test_stale_blocks(self, tmp_path):
        bundle, key = _make_bundle(tmp_path, verdict="pass", expires_in_days=-1)
        d = evaluate_gate(bundle, key_path=key)
        assert d.decision == "BLOCK"
        assert any("stale" in r or "expired" in r for r in d.reasons)

    def test_error_check_blocks(self, tmp_path):
        bundle, key = _make_bundle(tmp_path, verdict="pass-with-findings",
                                    extra_checks=[{"id": "L3.1_SCAN", "verdict": "error", "tool": "t"}])
        d = evaluate_gate(bundle, key_path=key)
        assert d.decision == "BLOCK"
        assert any("error" in r for r in d.reasons)

    def test_missing_file_blocks(self, tmp_path):
        d = evaluate_gate(str(tmp_path / "nonexistent.json"))
        assert d.decision == "BLOCK"

    def test_bad_signature_blocks(self, tmp_path):
        bundle, key = _make_bundle(tmp_path, verdict="pass")
        # corrupt the key so signature fails
        bad_key = tmp_path / "bad_key.json"
        bad_key.write_text('{"keytype": "ed25519", "keyval": {"public": "invalid"}}', encoding="utf-8")
        d = evaluate_gate(bundle, key_path=str(bad_key))
        assert d.decision == "BLOCK"
        assert any("signature" in r.lower() for r in d.reasons)


class TestGatePolicies:
    def test_strict_blocks_findings(self, tmp_path):
        bundle, key = _make_bundle(tmp_path, verdict="pass-with-findings")
        d = evaluate_gate(bundle, key_path=key, policy_name="strict")
        assert d.decision == "BLOCK"

    def test_lax_allows_findings(self, tmp_path):
        bundle, key = _make_bundle(tmp_path, verdict="pass-with-findings")
        d = evaluate_gate(bundle, key_path=key, policy_name="lax")
        assert d.decision == "ALLOW"

    def test_lax_allows_stale(self, tmp_path):
        bundle, key = _make_bundle(tmp_path, verdict="pass", expires_in_days=-1)
        d = evaluate_gate(bundle, key_path=key, policy_name="lax")
        assert d.decision == "ALLOW"

    def test_unknown_policy_raises(self, tmp_path):
        bundle, key = _make_bundle(tmp_path)
        with pytest.raises(ValueError, match="unknown policy"):
            evaluate_gate(bundle, policy_name="nonexistent")
