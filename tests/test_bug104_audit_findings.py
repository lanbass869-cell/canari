# -*- coding: utf-8 -*-
"""BUG-104: regressions for the 2026-11-11 adversarial audit (F1-F11).

Two independent auditors were asked to break the BUG-102 signature fix. They
found it incomplete: a "no envelope -> fall back to the unsigned mirror" branch
re-opened the bypass in the default (no --key) gate, and `canari-verify --chain`
still read the unsigned copy. This file locks those closed.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari.gate import evaluate_gate
from canari.signing import (generate_keypair, sign_attestation,
                            export_public_key, read_signed_payload)


def _att(verdict="unsupported", name="pkg", expires="2027-01-01T00:00:00Z",
         finding=False, registry="npm"):
    checks = [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t"}]
    if finding:
        checks.append({"id": "L2.4_CADENCE", "verdict": "pass", "tool": "t",
                       "evidence_ref": "finding: odd cadence"})
    a = {"_type": "https://agentcheck.dev/attestation/v0.1",
         "subject": {"name": name, "version": "1.0.0", "registry": registry,
                     "artifact_sha256": "0" * 64, "maintainers": []},
         "host": {"class": "mcp", "host_version": "t"},
         "scenario_sha256": "a" * 64, "checks": checks, "verdict": verdict,
         "checker": {"kind": "automation", "id": "t"}, "evidence_refs": [],
         "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                   "truncated_fields": []},
         "generated_at": "2026-11-11T00:00:00Z",
         "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                       "payload_type": ""}}
    if expires:
        a["expires_at"] = expires
    return a


def _bundle(tmp_path, **kw):
    signer, pub = generate_keypair()
    s = sign_attestation(_att(**kw), signer)
    bp = tmp_path / "b.bundle.json"
    bp.write_text(json.dumps({"envelope": s["envelope"], "payload": s["payload"]}),
                  encoding="utf-8")
    kp = tmp_path / "k.json"
    kp.write_text(export_public_key(pub), encoding="utf-8")
    return bp, kp


class TestF1NoFallback:
    def test_missing_envelope_payload_is_an_error(self, tmp_path):
        bp, _ = _bundle(tmp_path)
        b = json.loads(bp.read_text(encoding="utf-8"))
        del b["envelope"]["payload"]
        payload, err = read_signed_payload(b)
        assert payload is None and err

    def test_empty_envelope_payload_is_an_error(self, tmp_path):
        bp, _ = _bundle(tmp_path)
        b = json.loads(bp.read_text(encoding="utf-8"))
        b["envelope"]["payload"] = ""
        payload, err = read_signed_payload(b)
        assert payload is None and err

    def test_non_dict_envelope_is_an_error(self, tmp_path):
        bp, _ = _bundle(tmp_path)
        b = json.loads(bp.read_text(encoding="utf-8"))
        b["envelope"] = "x"
        payload, err = read_signed_payload(b)
        assert payload is None and err

    def test_no_key_gate_blocks_on_removed_envelope_payload(self, tmp_path):
        bp, _ = _bundle(tmp_path, verdict="unsupported", name="inv")
        b = json.loads(bp.read_text(encoding="utf-8"))
        b["payload"]["verdict"] = "pass"
        del b["envelope"]["payload"]
        bp.write_text(json.dumps(b), encoding="utf-8")
        dec = evaluate_gate(str(bp), key_path=None, policy_name="lax")
        assert dec.decision == "BLOCK"

    def test_non_dict_signed_payload_is_an_error(self, tmp_path):
        import base64
        bp, _ = _bundle(tmp_path)
        b = json.loads(bp.read_text(encoding="utf-8"))
        b["envelope"]["payload"] = base64.b64encode(b"[1,2,3]").decode()
        payload, err = read_signed_payload(b)
        assert payload is None and "not a JSON object" in err


class TestF3ChainUsesSignedPayload:
    def test_dangling_signed_supersedes_cannot_be_hidden_by_the_mirror(self, tmp_path):
        """The audited exploit: a SIGNED supersedes pointer to a missing digest
        made the chain fail (rc 4), but editing only the UNSIGNED mirror to
        supersedes=null turned the audit green (rc 0). The chain must be built
        from the signed payload, so the mirror edit has no effect."""
        from canari.verify_cli import verify_chain

        signer, pub = generate_keypair()
        att = _att(verdict="pass", name="chainpkg")
        att["supersedes"] = "f" * 64            # signed, dangling
        s = sign_attestation(att, signer)
        d = tmp_path / "attestations"
        d.mkdir()
        # (a) untouched: signed dangling pointer must FAIL
        (d / "a.bundle.json").write_text(
            json.dumps({"envelope": s["envelope"], "payload": s["payload"]}),
            encoding="utf-8")
        assert verify_chain(str(d)) == 4

        # (b) same file, mirror edited: must STILL fail
        b = json.loads((d / "a.bundle.json").read_text(encoding="utf-8"))
        b["payload"]["supersedes"] = None
        (d / "a.bundle.json").write_text(json.dumps(b), encoding="utf-8")
        assert verify_chain(str(d)) == 4

    def test_chain_rejects_unsigned_file(self, tmp_path):
        from canari.verify_cli import verify_chain
        att = tmp_path / "attestations"
        att.mkdir()
        (att / "fake.bundle.json").write_text(json.dumps({
            "payload": {"subject": {"name": "x", "version": "1",
                                    "registry": "npm"}, "verdict": "pass"}}),
            encoding="utf-8")
        assert verify_chain(str(att)) != 0


class TestF2UnsignedNeverPublished:
    def test_feed_skips_unsigned_file(self, tmp_path):
        from canari.feed import build_feed
        att = tmp_path / "attestations"
        att.mkdir()
        bp, _ = _bundle(tmp_path, verdict="pass", name="real")
        (att / "real.bundle.json").write_text(bp.read_text(encoding="utf-8"),
                                              encoding="utf-8")
        (att / "evil.bundle.json").write_text(json.dumps({
            "payload": {"subject": {"name": "evil", "version": "9",
                                    "registry": "npm",
                                    "artifact_sha256": "0" * 64},
                        "verdict": "pass",
                        "generated_at": "2026-11-11T00:00:00Z",
                        "checks": []}}), encoding="utf-8")
        names = [i["name"] for i in build_feed(str(tmp_path))["items"]]
        assert "real" in names
        assert "evil" not in names

    def test_consumer_skips_unsigned_file(self, tmp_path):
        from canari.consumer import list_components
        att = tmp_path / "attestations"
        att.mkdir()
        bp, _ = _bundle(tmp_path, verdict="pass", name="real")
        (att / "real.bundle.json").write_text(bp.read_text(encoding="utf-8"),
                                              encoding="utf-8")
        (att / "evil.bundle.json").write_text(json.dumps({
            "payload": {"subject": {"name": "evil", "version": "9",
                                    "registry": "npm",
                                    "artifact_sha256": "0" * 64},
                        "verdict": "pass",
                        "generated_at": "2026-11-11T00:00:00Z",
                        "checks": []}}), encoding="utf-8")
        names = [c["name"] for c in list_components(str(tmp_path))]
        assert "evil" not in names


class TestF4NoCrossRegistryFallback:
    def test_dsh_lookup_does_not_borrow_npm_verdict(self, tmp_path):
        from canari.guard import _lookup
        att = tmp_path / "attestations"
        att.mkdir()
        bp, _ = _bundle(tmp_path, verdict="pass", name="purge")
        (att / "npm.bundle.json").write_text(bp.read_text(encoding="utf-8"),
                                             encoding="utf-8")
        r = _lookup(str(tmp_path), "dsh-registry", "purge", None, None)
        assert r["decision"] == "BLOCK"
        assert not r["found"]


class TestF5ScannerNoEvidence:
    def test_missing_summary_is_unsupported(self):
        from canari.scanner_adapter import findings_to_checks
        _, v = findings_to_checks({})
        assert v == "unsupported"

    def test_zero_scanners_is_unsupported(self):
        from canari.scanner_adapter import findings_to_checks
        _, v = findings_to_checks({"summary": {"total": 0},
                                   "scanner_count": 0, "exit_code": 0})
        assert v == "unsupported"

    def test_clean_scan_still_passes(self):
        from canari.scanner_adapter import findings_to_checks
        _, v = findings_to_checks({"summary": {"total": 0},
                                   "scanner_count": 5, "exit_code": 0})
        assert v == "pass"

    def test_critical_still_fails(self):
        from canari.scanner_adapter import findings_to_checks
        _, v = findings_to_checks({"summary": {"total": 1, "critical": 1},
                                   "scanner_count": 3, "exit_code": 0})
        assert v == "fail"


class TestF6UnverifiedNeedsReason:
    def test_unsupported_without_evidence_is_reported(self):
        from canari.schema import unverified_without_reason
        att = {"checks": [{"id": "X", "verdict": "unsupported", "tool": "t"}]}
        assert unverified_without_reason(att) == ["X"]

    def test_unsupported_with_evidence_is_clean(self):
        from canari.schema import unverified_without_reason
        att = {"checks": [{"id": "X", "verdict": "unsupported", "tool": "t",
                           "evidence_ref": "no data"}]}
        assert unverified_without_reason(att) == []


class TestPolicyLayerF7ToF11:
    def test_f7_custom_policy_keeps_findings_review(self, tmp_path):
        bp, kp = _bundle(tmp_path, verdict="pass-with-findings", finding=True)
        pf = tmp_path / "p.json"
        pf.write_text(json.dumps({"name": "corp"}), encoding="utf-8")
        dec = evaluate_gate(str(bp), key_path=str(kp), policy_file=str(pf))
        assert dec.decision == "REVIEW"

    def test_f8_string_bool_override_is_rejected(self, tmp_path):
        bp, kp = _bundle(tmp_path, verdict="pass-with-findings", finding=True)
        with pytest.raises(ValueError):
            evaluate_gate(str(bp), key_path=str(kp), policy_name="strict",
                          policy_overrides={"allow_findings": "false"})

    def test_f10_missing_expiry_is_not_fresh(self, tmp_path):
        bp, kp = _bundle(tmp_path, verdict="pass", expires=None)
        dec = evaluate_gate(str(bp), key_path=str(kp), policy_name="strict")
        assert dec.decision == "BLOCK"

    def test_f11_fresh_is_reported(self, tmp_path):
        bp, kp = _bundle(tmp_path, verdict="pass",
                         expires="2020-01-01T00:00:00Z")
        dec = evaluate_gate(str(bp), key_path=str(kp), policy_name="strict")
        assert dec.decision == "BLOCK"
        assert dec.fresh is False

    def test_f9_min_verdict_is_gone(self):
        from canari.gate import GatePolicy
        assert not hasattr(GatePolicy(), "min_verdict")

