# -*- coding: utf-8 -*-
"""BUG-102 regression: the install gate must judge the SIGNED payload.

A bundle file stores the attestation twice:
  envelope.payload (base64, DSSE-signed)  <- the only trustworthy copy
  payload          (plain dict, convenience mirror, NOT signed)

Before the fix the gate verified the envelope but decided on the mirror, so
editing the mirror to "pass" yielded ALLOW with signature_ok=true: a complete
signature bypass. These tests lock the fail-closed behaviour in place.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari.gate import evaluate_gate
from canari.signing import (read_signed_payload, check_payload_integrity,
                            generate_keypair, sign_attestation, export_public_key)


def _attestation(verdict="unsupported", name="pkg-a"):
    return {
        "_type": "https://agentcheck.dev/attestation/v0.1",
        "subject": {"name": name, "version": "1.0.0", "registry": "npm",
                    "artifact_sha256": "0" * 64, "maintainers": []},
        "host": {"class": "mcp", "host_version": "t"},
        "scenario_sha256": "a" * 64,
        "checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t"}],
        "verdict": verdict,
        "checker": {"kind": "automation", "id": "t"},
        "evidence_refs": [],
        "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                  "truncated_fields": []},
        "expires_at": "2027-01-01T00:00:00Z",
        "generated_at": "2026-11-11T00:00:00Z",
        "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": ""},
    }


def _signed_bundle(tmp_path, verdict="unsupported", name="pkg-a"):
    signer, pub = generate_keypair()
    signed = sign_attestation(_attestation(verdict, name), signer)
    bundle = {"envelope": signed["envelope"], "payload": signed["payload"]}
    bp = tmp_path / ("%s.bundle.json" % name)
    bp.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
    kp = tmp_path / "pub.json"
    kp.write_text(export_public_key(pub), encoding="utf-8")
    return bp, kp, bundle


class TestSignedPayloadIsSourceOfTruth:
    def test_read_signed_payload_matches_envelope(self, tmp_path):
        _, _, bundle = _signed_bundle(tmp_path)
        payload, err = read_signed_payload(bundle)
        assert err is None
        assert payload is not None
        assert payload["verdict"] == "unsupported"

    def test_integrity_ok_for_untampered_bundle(self, tmp_path):
        _, _, bundle = _signed_bundle(tmp_path)
        ok, reason, payload = check_payload_integrity(bundle)
        assert ok is True, reason
        assert payload["verdict"] == "unsupported"

    def test_gate_allows_untampered_pass(self, tmp_path):
        bp, kp, _ = _signed_bundle(tmp_path, verdict="pass", name="ok-pkg")
        dec = evaluate_gate(str(bp), key_path=str(kp), policy_name="lax")
        assert dec.decision == "ALLOW", dec.reasons

    def test_gate_blocks_untampered_unsupported(self, tmp_path):
        bp, kp, _ = _signed_bundle(tmp_path, verdict="unsupported", name="u-pkg")
        dec = evaluate_gate(str(bp), key_path=str(kp), policy_name="lax")
        assert dec.decision == "BLOCK", dec.reasons

    def test_tampered_mirror_cannot_become_pass(self, tmp_path):
        """The actual bypass: flip the unsigned mirror to pass, keep the
        envelope untouched. Signature still verifies - but the gate must BLOCK."""
        bp, kp, bundle = _signed_bundle(tmp_path, verdict="unsupported", name="evil")
        bundle["payload"]["verdict"] = "pass"
        bundle["payload"]["checks"] = [
            {"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t"}]
        bp.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")

        dec = evaluate_gate(str(bp), key_path=str(kp), policy_name="lax")
        assert dec.decision == "BLOCK"
        assert any("integrity" in r.lower() or "signed payload" in r.lower()
                   for r in dec.reasons), dec.reasons
        assert dec.verdict == "unsupported"

    def test_tampered_mirror_detected_even_without_key(self, tmp_path):
        bp, kp, bundle = _signed_bundle(tmp_path, verdict="unsupported", name="evil2")
        bundle["payload"]["verdict"] = "pass"
        bp.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
        dec = evaluate_gate(str(bp), key_path=None, policy_name="lax")
        assert dec.decision == "BLOCK"
        assert dec.verdict == "unsupported"

    def test_tampering_subject_is_detected(self, tmp_path):
        bp, kp, bundle = _signed_bundle(tmp_path, verdict="pass", name="real")
        bundle["payload"]["subject"]["name"] = "other-package"
        bp.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
        dec = evaluate_gate(str(bp), key_path=str(kp), policy_name="lax")
        assert dec.decision == "BLOCK"
        assert any("subject" in r for r in dec.reasons), dec.reasons

    def test_tampering_checks_is_detected(self, tmp_path):
        bp, kp, bundle = _signed_bundle(tmp_path, verdict="unsupported", name="c-pkg")
        # add a fabricated extra passing check to the unsigned mirror
        bundle["payload"]["checks"] = bundle["payload"]["checks"] + [
            {"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "forged"}]
        bp.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
        dec = evaluate_gate(str(bp), key_path=str(kp), policy_name="lax")
        assert dec.decision == "BLOCK"
        assert any("checks" in r for r in dec.reasons), dec.reasons

    def test_missing_envelope_fails_closed(self, tmp_path):
        signer, pub = generate_keypair()
        signed = sign_attestation(_attestation("pass", "no-env"), signer)
        bundle = {"payload": signed["payload"]}
        bp = tmp_path / "noenv.bundle.json"
        bp.write_text(json.dumps(bundle), encoding="utf-8")
        dec = evaluate_gate(str(bp), key_path=None, policy_name="lax")
        assert dec.decision == "BLOCK"

    def test_consumer_lists_signed_verdict_not_mirror(self, tmp_path):
        from canari.consumer import list_components
        store = tmp_path / "store"
        (store / "attestations").mkdir(parents=True)
        signer, pub = generate_keypair()
        signed = sign_attestation(_attestation("unsupported", "mirror-pkg"), signer)
        bundle = {"envelope": signed["envelope"], "payload": signed["payload"]}
        bundle["payload"]["verdict"] = "pass"
        (store / "attestations" / "x.bundle.json").write_text(
            json.dumps(bundle), encoding="utf-8")
        comps = list_components(str(store))
        assert len(comps) == 1
        assert comps[0]["verdict"] == "unsupported"





class TestVerifyCliMirrorCheck:
    """canari-verify must also flag a tampered UNSIGNED mirror."""

    def _write(self, tmp_path, tamper):
        signer, pub = generate_keypair()
        signed = sign_attestation(_attestation("unsupported", "vc-pkg"), signer)
        bundle = {"envelope": signed["envelope"], "payload": signed["payload"]}
        if tamper:
            bundle["payload"]["verdict"] = "pass"
        bp = tmp_path / "vc.bundle.json"
        bp.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
        kp = tmp_path / "pub.json"
        kp.write_text(export_public_key(pub), encoding="utf-8")
        return bp, kp

    def test_verify_passes_untampered(self, tmp_path, capsys):
        from canari.verify_cli import main
        bp, kp = self._write(tmp_path, tamper=False)
        rc = main([str(bp), "--key", str(kp)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "payload mirror: PASS" in out

    def test_verify_fails_on_tampered_mirror(self, tmp_path, capsys):
        from canari.verify_cli import main
        bp, kp = self._write(tmp_path, tamper=True)
        rc = main([str(bp), "--key", str(kp)])
        out = capsys.readouterr().out
        assert rc == 1
        assert "payload mirror: FAIL" in out
