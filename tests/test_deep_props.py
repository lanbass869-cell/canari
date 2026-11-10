# -*- coding: utf-8 -*-
"""Deep property tests #2: signature determinism and non-canonical payloads."""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
V = "https://agentcheck.dev/attestation/v0.1"


def _att():
    return {"_type": V,
            "subject": {"name": "t", "version": "1", "registry": "npm",
                        "artifact_sha256": "a" * 64, "maintainers": []},
            "host": {"class": "mcp", "host_version": "t"},
            "scenario_sha256": "b" * 64,
            "checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t/0.1"}],
            "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
            "evidence_refs": [],
            "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                      "truncated_fields": []},
            "expires_at": "2026-12-30T00:00:00Z", "generated_at": "2026-11-10T00:00:00Z",
            "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": V}}


class TestDeterminism:
    def test_same_input_same_bytes(self):
        """Canonical serialisation: the same attestation must produce identical
        signed bytes on every run (otherwise the digest/chain model breaks)."""
        from canari.signing import generate_keypair, sign_attestation
        signer, _ = generate_keypair()
        a = sign_attestation(_att(), signer)
        b = sign_attestation(_att(), signer)
        assert a["envelope"]["payload"] == b["envelope"]["payload"]

    def test_payload_is_sorted_key_json(self):
        from canari.signing import generate_keypair, sign_attestation
        signer, _ = generate_keypair()
        signed = sign_attestation(_att(), signer)
        raw = base64.b64decode(signed["envelope"]["payload"]).decode()
        parsed = json.loads(raw)
        canonical = json.dumps(parsed, ensure_ascii=False, sort_keys=True)
        assert raw == canonical


class TestNonCanonicalPayload:
    def test_independent_check_rejects_noncanonical_bytes(self):
        """A validly-signed payload that was NOT canonically serialised must be
        flagged by the independent canonicalisation check."""
        import base64 as b64
        from canari.signing import generate_keypair, DSSE_PAYLOAD_TYPE
        from canari.verify_cli import _independent_pae, _independent_verify

        signer, pub = generate_keypair()
        payload = _att()
        noncanon = json.dumps(payload, ensure_ascii=False, sort_keys=False).encode()
        pae = _independent_pae(DSSE_PAYLOAD_TYPE, noncanon)
        sig = signer.sign(pae)
        env = {"payloadType": DSSE_PAYLOAD_TYPE,
               "payload": b64.b64encode(noncanon).decode(),
               "signatures": [{"keyid": sig.keyid,
                               "sig": sig.signature if isinstance(sig.signature, str)
                                      else b64.b64encode(sig.signature).decode()}]}
        ok, detail = _independent_verify(env, pub.to_dict())
        assert ok is False
        assert "canonical" in detail.lower()
