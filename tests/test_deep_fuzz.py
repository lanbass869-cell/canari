# -*- coding: utf-8 -*-
"""Deep property-based tests (hypothesis): cryptographic verifier, schema
validator, gate, guard parser and chain builder must never crash and must fail
closed on adversarial input."""
import base64
import json
import os
import string
import sys

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

V = "https://agentcheck.dev/attestation/v0.1"


def _signer():
    from canari.signing import generate_keypair
    return generate_keypair()


_PUB = {}


def _pub():
    if "k" not in _PUB:
        _PUB["k"] = _signer()
    return _PUB["k"]


def _att(payload_extra=None):
    att = {"_type": V,
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
    if payload_extra:
        att.update(payload_extra)
    return att


class TestSignatureFuzz:
    @settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(st.binary(min_size=0, max_size=400))
    def test_verify_never_raises_on_garbage(self, blob):
        from canari.signing import verify_signed
        signer, pub = _pub()
        env = {"payloadType": V, "payload": base64.b64encode(blob).decode(),
               "signatures": [{"keyid": "x", "sig": base64.b64encode(blob).decode()}]}
        ok, _, _ = verify_signed(env, pub.to_dict())
        assert ok is False

    @settings(max_examples=30, deadline=None)
    @given(st.text(min_size=0, max_size=200),
           st.text(min_size=0, max_size=200))
    def test_random_payloads_roundtrip(self, name, homepage):
        from canari.signing import sign_attestation, verify_signed
        signer, pub = _pub()
        att = _att({"subject": {"name": name or "x", "version": "1", "registry": "npm",
                                "artifact_sha256": "a" * 64, "maintainers": [],
                                "homepage": homepage}})
        signed = sign_attestation(att, signer)
        ok, payload, err = verify_signed(signed["envelope"], pub.to_dict())
        assert ok, err
        # signing NFC-normalises strings by design (D1): U+F900 -> U+8C48 etc.
        import unicodedata
        assert payload["subject"]["name"] == unicodedata.normalize("NFC", name or "x")
        assert payload["subject"]["homepage"] == unicodedata.normalize("NFC", homepage)

    @settings(max_examples=40, deadline=None)
    @given(st.binary(min_size=1, max_size=200))
    def test_mutation_always_rejected(self, noise):
        from canari.signing import sign_attestation, verify_signed
        signer, pub = _pub()
        signed = sign_attestation(_att(), signer)
        env = json.loads(json.dumps(signed["envelope"]))
        raw = base64.b64decode(env["payload"])
        pos = noise[0] % len(raw)
        mutated = raw[:pos] + bytes([raw[pos] ^ 0x01]) + raw[pos + 1:]
        env["payload"] = base64.b64encode(mutated).decode()
        ok, _, _ = verify_signed(env, pub.to_dict())
        assert ok is False


class TestGateFuzz:
    @settings(max_examples=40, deadline=None)
    @given(st.text(max_size=200))
    def test_gate_never_allows_garbage_file(self, text):
        import tempfile
        from canari.gate import evaluate_gate
        d = tempfile.mkdtemp()
        p = os.path.join(d, "b.json")
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        dec = evaluate_gate(p)
        assert dec.decision == "BLOCK"

    @settings(max_examples=30, deadline=None)
    @given(st.dictionaries(st.text(max_size=20), st.text(max_size=20), max_size=5))
    def test_gate_never_allows_json_without_envelope(self, blob):
        import tempfile
        from canari.gate import evaluate_gate
        d = tempfile.mkdtemp()
        p = os.path.join(d, "b.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(blob, f)
        assert evaluate_gate(p).decision == "BLOCK"


class TestGuardFuzz:
    @settings(max_examples=200, deadline=None)
    @given(st.lists(st.text(alphabet=string.printable, max_size=30), max_size=6))
    def test_parser_never_raises(self, tokens):
        from canari.guard import parse_install
        out = parse_install(tokens)
        assert isinstance(out, list)


class TestSchemaFuzz:
    @settings(max_examples=60, deadline=None)
    @given(st.dictionaries(st.text(max_size=12), st.one_of(st.text(max_size=30),
                                                           st.integers(), st.none(),
                                                           st.booleans(), st.lists(st.text(max_size=5), max_size=3)),
                           max_size=6))
    def test_validator_never_raises(self, blob):
        from canari.schema import validate_attestation
        errs = validate_attestation(blob)
        assert isinstance(errs, list)
