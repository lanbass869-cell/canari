# -*- coding: utf-8 -*-
"""Signing roundtrip + tamper detection (offline, no network)."""
import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canari.signing import generate_keypair, sign_attestation, verify_signed


@pytest.fixture(scope="module")
def keys():
    signer, pub = generate_keypair()
    return signer, pub


def _sample_att():
    return {
        "_type": "https://agentcheck.dev/attestation/v0.1",
        "subject": {"name": "test-mcp", "version": "1.0.0",
                    "registry": "npm", "artifact_sha256": "a" * 64},
        "host": {"class": "mcp", "host_version": "test-1"},
        "scenario_sha256": "b" * 64,
        "checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t/0.1"}],
        "verdict": "pass",
        "checker": {"kind": "automation", "id": "test"},
        "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
        "generated_at": "2026-11-08T00:00:00Z",
        "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                      "payload_type": "https://agentcheck.dev/attestation/v0.1"},
    }


def test_sign_verify_roundtrip(keys):
    signer, pub = keys
    att = _sample_att()
    signed = sign_attestation(att, signer)
    pub_dict = pub.to_dict()
    ok, payload, err = verify_signed(signed["envelope"], pub_dict)
    assert ok, err
    assert payload["subject"]["name"] == "test-mcp"


def test_tamper_detected(keys):
    signer, pub = keys
    att = _sample_att()
    signed = sign_attestation(att, signer)
    env = json.loads(json.dumps(signed["envelope"]))
    raw = base64.b64decode(env["payload"])
    raw = raw.replace(b"test-mcp", b"evil-mcp")
    env["payload"] = base64.b64encode(raw).decode("ascii")
    ok, payload, err = verify_signed(env, pub.to_dict())
    assert not ok
    assert err


def test_wrong_key_fails(keys):
    signer, _ = keys
    from securesystemslib.signer import CryptoSigner
    other = CryptoSigner.generate_ed25519()
    att = _sample_att()
    signed = sign_attestation(att, signer)
    ok, _, err = verify_signed(signed["envelope"], other.public_key.to_dict())
    assert not ok
    assert err

