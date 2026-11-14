# -*- coding: utf-8 -*-
"""End-to-end verify CLI test: sign -> write bundle -> verify -> tamper -> fail.

Also covers the M0 acceptance criterion shape: a bundle produced by this
project is verified by the CLI (self-test); the "verified by a non-self
party" criterion is the operator step documented in README.
"""

# GUARDS_AGAINST: silent verification bypass (tampered bundle, invalid schema, missing file), independent PAE cross-check
import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canari.signing import generate_keypair, sign_attestation
from canari.verify_cli import verify_bundle


@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    signer, pub = generate_keypair()
    d = tmp_path_factory.mktemp("kp")
    key_path = d / "pub.json"
    key_path.write_text(json.dumps(pub.to_dict(), ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return signer, str(key_path)


def _att():
    return {
        "_type": "https://agentcheck.dev/attestation/v0.1",
        "subject": {"name": "demo-mcp", "version": "0.1.0", "registry": "npm",
                    "artifact_sha256": "a" * 64, "maintainers": ["bob"]},
        "host": {"class": "mcp", "host_version": "registry-meta-v1"},
        "scenario_sha256": "b" * 64,
        "checks": [
            {"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "canari-meta/0.1", "duration_ms": 12},
            {"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "canari-meta/0.1",
             "evidence_ref": "npm-tarball:demo-mcp"},
            {"id": "L2.5_METADATA_ANOMALY", "verdict": "unsupported", "tool": "canari-meta/0.1",
             "evidence_ref": "not downloaded"},
        ],
        "verdict": "pass-with-findings",
        "checker": {"kind": "automation", "id": "canari-m0", "tools": ["canari-meta/0.1"]},
        "evidence_refs": ["npm-packument:demo-mcp"],
        "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
        "expires_at": "2026-11-15T00:00:00Z",
        "generated_at": "2026-11-08T00:00:00Z",
        "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                      "payload_type": "https://agentcheck.dev/attestation/v0.1"},
    }


def _write_bundle(tmp_path, signer, att=None, name="demo.bundle.json"):
    att = att or _att()
    signed = sign_attestation(att, signer)
    p = tmp_path / name
    p.write_text(json.dumps({"envelope": signed["envelope"], "payload": signed["payload"]},
                            ensure_ascii=False, indent=1), encoding="utf-8")
    return str(p)


def test_clean_bundle_verifies(keypair, tmp_path, capsys):
    signer, key_path = keypair
    bundle = _write_bundle(tmp_path, signer)
    rc = verify_bundle(bundle, key_path)
    out = capsys.readouterr()
    assert rc == 0, out.err
    assert "signature (in-toto): PASS" in out.out
    assert "schema:    PASS" in out.out
    assert "UNSUP" in out.out  # the unsupported check is visible, not hidden
    assert "ALLOW" in out.out


def test_tampered_bundle_fails(keypair, tmp_path, capsys):
    signer, key_path = keypair
    bundle_path = _write_bundle(tmp_path, signer)
    bundle = json.load(open(bundle_path, encoding="utf-8"))
    raw = base64.b64decode(bundle["envelope"]["payload"])
    bundle["envelope"]["payload"] = base64.b64encode(
        raw.replace(b"demo-mcp", b"evil-mcp")).decode("ascii")
    p2 = tmp_path / "tampered.json"
    p2.write_text(json.dumps(bundle), encoding="utf-8")
    rc = verify_bundle(str(p2), key_path)
    assert rc == 1
    assert "signature (in-toto): FAIL" in capsys.readouterr().out


def test_schema_invalid_payload_fails(keypair, tmp_path, capsys):
    # sign a payload that VIOLATES the schema (bad registry enum)
    signer, key_path = keypair
    att = _att()
    att["subject"]["registry"] = "cran"
    bundle_path = _write_bundle(tmp_path, signer, att, "badschema.json")
    rc = verify_bundle(bundle_path, key_path)
    assert rc == 2
    out = capsys.readouterr().out
    assert "schema:    FAIL" in out


def test_missing_bundle_file(keypair, tmp_path):
    _, key_path = keypair
    assert verify_bundle(str(tmp_path / "nope.json"), key_path) == 3

