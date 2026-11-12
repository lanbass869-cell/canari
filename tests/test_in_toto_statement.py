# -*- coding: utf-8 -*-
"""in-toto Statement v1 compliance.

Without this test the "we emit in-toto attestations" claim silently regresses
to "DSSE envelope around a custom JSON blob" - which GUAC cannot graph and
cosign cannot consume. Measured on a real bundle before the migration:
_type wrong, subject an object instead of an array, no predicateType,
no predicate.
"""
import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari.signing import (_PREDICATE_TYPE, STATEMENT_TYPE, generate_keypair,
                            sign_attestation, unwrap_statement, verify_signed,
                            verify_signed_raw)
from canari.verify_cli import _check_statement_shape


def _att(name="x", sha="a" * 64):
    return {
        "_type": "https://agentcheck.dev/attestation/v0.1",
        "subject": {"name": name, "version": "1.0.0", "registry": "npm",
                    "artifact_sha256": sha, "maintainers": []},
        "host": {"class": "mcp", "host_version": "t"},
        "scenario_sha256": "b" * 64,
        "checks": [{"id": "L1.1", "verdict": "pass", "tool": "t/0.1"}],
        "verdict": "pass",
        "checker": {"kind": "automation", "id": "t"},
        "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                  "truncated_fields": []},
        "generated_at": "2026-11-12T00:00:00Z",
        "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                      "payload_type": _PREDICATE_TYPE},
    }


@pytest.fixture(scope="module")
def kp():
    return generate_keypair()


def _signed_statement(att, signer):
    s = sign_attestation(att, signer)
    raw = base64.b64decode(s["envelope"]["payload"])
    return s, json.loads(raw)


class TestStatementShape:
    def test_type_is_statement_v1(self, kp):
        signer, _ = kp
        _s, stmt = _signed_statement(_att(), signer)
        assert stmt["_type"] == "https://in-toto.io/Statement/v1"

    def test_subject_is_array_with_digest(self, kp):
        signer, _ = kp
        _s, stmt = _signed_statement(_att("pkg-a"), signer)
        assert isinstance(stmt["subject"], list) and len(stmt["subject"]) == 1
        ent = stmt["subject"][0]
        assert "pkg-a" in ent["name"]
        assert ent["digest"]["sha256"] == "a" * 64

    def test_predicate_type_and_predicate_present(self, kp):
        signer, _ = kp
        _s, stmt = _signed_statement(_att(), signer)
        assert stmt["predicateType"] == _PREDICATE_TYPE
        assert isinstance(stmt["predicate"], dict)
        assert stmt["predicate"]["verdict"] == "pass"

    def test_predicate_is_verbatim_attestation(self, kp):
        """The predicate must equal the attestation body (minus the inline
        signature block, which differs by design: pass 1 vs pass 2 of signing).

        Any derived field added here would diverge from the unsigned mirror
        and be reported as tampering by check_payload_integrity().
        """
        signer, _ = kp
        s, stmt = _signed_statement(_att(), signer)

        def body(d):
            return {k: v for k, v in d.items() if k != "signature"}

        assert body(stmt["predicate"]) == body(s["payload"])

    def test_no_fake_sha256_for_metadata_only(self, kp):
        """Unknown artifact bytes must not be reported as a sha256."""
        signer, _ = kp
        _s, stmt = _signed_statement(_att("meta-only", sha="0" * 64), signer)
        digest = stmt["subject"][0]["digest"]
        assert "sha256" not in digest
        assert "canari-component-id" in digest

    def test_shape_validator_accepts_signed_statement(self, kp):
        signer, _ = kp
        _s, stmt = _signed_statement(_att(), signer)
        ok, why = _check_statement_shape(stmt)
        assert ok is True, why

    def test_shape_validator_flags_old_format(self, kp):
        signer, _ = kp
        ok, _why = _check_statement_shape(_att())
        assert ok == "legacy"

    def test_shape_validator_rejects_object_subject(self, kp):
        signer, _ = kp
        _s, stmt = _signed_statement(_att(), signer)
        stmt["subject"] = {"name": "x", "digest": {"sha256": "a" * 64}}
        ok, _why = _check_statement_shape(stmt)
        assert ok is False

    def test_shape_validator_rejects_missing_predicate_type(self, kp):
        signer, _ = kp
        _s, stmt = _signed_statement(_att(), signer)
        del stmt["predicateType"]
        ok, _why = _check_statement_shape(stmt)
        assert ok is False


class TestStatementVerify:
    def test_signature_covers_statement(self, kp):
        signer, pub = kp
        s, _stmt = _signed_statement(_att(), signer)
        ok, raw, err = verify_signed_raw(s["envelope"], pub.to_dict())
        assert ok, err
        assert raw["_type"] == STATEMENT_TYPE

    def test_tampering_predicate_breaks_signature(self, kp):
        signer, pub = kp
        s, stmt = _signed_statement(_att(), signer)
        stmt["predicate"]["verdict"] = "fail"
        env = dict(s["envelope"])
        env["payload"] = base64.b64encode(
            json.dumps(stmt, ensure_ascii=False, sort_keys=True).encode()).decode()
        assert verify_signed(env, pub.to_dict())[0] is False

    def test_consumer_gets_unwrapped_attestation(self, kp):
        signer, pub = kp
        s, _stmt = _signed_statement(_att(), signer)
        ok, payload, err = verify_signed(s["envelope"], pub.to_dict())
        assert ok, err
        assert payload["verdict"] == "pass"          # no .predicate hop needed
        assert payload["subject"]["name"] == "x"

    def test_unwrap_is_idempotent_on_legacy(self):
        body = _att()
        assert unwrap_statement(body) is body
