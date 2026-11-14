# -*- coding: utf-8 -*-
"""Schema validation + install-gate predicate tests."""

# GUARDS_AGAINST: schema violation not caught (missing field, bad enum, empty checks, invalid gate verdict)
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canari.schema import load_schema, validate_attestation, is_gate_passing


def _valid_att(**overrides):
    att = {
        "_type": "https://agentcheck.dev/attestation/v0.1",
        "subject": {"name": "x", "version": "1.0", "registry": "npm",
                    "artifact_sha256": "a" * 64},
        "host": {"class": "mcp", "host_version": "h1"},
        "scenario_sha256": "b" * 64,
        "checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t"},
                   {"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "t"}],
        "verdict": "pass",
        "checker": {"kind": "automation", "id": "c1"},
        "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
        "generated_at": "2026-11-08T00:00:00Z",
        "signature": {"envelope": "DSSE", "keyid": "k", "sig": "s",
                      "payload_type": "https://agentcheck.dev/attestation/v0.1"},
    }
    att.update(overrides)
    return att


class TestSchema:
    def test_valid_attestation_zero_errors(self):
        assert validate_attestation(_valid_att()) == []

    def test_missing_required_field(self):
        att = _valid_att()
        del att["scenario_sha256"]
        errs = validate_attestation(att)
        assert any("scenario_sha256" in e for e in errs)

    def test_bad_registry_enum(self):
        att = _valid_att()
        att["subject"]["registry"] = "cran"
        assert validate_attestation(att)

    def test_bad_sha256_pattern(self):
        att = _valid_att()
        att["subject"]["artifact_sha256"] = "xyz"
        assert validate_attestation(att)

    def test_bad_verdict_enum(self):
        att = _valid_att()
        att["verdict"] = "maybe"
        assert validate_attestation(att)

    def test_checks_min_items(self):
        att = _valid_att()
        att["checks"] = []
        assert validate_attestation(att)

    def test_check_missing_tool(self):
        att = _valid_att()
        att["checks"] = [{"id": "L1.1_X", "verdict": "pass"}]
        assert validate_attestation(att)

    def test_related_revocations_ok(self):
        att = _valid_att()
        att["related_revocations"] = [{"name": "evil-variant", "relation": "name-variant", "ref": "digest1"}]
        assert validate_attestation(att) == []

    def test_supersedes_chain_ok(self):
        att = _valid_att()
        att["supersedes"] = "sha256-abc"
        assert validate_attestation(att) == []


class TestGate:
    def test_pass_allows(self):
        assert is_gate_passing(_valid_att()) is True

    def test_pass_with_findings_allows(self):
        att = _valid_att(); att["verdict"] = "pass-with-findings"
        assert is_gate_passing(att) is True

    def test_fail_blocks(self):
        att = _valid_att(); att["verdict"] = "fail"
        assert is_gate_passing(att) is False

    def test_error_blocks(self):
        att = _valid_att(); att["verdict"] = "error"
        assert is_gate_passing(att) is False

    def test_unsupported_not_pass(self):
        att = _valid_att(); att["verdict"] = "unsupported"
        assert is_gate_passing(att) is False

    def test_empty_no_verdict(self):
        assert is_gate_passing({}) is False
        assert is_gate_passing(None) is False
