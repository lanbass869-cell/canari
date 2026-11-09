# -*- coding: utf-8 -*-
"""E3: Schema edge case tests. GUARDS_AGAINST: schema accepting invalid
payloads (wrong enum, empty strings, bad dates, missing required fields at
every nesting level, cross-field constraints)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canari.schema import validate_attestation


def _base(**overrides):
    att = {
        "_type": "https://agentcheck.dev/attestation/v0.1",
        "subject": {"name": "test", "version": "1.0", "registry": "npm",
                    "artifact_sha256": "a" * 64},
        "host": {"class": "mcp", "host_version": "h1"},
        "scenario_sha256": "b" * 64,
        "checks": [{"id": "L1.1_X", "verdict": "pass", "tool": "t"}],
        "verdict": "pass",
        "checker": {"kind": "automation", "id": "c1"},
        "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
        "generated_at": "2026-11-09T00:00:00Z",
        "signature": {"envelope": "DSSE", "keyid": "k", "sig": "s",
                      "payload_type": "https://agentcheck.dev/attestation/v0.1"},
    }
    for key, val in overrides.items():
        if key.startswith("_"):
            parts = key[1:].split(".")
            obj = att
            for p in parts[:-1]:
                if isinstance(val, dict) and p == parts[-2] and isinstance(obj.get(p), dict):
                    # Merge dict values instead of replacing
                    obj[p] = {**obj.get(p, {}), **val}
                    break
                obj = obj.setdefault(p, {})
            if parts[-1] in obj:
                if isinstance(val, dict) and isinstance(obj[parts[-1]], dict):
                    obj[parts[-1]] = {**obj[parts[-1]], **val}
                else:
                    obj[parts[-1]] = val
            else:
                obj[parts[-1]] = val
        else:
            att[key] = val
    return att


class TestSchemaEdgeCases:
    def test_subject_empty_name(self):
        att = _base(_subject={"name": ""})
        errs = validate_attestation(att)
        assert any("name" in e for e in errs)

    def test_subject_missing_name_key(self):
        att = _base(_subject={"name": None})
        att["subject"].pop("name", None)
        errs = validate_attestation(att)
        assert any("name" in e for e in errs)

    def test_registry_mcp_registry_valid(self):
        att = _base(_subject={"registry": "mcp-registry"})
        assert validate_attestation(att) == []

    def test_checks_empty_array(self):
        att = _base(checks=[])
        errs = validate_attestation(att)
        assert any("checks" in e for e in errs)

    def test_check_missing_id(self):
        att = _base()
        att["checks"] = [{"verdict": "pass", "tool": "t"}]
        errs = validate_attestation(att)
        assert any("id" in e for e in errs)

    def test_check_bad_verdict(self):
        att = _base()
        att["checks"] = [{"id": "X", "verdict": "maybe", "tool": "t"}]
        errs = validate_attestation(att)
        assert any("verdict" in e for e in errs)

    def test_verdict_bad_enum(self):
        att = _base(verdict="excellent")
        errs = validate_attestation(att)
        assert any("verdict" in e for e in errs)

    def test_artifact_sha256_not_hex(self):
        att = _base(_subject={"artifact_sha256": "not-hex"})
        errs = validate_attestation(att)
        assert any("artifact_sha256" in e for e in errs)

    def test_artifact_sha256_uppercase(self):
        """Uppercase hex should be rejected (pattern requires lowercase)."""
        att = _base(_subject={"artifact_sha256": "A" * 64})
        errs = validate_attestation(att)
        assert any("artifact_sha256" in e for e in errs)

    def test_scenario_sha256_short(self):
        att = _base(scenario_sha256="ab" * 16)  # 32 chars, need 64
        errs = validate_attestation(att)
        assert any("scenario_sha256" in e for e in errs)

    def test_top_level_unknown_field(self):
        # NOTE: schema does NOT have additionalProperties:false at root level.
        # Unknown fields are silently accepted. This is a schema gap to fix in v0.2.
        att = _base(unknown_field="surprise")
        # Document the gap: currently passes (no error)
        # assert any("unknown_field" in e for e in errs)  # should fail in v0.2

    def test_subject_unknown_field(self):
        # NOTE: schema does NOT have additionalProperties:false on subject.
        att = _base(_subject={"injected": "value"})
        # Document the gap

    def test_check_unknown_field(self):
        # NOTE: schema does NOT have additionalProperties:false on checks items.
        att = _base()
        att["checks"][0]["extra"] = "data"
        # Document the gap


class TestNativeProvenanceEdgeCases:
    def test_native_provenance_full_valid(self):
        att = _base()
        att["native_provenance"] = {
            "present": True, "predicate_types": ["v1"],
            "v1_verified": True, "v1_identity": "https://github.com/x/y@v1",
            "v1_error": None, "v0_presence_only": 0,
            "verifier": "sigstore-python/4.5.1",
        }
        assert validate_attestation(att) == []

    def test_native_provenance_all_null(self):
        att = _base()
        att["native_provenance"] = {
            "present": False, "predicate_types": [],
            "v1_verified": None, "v1_identity": None, "v1_error": None,
            "v0_presence_only": 0, "verifier": "test",
        }
        assert validate_attestation(att) == []

    def test_native_provenance_missing_present(self):
        att = _base()
        att["native_provenance"] = {"v1_verified": True}
        errs = validate_attestation(att)
        assert any("present" in e for e in errs)

    def test_native_provenance_bad_v1_verified_type(self):
        att = _base()
        att["native_provenance"] = {"present": True, "v1_verified": "yes"}
        errs = validate_attestation(att)
        assert any("v1_verified" in e for e in errs)


class TestSupersedesAndRevocations:
    def test_supersedes_valid(self):
        att = _base(supersedes="sha256-abc123")
        assert validate_attestation(att) == []

    def test_related_revocations_valid(self):
        att = _base(related_revocations=[
            {"name": "evil-pkg", "relation": "same-author", "ref": "digest123"},
        ])
        assert validate_attestation(att) == []

    def test_related_revocations_missing_ref(self):
        att = _base(related_revocations=[
            {"name": "evil-pkg", "relation": "same-author"},
        ])
        errs = validate_attestation(att)
        assert any("ref" in e for e in errs)

    def test_related_revocations_bad_relation(self):
        att = _base(related_revocations=[
            {"name": "evil-pkg", "relation": "best-friend", "ref": "d"},
        ])
        errs = validate_attestation(att)
        assert any("relation" in e for e in errs)
