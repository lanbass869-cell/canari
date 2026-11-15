# -*- coding: utf-8 -*-
"""SARIF ingestion: record ANOTHER tool's scan as a Canari attestation.

The point of these tests is not "does it parse". It is:
  - we must never claim Canari performed the scan
  - we must never bind a verdict to an artifact we cannot identify
  - a high/critical finding must move the verdict, or the ledger is a rubber stamp
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari.sarif_ingest import build_attestation, ingest, sarif_to_checks
from canari.signing import read_signed_payload, check_payload_integrity

SHA = "a" * 64


def _sarif(results=None, exec_ok=True, tool="SkillSpector", ver="1.4.0"):
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "semanticVersion": ver}},
            "invocations": [{"executionSuccessful": exec_ok,
                             "endTimeUtc": "2026-11-14T10:00:00Z"}],
            "results": results or [],
        }],
    }


def _res(rule="agent.data-exfiltration", level="error", sev="9.1", uri="skill/main.py", line=12):
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": "example"},
        "properties": {"security-severity": sev},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line}}}],
    }


class TestVerdictMapping:
    def test_no_findings_is_pass(self):
        checks, verdict, tool, ver, meta = sarif_to_checks(_sarif([]))
        assert verdict == "pass"
        assert meta["results"] == 0
        assert checks[0]["verdict"] == "pass"

    def test_critical_finding_is_fail(self):
        checks, verdict, _, _, _ = sarif_to_checks(_sarif([_res(sev="9.1")]))
        assert verdict == "fail"
        assert checks[0]["verdict"] == "fail"

    def test_medium_finding_is_pass_with_findings(self):
        checks, verdict, _, _, meta = sarif_to_checks(_sarif([_res(sev="5.0", level="warning")]))
        assert verdict == "pass-with-findings"
        assert meta["highest_severity"] == "medium"

    def test_execution_failure_is_error_not_pass(self):
        _c, verdict, _n, _v, meta = sarif_to_checks(_sarif([], exec_ok=False))
        assert verdict == "error"
        assert meta["execution_successful"] is False

    def test_empty_sarif_is_error_not_pass(self):
        """A report with no runs must not read as a clean scan."""
        checks, verdict, tool, _v, meta = sarif_to_checks({"version": "2.1.0", "runs": []})
        assert verdict == "error"
        assert meta["execution_successful"] is False
        assert "unusable" in checks[0]["evidence_ref"]
        assert tool == "unknown-scanner"


class TestAttribution:
    def test_upstream_tool_is_named_not_canari(self):
        att = build_attestation(_sarif([]), "pkg-x", "npm", SHA)
        checks = att["checks"]
        assert all(c["tool"].startswith("SkillSpector/") for c in checks), checks
        assert "SkillSpector" in att["checker"]["id"]
        assert "canari" in att["checker"]["id"].lower()  # discloses it was ingested

    def test_finding_carries_rule_and_location(self):
        att = build_attestation(_sarif([_res(rule="agent.secret-leak", uri="a/b.py", line=7)]),
                                "pkg-x", "npm", SHA)
        refs = " ".join(c["evidence_ref"] for c in att["checks"])
        assert "agent.secret-leak" in refs
        assert "a/b.py:7" in refs


class TestArtifactBinding:
    def test_missing_artifact_sha_is_rejected(self):
        with pytest.raises(ValueError):
            build_attestation(_sarif([]), "pkg-x", "npm", "")

    def test_malformed_artifact_sha_is_rejected(self):
        with pytest.raises(ValueError):
            build_attestation(_sarif([]), "pkg-x", "npm", "not-a-hash")

    def test_artifact_sha_is_carried_into_subject(self):
        att = build_attestation(_sarif([]), "pkg-x", "pypi", SHA, version="1.2.3")
        assert att["subject"]["artifact_sha256"] == SHA
        assert att["subject"]["registry"] == "pypi"
        assert att["subject"]["version"] == "1.2.3"


class TestBoundedAndHonest:
    def test_findings_are_capped_and_counted(self):
        many = [_res(rule="r%d" % i) for i in range(50)]
        att = build_attestation(_sarif(many), "pkg-x", "npm", SHA)
        finding_checks = [c for c in att["checks"] if c["id"] == "L3.1_FINDING"]
        assert len(finding_checks) <= 20
        assert att["evidence_completeness"]["dropped_logs"] == 50 - len(finding_checks)

    def test_scenario_hash_is_deterministic(self):
        a = build_attestation(_sarif([]), "pkg-x", "npm", SHA)
        b = build_attestation(_sarif([]), "pkg-x", "npm", SHA)
        assert a["scenario_sha256"] == b["scenario_sha256"]


class TestRoundTrip:
    def test_signed_bundle_verifies(self, tmp_path):
        s = _sarif([_res(sev="9.4")])
        sp = tmp_path / "r.sarif"
        sp.write_text(json.dumps(s), encoding="utf-8")
        key = tmp_path / "k.pem"
        out = tmp_path / "att"
        path, verdict = ingest(str(sp), "pkg-x", "npm", SHA, str(key), str(out))
        assert verdict == "fail"
        bundle = json.load(open(path, encoding="utf-8"))
        ok, why, payload = check_payload_integrity(bundle)
        assert ok is True, why
        assert payload["subject"]["artifact_sha256"] == SHA
        signed, err = read_signed_payload(bundle)
        assert err is None
        assert signed["verdict"] == "fail"
        assert signed["checks"][0]["tool"].startswith("SkillSpector/")

class TestSchemaConformance:
    ALLOWED_CHECK_VERDICTS = {"pass", "fail", "skip", "unsupported", "error"}

    def test_every_check_verdict_is_schema_legal(self):
        """Regression: 'pass-with-findings' is only legal at the attestation
        level. A per-check verdict using it makes verify_bundle fail schema."""
        from canari.schema import validate_attestation
        cases = [
            _sarif([]),
            _sarif([_res(sev="5.0", level="warning")]),
            _sarif([_res(sev="9.5")]),
            {"version": "2.1.0", "runs": []},
        ]
        for sarif in cases:
            att = build_attestation(sarif, "pkg-x", "npm", SHA)
            for c in att["checks"]:
                assert c["verdict"] in self.ALLOWED_CHECK_VERDICTS, c
            errors = validate_attestation(att)
            assert not errors, errors


def _bandit(results=None, errors=None, version="1.9.4"):
    return {"errors": errors or [], "metrics": {"_totals": {}},
            "generated_at": "2026-11-14T10:00:00Z",
            "bandit_version": version,
            "results": results or []}


def _bhit(sev="HIGH", test_id="B602", fname="pkg/run.py", line=10):
    return {"filename": fname, "test_id": test_id, "test_name": "shell_injection",
            "issue_severity": sev, "issue_confidence": "HIGH",
            "issue_text": "subprocess call with shell=True", "line_number": line}


class TestBanditAdapter:
    def test_bandit_format_is_detected(self):
        from canari.sarif_ingest import detect_format
        assert detect_format(_bandit()) == "bandit"
        assert detect_format(_sarif()) == "sarif"
        assert detect_format({"whatever": 1}) is None

    def test_high_severity_fails(self):
        att = build_attestation(_bandit([_bhit("HIGH")]), "pkg-x", "pypi", SHA)
        assert att["verdict"] == "fail"
        assert att["checks"][0]["tool"] == "bandit/1.9.4"

    def test_medium_is_pass_with_findings(self):
        att = build_attestation(_bandit([_bhit("MEDIUM", "B101")]), "pkg-x", "pypi", SHA)
        assert att["verdict"] == "pass-with-findings"
        assert att["checks"][0]["verdict"] == "pass"

    def test_clean_is_pass(self):
        att = build_attestation(_bandit([]), "pkg-x", "pypi", SHA)
        assert att["verdict"] == "pass"
        assert att["checks"][0]["verdict"] == "pass"

    def test_scanner_errors_are_error_not_pass(self):
        att = build_attestation(_bandit([], errors=[{"filename": "x.py"}]), "pkg-x", "pypi", SHA)
        assert att["verdict"] == "error"

    def test_unknown_format_rejected(self):
        with pytest.raises(ValueError):
            build_attestation({"hello": "world"}, "pkg-x", "pypi", SHA)


class TestUnspecifiedSeverity:
    """gitleaks 8.30.1 writes no level and no security-severity.

    Before this fix, a missing level defaulted to "warning" -> medium, so a
    leaked credential was recorded as pass-with-findings and could never fail.
    Absence of severity is not evidence of low severity.
    """

    def _no_level_sarif(self, rule_level=None):
        res = {"ruleId": "github-pat", "message": {"text": "leak"}}
        rule = {"id": "github-pat"}
        if rule_level:
            rule["defaultConfiguration"] = {"level": rule_level}
        return {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "gitleaks", "semanticVersion": "8.30.1",
                                "rules": [rule]}},
            "invocations": [{"executionSuccessful": True}],
            "results": [res]}]}

    def test_missing_level_is_unknown_not_medium(self):
        from canari.sarif_ingest import sarif_to_checks
        checks, verdict, _t, _v, meta = sarif_to_checks(self._no_level_sarif())
        assert meta["highest_severity"] == "unknown"
        assert verdict == "fail"

    def test_rule_default_configuration_is_used(self):
        from canari.sarif_ingest import sarif_to_checks
        _c, verdict, _t, _v, meta = sarif_to_checks(self._no_level_sarif("note"))
        assert meta["highest_severity"] == "low"
        assert verdict == "pass-with-findings"

    def test_explicit_error_still_fails(self):
        from canari.sarif_ingest import sarif_to_checks
        s = self._no_level_sarif()
        s["runs"][0]["results"][0]["level"] = "error"
        _c, verdict, _t, _v, meta = sarif_to_checks(s)
        assert meta["highest_severity"] == "high"
        assert verdict == "fail"


class TestEvidenceNotary:
    """Notarizing someone else's published export: bind, but never overclaim."""

    def _idx(self, sha=None, entries=10, states=None, checks=None):
        return {"dataset": "demo-evidence", "run": "2026-11-14",
                "probed_at": "2026-11-14T10:00:00Z", "entries": entries,
                "states": states if states is not None else {"alive": 7, "dead": 3},
                "checks": checks if checks is not None else {"endpoint": 10},
                "bytes": 1234, "sha256": sha or "f" * 64,
                "checked_with": {"client": "demo 1.0", "sdk": "sdk 1.0"}}

    def test_consistent_index_passes_with_findings(self):
        from canari.evidence_notary import build_attestation
        att = build_attestation(self._idx())
        assert att["verdict"] == "pass-with-findings"
        assert att["subject"]["registry"] == "dataset"
        assert att["subject"]["artifact_sha256"] == "f" * 64

    def test_inconsistent_summary_fails(self):
        from canari.evidence_notary import build_attestation
        att = build_attestation(self._idx(entries=10, states={"alive": 1}))
        assert att["verdict"] == "fail"

    def test_digest_is_not_claimed_as_recomputed(self):
        """The notary must not pretend it downloaded and hashed the data file."""
        from canari.evidence_notary import build_attestation
        att = build_attestation(self._idx())
        hashcheck = [c for c in att["checks"] if c["id"] == "L2.1_ARTIFACT_HASH"][0]
        assert hashcheck["verdict"] == "unsupported"
        assert "not recomputed" in hashcheck["evidence_ref"]

    def test_missing_sha_is_refused(self):
        import pytest
        from canari.evidence_notary import build_attestation
        bad = self._idx()
        bad.pop("sha256")
        with pytest.raises(ValueError):
            build_attestation(bad)

    def test_schema_accepts_dataset_records(self):
        from canari.evidence_notary import build_attestation
        from canari.schema import validate_attestation
        assert validate_attestation(build_attestation(self._idx())) == []
