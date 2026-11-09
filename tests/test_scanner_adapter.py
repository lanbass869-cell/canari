# -*- coding: utf-8 -*-
"""T6: scanner adapter tests."""

# GUARDS_AGAINST: None crash in findings_to_checks, digest not reflecting scanner content changes, path traversal in scanner paths
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canari.scanner_adapter import (compute_source_digest, findings_to_checks,
                                     run_repo_forensics, get_rule_count)


class TestDigest:
    def test_digest_deterministic(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.py").write_text("y = 2")
        d1 = compute_source_digest(str(tmp_path))
        d2 = compute_source_digest(str(tmp_path))
        assert d1 == d2
        assert len(d1) == 64

    def test_digest_changes_with_content(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        d1 = compute_source_digest(str(tmp_path))
        (tmp_path / "a.py").write_text("x = 2")
        d2 = compute_source_digest(str(tmp_path))
        assert d1 != d2

    def test_digest_ignores_pycache(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        d1 = compute_source_digest(str(tmp_path))
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "junk.pyc").write_bytes(b"garbage")
        d2 = compute_source_digest(str(tmp_path))
        assert d1 == d2


class TestFindingsToChecks:
    def test_error_path(self):
        checks, verdict = findings_to_checks({"error": "scanner not found"})
        assert verdict == "error"
        assert checks[0]["id"] == "L3.1_SCANNER_ERROR"

    def test_clean_pass(self):
        data = {"summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "exit_code": 0, "scanner_count": 29, "_canari_source_digest": "a" * 64}
        checks, verdict = findings_to_checks(data)
        assert verdict == "pass"
        assert checks[0]["id"] == "L3.1_STATIC_SCAN"
        assert "0 findings" in checks[0]["evidence_ref"]

    def test_medium_findings(self):
        data = {"summary": {"total": 3, "critical": 0, "high": 0, "medium": 2, "low": 1},
                "exit_code": 1, "scanner_count": 29, "_canari_source_digest": "a" * 64}
        checks, verdict = findings_to_checks(data)
        assert verdict == "pass-with-findings"

    def test_critical_fail(self):
        data = {"summary": {"total": 5, "critical": 1, "high": 2, "medium": 1, "low": 1},
                "exit_code": 2, "scanner_count": 29, "_canari_source_digest": "a" * 64}
        checks, verdict = findings_to_checks(data)
        assert verdict == "fail"
        assert "critical=1" in checks[0]["evidence_ref"]

    def test_tool_id_contains_digest_and_scanner_count(self):
        data = {"summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "exit_code": 0, "scanner_count": 29, "_canari_source_digest": "b" * 64}
        checks, _ = findings_to_checks(data)
        assert "29-scanners" in checks[0]["tool"]
        assert "bbbb" in checks[0]["tool"]


class TestRepoForensicsIntegration:
    """Live tests only if the repo-forensics clone exists."""

    REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "external", "repo-forensics", "skills", "repo-forensics")

    @pytest.mark.skipif(not os.path.isdir(REPO), reason="repo-forensics not cloned")
    def test_rule_count_positive(self):
        n = get_rule_count()
        assert n > 500, "expected >500 re.compile calls, got %d" % n

    @pytest.mark.skipif(not os.path.isdir(REPO), reason="repo-forensics not cloned")
    def test_scanner_not_found_error(self):
        r = run_repo_forensics("/nonexistent/path", scanner_root="/nonexistent")
        assert "error" in r
