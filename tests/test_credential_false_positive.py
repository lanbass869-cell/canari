# -*- coding: utf-8 -*-
"""Credential heuristics must not reject ordinary package names.

Real incident (2026-11-13): the "vendor key prefix" rule matched `pypi-` with no
length requirement, so the PyPI package
`mcp-server-time-allenash-pypi-test` was rejected with
CREDENTIAL_IN_PAYLOAD during signing - and because the PyPI loop had no
per-package error boundary, that aborted an entire 700-package sweep.

Two properties are pinned here:
  1. realistic identifiers are NOT flagged (no false positives)
  2. real token shapes ARE still flagged (the rule must not be gutted)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari.signing import credential_shapes


class TestNoFalsePositives:
    def test_package_name_containing_pypi_prefix(self):
        assert credential_shapes(
            {"subject": {"name": "mcp-server-time-allenash-pypi-test"}}) == []

    def test_other_ordinary_identifiers(self):
        for name in [
            "mcp-server-npm-helper",          # contains npm_
            "sk-live-testing-tool",           # contains sk...
            "github-pat-helper-mcp",          # contains github_pat
            "mcp-server-pypi-upload-tool",    # contains pypi-
            "xox-bridge-server",              # contains xox
        ]:
            got = credential_shapes({"subject": {"name": name}})
            assert got == [], "%s was falsely flagged: %s" % (name, got)


class TestRealTokensStillCaught:
    def test_pypi_token(self):
        tok = "pypi-" + "A" * 60
        assert credential_shapes({"v": tok}), "real PyPI token must be caught"

    def test_github_tokens(self):
        for tok in ["ghp_" + "a" * 36,
                    "github_pat_" + "a" * 22 + "_" + "b" * 59,
                    "gho_" + "a" * 36]:
            assert credential_shapes({"v": tok}), tok[:12]

    def test_npm_and_stripe(self):
        assert credential_shapes({"v": "npm_" + "x" * 36})
        assert credential_shapes({"v": "sk_live_" + "a" * 24})

    def test_aws_and_google(self):
        assert credential_shapes({"v": "AKIA" + "B" * 16})
        assert credential_shapes({"v": "AIza" + "c" * 30})


class TestScanSurvivesOneBadPackage:
    """A per-package failure must not abort the registry sweep."""

    @staticmethod
    def _src():
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return open(os.path.join(root, "canari", "baseline.py"), encoding="utf-8").read()

    def test_pypi_loop_has_save_error_boundary(self):
        src = self._src()
        assert "except Exception as _save_err:" in src
        assert "pypi_attest" in src, "the save failure must be dead-lettered"
