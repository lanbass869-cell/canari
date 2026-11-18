# -*- coding: utf-8 -*-
"""Tests for the false-pass hardening (2026-11-18).

Three shapes of "looks checked, actually not" were live in the codebase:

1. `cadence.py` returned `[]` both for "ran, found nothing" and for "could not run",
   and every call site turned `[]` into verdict "pass".
2. The record verdict was `"pass" if sha else "fail"`, so a package whose tarball
   downloaded was recorded as passing even when the heuristics inside it reported
   "unsupported". 2,473 of 6,787 records in the store carry that shape.
3. `guard.parse_install` did not recognise `npx -y <pkg>` / `uvx <pkg>` -- the most
   common way an MCP server is started -- and printed "no install pattern
   recognised; passing through".

Each test below fails on the pre-fix code.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import canari.cadence as cadence
from canari.baseline import _cadence_rows, _record_verdict
from canari.guard import parse_install


class TestCadenceReturnsNoneWhenItCannotCheck:
    """`None` = could not evaluate, `[]` = evaluated and clean. Never conflate."""

    def test_no_uploads_is_none_not_empty(self):
        assert cadence._cadence_from_uploads([], "1.0") is None

    def test_version_absent_from_history_is_none(self):
        uploads = [(cadence._parse_iso_z("2026-01-01T00:00:00Z"), "1.0")]
        assert cadence._cadence_from_uploads(uploads, "9.9") is None

    def test_version_present_and_clean_is_empty_list(self):
        uploads = [(cadence._parse_iso_z("2026-01-01T00:00:00Z"), "1.0")]
        assert cadence._cadence_from_uploads(uploads, "1.0") == []

    def test_npm_without_packument_is_none(self):
        assert cadence.analyze_npm_cadence(None, "1.0") is None
        assert cadence.analyze_npm_cadence({}, "1.0") is None

    def test_pypi_without_version_is_none(self):
        assert cadence.analyze_release_cadence("p", "") is None

    def test_pypi_version_missing_from_releases_is_none(self):
        doc = {"releases": {"1.0": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}]}}
        assert cadence.analyze_release_cadence("p", "9.9", pypi_json=doc) is None


class TestCadenceRowsNeverClaimPassForUnchecked:
    def test_none_becomes_unsupported(self):
        row = _cadence_rows(None, "clean")[0]
        assert row["verdict"] == "unsupported"
        assert row["id"] == "L2.4_RELEASE_CADENCE"
        assert "not evaluated" in row["evidence_ref"]

    def test_empty_list_becomes_pass(self):
        row = _cadence_rows([], "no cadence anomaly")[0]
        assert row["verdict"] == "pass"
        assert row["evidence_ref"] == "no cadence anomaly"

    def test_findings_pass_through(self):
        finding = [{"id": "L2.4_RELEASE_CADENCE", "verdict": "pass",
                    "tool": "t", "evidence_ref": "finding: release_burst"}]
        assert _cadence_rows(finding, "clean") == finding


class TestRecordVerdictFollowsTheWeakestLink:
    def _row(self, verdict, ref=""):
        return {"id": "X", "verdict": verdict, "evidence_ref": ref}

    def test_all_pass_is_pass(self):
        assert _record_verdict([self._row("pass")], "a" * 64) == "pass"

    def test_any_unsupported_makes_it_unsupported(self):
        """The pre-fix code returned 'pass' here, which is the whole bug."""
        checks = [self._row("pass"), self._row("unsupported")]
        assert _record_verdict(checks, "a" * 64) == "unsupported"

    def test_any_error_makes_it_error(self):
        checks = [self._row("pass"), self._row("error")]
        assert _record_verdict(checks, "a" * 64) == "error"

    def test_any_skip_makes_it_unsupported(self):
        checks = [self._row("skip")]
        assert _record_verdict(checks, "a" * 64) == "unsupported"

    def test_fail_dominates(self):
        checks = [self._row("unsupported"), self._row("fail")]
        assert _record_verdict(checks, "a" * 64) == "fail"

    def test_finding_only_is_pass_with_findings(self):
        checks = [self._row("pass", "finding: release_burst")]
        assert _record_verdict(checks, "a" * 64) == "pass-with-findings"

    def test_no_artifact_hash_is_fail(self):
        """Nothing downloaded means nothing can be said about the bytes."""
        assert _record_verdict([self._row("pass")], None) == "fail"

    def test_unsupported_beats_finding(self):
        checks = [self._row("pass", "finding: x"), self._row("unsupported")]
        assert _record_verdict(checks, "a" * 64) == "unsupported"


class TestGuardRecognisesLaunchers:
    def test_npx(self):
        assert parse_install(["npx", "-y", "@modelcontextprotocol/server-filesystem",
                              "/tmp"]) == [("npm", "@modelcontextprotocol/server-filesystem", None)]

    def test_uvx(self):
        assert parse_install(["uvx", "mcp-server-fetch"]) == [("pypi", "mcp-server-fetch", None)]

    def test_pipx(self):
        assert parse_install(["pipx", "mcp-server-git"]) == [("pypi", "mcp-server-git", None)]

    def test_scoped_version_pin(self):
        assert parse_install(["npx", "@scope/pkg@1.2.3"]) == [("npm", "@scope/pkg", "1.2.3")]

    def test_unrecognised_still_returns_empty(self):
        assert parse_install(["node", "server.js"]) == []


class TestEmptyCorpusIsSkipNotPass:
    """A similarity verdict needs a corpus. No corpus -> skip, never pass."""

    def test_typosquat_returns_none_on_empty_corpus(self):
        from canari.typosquat import check_typosquatting
        assert check_typosquatting("mcp-server-fetch", set()) is None

    def test_empty_corpus_becomes_skip(self):
        from canari.baseline import _typosquat_row
        row = _typosquat_row(None, set())
        assert row["verdict"] == "skip"
        assert row["id"] == "L2.6_TYPOSQUATTING"
        assert "corpus" in row["evidence_ref"]

    def test_non_empty_corpus_with_no_finding_is_pass(self):
        from canari.baseline import _typosquat_row
        row = _typosquat_row(None, {"pkg-a", "pkg-b"})
        assert row["verdict"] == "pass"

    def test_finding_is_kept_and_corpus_attached(self):
        from canari.baseline import _typosquat_row
        corpus = {"registry": "npm", "size": 2, "digest": "sha256:aa"}
        found = {"id": "L2.6_TYPOSQUATTING", "verdict": "pass-with-findings",
                 "tool": "canari-typosquat/0.1",
                 "evidence_ref": "distance 1 from pkg-a"}
        row = _typosquat_row(found, {"pkg-a", "pkg-b"}, corpus)
        assert row["verdict"] == "pass-with-findings"
        assert row["comparison_corpus"]["size"] == 2


class TestPreviousSnapshotIsRegistryAware:
    """A plain-name state entry from another registry is not this one's baseline.

    134 bare names appear on both npm and PyPI in one MCP Registry snapshot and
    33 of those are unrelated projects (experiments/identity_conflict). Letting
    the meta tier write plain names and the reader fall back unconditionally
    meant an npm package could be compared against a PyPI package with the same
    name - a maintainer "change" that never happened, or a real one hidden.
    """

    def test_qualified_entry_wins(self):
        from canari.baseline import _prev_from
        from canari.state import StateStore
        st = StateStore.__new__(StateStore)
        st._data = {"components": {
            "npm:foo": {"version": "1", "sha256": "a"},
            "foo": {"version": "9", "sha256": "b"},
        }}
        assert _prev_from(st, "npm", "foo")["version"] == "1"

    def test_plain_entry_from_other_registry_is_ignored(self):
        from canari.baseline import _prev_from
        from canari.state import StateStore
        st = StateStore.__new__(StateStore)
        st._data = {"components": {
            "foo": {"version": "2", "sha256": "",
                    "meta": {"tier": "meta", "registry": "pypi"}},
        }}
        assert _prev_from(st, "npm", "foo") is None

    def test_plain_entry_from_same_registry_is_used(self):
        from canari.baseline import _prev_from
        from canari.state import StateStore
        st = StateStore.__new__(StateStore)
        st._data = {"components": {
            "foo": {"version": "2", "sha256": "",
                    "meta": {"tier": "meta", "registry": "npm"}},
        }}
        assert _prev_from(st, "npm", "foo")["version"] == "2"

    def test_unstamped_legacy_entry_keeps_working(self):
        from canari.baseline import _prev_from
        from canari.state import StateStore
        st = StateStore.__new__(StateStore)
        st._data = {"components": {"foo": {"version": "3", "sha256": "c"}}}
        assert _prev_from(st, "npm", "foo")["version"] == "3"
