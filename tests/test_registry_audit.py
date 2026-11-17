# -*- coding: utf-8 -*-
"""Tests for the registry package-existence audit.

The network half is exercised by the scheduled run, not here. What is tested here is the
part that decides the published numbers: which references are collected, how a result is
classified, and how the counts are rolled up. Getting any of these wrong makes the report
lie while every request still succeeds.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari.registry_audit import classify, collect_refs, rank_namespaces, namespace_totals, summarize


def _rec(name, packages):
    return {"server": {"name": name, "packages": packages}}


def _pkg(reg, ident, ver):
    return {"registryType": reg, "identifier": ident, "version": ver}


class TestCollectRefs:
    def test_only_npm_and_pypi(self):
        recs = [_rec("a/x", [_pkg("npm", "pkg-a", "1.0.0"),
                             _pkg("oci", "ghcr.io/a/x", "1"),
                             _pkg("mcpb", "https://x/y.mcpb", "1")])]
        refs = collect_refs(recs)
        assert list(refs) == [("npm", "pkg-a", "1.0.0")]

    def test_same_reference_in_two_entries_is_deduped_and_keeps_both_names(self):
        recs = [_rec("a/x", [_pkg("npm", "shared", "1.0.0")]),
                _rec("b/y", [_pkg("npm", "shared", "1.0.0")])]
        refs = collect_refs(recs)
        assert len(refs) == 1
        assert refs[("npm", "shared", "1.0.0")] == ["a/x", "b/y"]

    def test_missing_identifier_skipped(self):
        recs = [_rec("a/x", [_pkg("npm", "", "1.0.0"), _pkg("pypi", "real", "2.0")])]
        assert list(collect_refs(recs)) == [("pypi", "real", "2.0")]

    def test_missing_version_is_kept_as_empty_string(self):
        """An entry with no version is not the same as a missing package; keep it so the
        classifier can bucket it rather than silently dropping it."""
        recs = [_rec("a/x", [_pkg("npm", "pkg", None)])]
        assert list(collect_refs(recs)) == [("npm", "pkg", "")]


class TestClassify:
    def test_resolves(self):
        assert classify("1.0.0", 200, True) == "ok"

    def test_package_gone(self):
        assert classify("1.0.0", 404, False) == "package-gone"

    def test_version_absent(self):
        assert classify("1.0.0", 200, False) == "version-absent"

    def test_dist_tag_is_its_own_bucket_not_a_missing_version(self):
        for tag in ("latest", "LATEST", "next", "beta"):
            assert classify(tag, 200, False) == "reserved-tag"

    def test_network_failure_is_unknown_never_missing(self):
        """A timeout must not be reported as a defect."""
        assert classify("1.0.0", None, False) == "unknown"

    def test_404_wins_over_tag_only_when_not_a_tag(self):
        assert classify("latest", 404, False) == "reserved-tag"


class TestSummarize:
    def _rows(self):
        return [
            {"registry": "npm", "identifier": "a", "version": "1", "status": "ok", "servers": ["n/a"]},
            {"registry": "npm", "identifier": "b", "version": "1", "status": "package-gone", "servers": ["n/b"]},
            {"registry": "pypi", "identifier": "c", "version": "1", "status": "version-absent", "servers": ["n/c", "n/d"]},
            {"registry": "npm", "identifier": "d", "version": "latest", "status": "reserved-tag", "servers": ["n/e"]},
            {"registry": "npm", "identifier": "e", "version": "1", "status": "unknown", "servers": ["n/f"]},
        ]

    def test_counts(self):
        s = summarize(self._rows())
        assert s["checked"] == 5
        assert s["ok"] == 1
        assert s["package_gone"] == 1
        assert s["version_absent"] == 1
        assert s["reserved_tag"] == 1
        assert s["unknown"] == 1

    def test_missing_excludes_reserved_tag_and_unknown(self):
        s = summarize(self._rows())
        assert s["missing"] == 2
        assert abs(s["missing_rate"] - 0.4) < 1e-9

    def test_affected_servers_deduped_across_references(self):
        s = summarize(self._rows())
        assert s["affected_servers"] == 3          # n/b, n/c, n/d

    def test_by_registry_counts_only_missing(self):
        s = summarize(self._rows())
        assert s["by_registry"] == {"npm": 1, "pypi": 1}

    def test_empty_is_safe(self):
        s = summarize([])
        assert s["checked"] == 0 and s["missing"] == 0 and s["missing_rate"] == 0.0


class TestRankNamespaces:
    def _rows(self):
        return [
            {"registry": "npm", "identifier": "a", "version": "1", "status": "package-gone",
             "servers": ["eu.ansvar/x", "eu.ansvar/y"]},
            {"registry": "npm", "identifier": "b", "version": "1", "status": "version-absent",
             "servers": ["eu.ansvar/z"]},
            {"registry": "npm", "identifier": "c", "version": "1", "status": "package-gone",
             "servers": ["io.github.a/one"]},
            {"registry": "npm", "identifier": "d", "version": "1", "status": "ok",
             "servers": ["io.github.a/two"]},
            {"registry": "npm", "identifier": "e", "version": "latest", "status": "reserved-tag",
             "servers": ["noise/one"]},
        ]

    def test_ranks_by_affected_entry_count(self):
        r = rank_namespaces(self._rows())
        assert r[0]["namespace"] == "eu.ansvar"
        assert r[0]["entries"] == 3
        assert r[0]["refs"] == 3

    def test_excludes_ok_and_reserved_tag(self):
        names = {x["namespace"] for x in rank_namespaces(self._rows())}
        assert "noise" not in names           # reserved-tag is not a missing entry
        assert "io.github.a" in names         # the ok row must not inflate the count

    def test_share_is_of_all_affected_entries(self):
        r = rank_namespaces(self._rows())
        top = r[0]
        assert abs(top["share"] - 3 / 4) < 1e-9   # 3 of 4 affected entries

    def test_limit(self):
        assert len(rank_namespaces(self._rows(), limit=1)) == 1

    def test_empty(self):
        assert rank_namespaces([]) == []

    def test_namespace_totals_counts_all_entries(self):
        recs = [{"server": {"name": "eu.ansvar/x"}},
                {"server": {"name": "eu.ansvar/y"}},
                {"server": {"name": "io.github.a/one"}},
                {"server": {"name": "no-slash"}}]
        t = namespace_totals(recs)
        assert t["eu.ansvar"] == 2 and t["io.github.a"] == 1 and "no-slash" not in t
