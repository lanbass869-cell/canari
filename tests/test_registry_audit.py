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


# ------------------------------------------------------------------ network half
# The network half is covered with a stubbed opener so the suite stays offline and
# deterministic. These tests exist because the module is mostly network code, and
# leaving it uncovered dropped the repository's overall coverage below its gate.

import json
import urllib.error

import canari.registry_audit as ra


class _Resp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()
        self.status = 200

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _stub(monkeypatch, table):
    """table: url-substring -> payload | int (http status)."""
    calls = []

    def fake(req, timeout=None, context=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        calls.append(url)
        for key, val in table.items():
            if key in url:
                if isinstance(val, int):
                    raise urllib.error.HTTPError(url, val, "err", {}, None)
                return _Resp(val)
        raise urllib.error.HTTPError(url, 404, "nf", {}, None)

    monkeypatch.setattr(ra.urllib.request, "urlopen", fake)
    return calls


class TestGet:
    def test_returns_payload(self, monkeypatch):
        _stub(monkeypatch, {"example.test": {"ok": 1}})
        status, data = ra._get("https://example.test/x")
        assert status == 200 and data == {"ok": 1}

    def test_404_is_returned_not_retried(self, monkeypatch):
        calls = _stub(monkeypatch, {"gone.test": 404})
        status, data = ra._get("https://gone.test/x")
        assert status == 404 and data is None
        assert len(calls) == 1

    def test_network_failure_retries_then_unknown(self, monkeypatch):
        calls = []

        def boom(req, timeout=None, context=None):
            calls.append(1)
            raise OSError("no route")

        monkeypatch.setattr(ra.urllib.request, "urlopen", boom)
        monkeypatch.setattr(ra.time, "sleep", lambda *_: None)
        status, data = ra._get("https://x.test/y", tries=2)
        assert status is None
        assert data and "_err" in data
        assert len(calls) == 2


class TestFetchRegistry:
    def test_paginates_until_no_cursor(self, monkeypatch):
        pages = [
            {"servers": [{"server": {"name": "a/x"}}], "metadata": {"nextCursor": "c1"}},
            {"servers": [{"server": {"name": "b/y"}}], "metadata": {}},
        ]
        seq = iter(pages)
        monkeypatch.setattr(ra, "_get", lambda *a, **k: (200, next(seq)))
        recs, n = ra.fetch_registry()
        assert n == 2 and len(recs) == 2

    def test_max_pages_stops_early(self, monkeypatch):
        monkeypatch.setattr(ra, "_get", lambda *a, **k: (200, {"servers": [], "metadata": {"nextCursor": "z"}}))
        recs, n = ra.fetch_registry(max_pages=3)
        assert n == 3

    def test_raises_on_bad_status(self, monkeypatch):
        monkeypatch.setattr(ra, "_get", lambda *a, **k: (500, None))
        try:
            ra.fetch_registry()
        except RuntimeError as e:
            assert "registry fetch failed" in str(e)
        else:
            raise AssertionError("expected RuntimeError")


class TestCheckOne:
    def test_npm_version_present(self, monkeypatch):
        _stub(monkeypatch, {"registry.npmjs.org": {"versions": {"1.0.0": {}}}})
        r = ra.check_one((("npm", "pkg", "1.0.0"), ["a/x"]))
        assert r["status"] == "ok"

    def test_npm_version_missing(self, monkeypatch):
        _stub(monkeypatch, {"registry.npmjs.org": {"versions": {"2.0.0": {}}}})
        r = ra.check_one((("npm", "pkg", "1.0.0"), ["a/x"]))
        assert r["status"] == "version-absent"

    def test_pypi_release_with_no_files_is_absent(self, monkeypatch):
        _stub(monkeypatch, {"pypi.org": {"releases": {"1.0.0": []}}})
        r = ra.check_one((("pypi", "pkg", "1.0.0"), ["a/x"]))
        assert r["status"] == "version-absent"

    def test_pypi_release_with_files_is_ok(self, monkeypatch):
        _stub(monkeypatch, {"pypi.org": {"releases": {"1.0.0": [{"filename": "w.whl"}]}}})
        r = ra.check_one((("pypi", "pkg", "1.0.0"), ["a/x"]))
        assert r["status"] == "ok"

    def test_missing_package(self, monkeypatch):
        _stub(monkeypatch, {"registry.npmjs.org": 404})
        r = ra.check_one((("npm", "gone", "1.0.0"), ["a/x"]))
        assert r["status"] == "package-gone"


class TestCheckRefs:
    def test_runs_all_items(self, monkeypatch):
        monkeypatch.setattr(ra, "check_one", lambda item: {"status": "ok", "servers": item[1]})
        rows = ra.check_refs({("npm", "a", "1"): ["x/y"], ("npm", "b", "1"): ["x/z"]}, workers=2)
        assert len(rows) == 2


class TestOutputs:
    def _rows(self):
        return [
            {"registry": "npm", "identifier": "a", "version": "1", "status": "package-gone",
             "http": 404, "servers": ["ns/one"]},
            {"registry": "pypi", "identifier": "b", "version": "2", "status": "ok",
             "http": 200, "servers": ["ns/two"]},
        ]

    def test_render_page_contains_the_numbers(self):
        rows = [r for r in self._rows() if r["status"] != "ok"]
        html = ra.render_page(ra.summarize(self._rows()), rows, "2026-11-17", 654)
        assert "2026-11-17" in html and "654" in html
        assert "cannot be installed" in html
        assert "ns/one" in html

    def test_render_page_truncates_long_lists(self):
        rows = [{"registry": "npm", "identifier": "p%d" % i, "version": "1",
                 "status": "package-gone", "servers": ["ns/x"]} for i in range(450)]
        html = ra.render_page(ra.summarize(rows), rows, "2026-11-17", 1)
        assert "first 400 rows" in html

    def test_render_page_with_ranking(self):
        rows = [r for r in self._rows() if r["status"] != "ok"]
        html = ra.render_page(ra.summarize(self._rows()), rows, "2026-11-17", 1,
                              ranking=[{"namespace": "ns", "entries": 1, "refs": 1, "share": 1.0}],
                              ns_totals={"ns": 4})
        assert "Where to start" in html and "1/4" in html

    def test_write_outputs_creates_all_files(self, tmp_path):
        rows = self._rows()
        doc = ra.write_outputs(str(tmp_path), ra.summarize(rows), rows, "2026-11-17", 10,
                               ranking=[], ns_totals={})
        assert doc["summary"]["missing"] == 1
        for name in ("latest.json", "latest.csv", "index.html",
                     os.path.join("history", "2026-11-17.json")):
            assert (tmp_path / name).exists()
        csv_text = (tmp_path / "latest.csv").read_text(encoding="utf-8")
        assert "package-gone" in csv_text
        assert "a" in csv_text and "ns/one" in csv_text


class TestMain:
    def test_end_to_end_with_stubs(self, tmp_path, monkeypatch):
        recs = [{"server": {"name": "ns/one",
                            "packages": [{"registryType": "npm", "identifier": "gone",
                                          "version": "1.0.0"}]}}]
        monkeypatch.setattr(ra, "fetch_registry", lambda max_pages=None: (recs, 1))
        monkeypatch.setattr(ra, "check_one",
                            lambda item: {"registry": "npm", "identifier": "gone",
                                          "version": "1.0.0", "status": "package-gone",
                                          "http": 404, "servers": item[1]})
        rc = ra.main(["--out", str(tmp_path), "--as-of", "2026-11-17"])
        assert rc == 0
        doc = json.loads((tmp_path / "latest.json").read_text(encoding="utf-8"))
        assert doc["summary"]["missing"] == 1
        assert doc["rows"][0]["identifier"] == "gone"
        assert doc["ranking"][0]["namespace"] == "ns"
