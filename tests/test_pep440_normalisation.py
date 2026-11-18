# -*- coding: utf-8 -*-
"""PEP 440 normalisation in the registry audit.

Found 2026-11-19 by re-running the real install for the published 274: a registry
entry declaring `0.2.0-rc.3` is installable (pip normalises to `0.2.0rc3`) but the
raw string is not a key in PyPI's `releases`, so the audit counted it as missing.
Six of the 32 PyPI version-absent rows were normalisation false positives.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import canari.registry_audit as ra


def _fake_pypi(releases):
    def fake_get(url, timeout=15):
        return 200, {"info": {"version": "9.9.9"}, "releases": releases}
    return fake_get


class TestPep440Normalisation:
    def test_prerelease_spelling_is_installable(self, monkeypatch):
        monkeypatch.setattr(ra, "_get", _fake_pypi({"0.2.0rc3": [{"filename": "x.whl"}],
                                                    "0.1.0": [{"filename": "y.whl"}]}))
        row = ra.check_one((("pypi", "p", "0.2.0-rc.3"), ["srv"]))
        assert row["status"] == "ok", row

    def test_v_prefix_is_installable(self, monkeypatch):
        monkeypatch.setattr(ra, "_get", _fake_pypi({"0.1.1": [{"filename": "x.whl"}]}))
        row = ra.check_one((("pypi", "p", "v0.1.1"), ["srv"]))
        assert row["status"] == "ok", row

    def test_genuinely_absent_stays_absent(self, monkeypatch):
        monkeypatch.setattr(ra, "_get", _fake_pypi({"1.0.0": [{"filename": "x.whl"}]}))
        row = ra.check_one((("pypi", "p", "0.0.9"), ["srv"]))
        assert row["status"] == "version-absent", row

    def test_raw_key_still_works(self, monkeypatch):
        monkeypatch.setattr(ra, "_get", _fake_pypi({"1.0.0": [{"filename": "x.whl"}]}))
        row = ra.check_one((("pypi", "p", "1.0.0"), ["srv"]))
        assert row["status"] == "ok", row

    def test_service_version_is_not_judged(self, monkeypatch):
        monkeypatch.setattr(ra, "_get", _fake_pypi({"1.0.0": [{"filename": "x.whl"}]}))
        row = ra.check_one((("pypi", "p", "latest"), ["srv"]))
        assert row["status"] == "reserved-tag", row
