# -*- coding: utf-8 -*-
"""npm tombstones: an unpublished package must read as package-gone, not version-absent.

Found 2026-11-19: GET /<unscoped-pkg> answers 200 with `versions: {}` and
`time.unpublished: {time, versions}` after an unpublish. The audit read the 200 as
"package exists", so tombstones were counted as version-absent - wrong bucket, and the
error message a publisher would see ("publish this version") is impossible to follow.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import canari.registry_audit as ra


def _fake(payload):
    def fake_get(url, timeout=15):
        return 200, payload
    return fake_get


class TestNpmTombstone:
    def test_unpublished_object_is_package_gone(self, monkeypatch):
        monkeypatch.setattr(ra, "_get", _fake({
            "versions": {},
            "time": {"unpublished": {"time": "2026-08-05T17:24:17.672Z",
                                     "versions": ["0.1.0", "0.1.1"]}},
        }))
        row = ra.check_one((("npm", "ace-context-mcp", "0.1.1"), ["srv"]))
        assert row["status"] == "package-gone", row

    def test_empty_versions_without_timestamp_is_package_gone(self, monkeypatch):
        monkeypatch.setattr(ra, "_get", _fake({"versions": {}}))
        row = ra.check_one((("npm", "gone-mcp", "1.0.0"), ["srv"]))
        assert row["status"] == "package-gone", row

    def test_live_package_missing_version_stays_version_absent(self, monkeypatch):
        monkeypatch.setattr(ra, "_get", _fake({
            "versions": {"2.0.0": {}}, "time": {"modified": "2026-11-01T00:00:00Z"}}))
        row = ra.check_one((("npm", "live-mcp", "9.9.9"), ["srv"]))
        assert row["status"] == "version-absent", row

    def test_live_package_present_version_is_ok(self, monkeypatch):
        monkeypatch.setattr(ra, "_get", _fake({"versions": {"2.0.0": {}}}))
        row = ra.check_one((("npm", "live-mcp", "2.0.0"), ["srv"]))
        assert row["status"] == "ok", row
