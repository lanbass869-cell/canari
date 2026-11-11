# -*- coding: utf-8 -*-
"""BUG-100 regression: the run-level feed must echo the signed bundle verdict.

The published run-feed is what a consumer reads when it wants to know what a
scan found. It hardcoded "pass-with-findings" for every mcp-registry and
dsh-registry item, so 247 of 559 entries in dataset/feeds/run-feed-20261110T142700.json
claimed a pass while their signed bundles said "unsupported". The bundle is the
signed artifact; the feed is a projection of it and must never disagree.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _run(tmp_path, monkeypatch, dsh=None, mcp=None):
    import canari.baseline as bl
    monkeypatch.setattr(bl, "enumerate_top", lambda limit=50, dedupe=True: [])
    monkeypatch.setattr(bl, "pypi_enumerate", lambda limit=500, cache_path=None: [])
    monkeypatch.setattr(bl, "mcp_registry_enumerate",
                        lambda limit=500: mcp or [])
    monkeypatch.setattr(bl, "dsh_enumerate",
                        lambda limit=500, with_security=True: dsh or [])
    monkeypatch.setattr(bl, "_runner_source_digest", lambda: "d" * 64)
    res = bl.run_multi(npm_limit=0, pypi_limit=0,
                       registry_limit=len(mcp or []),
                       dsh_limit=len(dsh or []), out_dir=str(tmp_path))
    feed = json.load(open(res["feed"], encoding="utf-8"))
    return res, feed


def _bundles(tmp_path):
    out = {}
    for f in tmp_path.joinpath("attestations").glob("*.bundle.json"):
        p = json.loads(f.read_text(encoding="utf-8"))["payload"]
        out[(p["subject"]["registry"], p["subject"]["name"])] = p
    return out


class TestRunFeedEchoesVerdict:
    def test_mcp_unsupported_is_not_reported_as_pass(self, tmp_path, monkeypatch):
        res, feed = _run(tmp_path, monkeypatch, mcp=[{"name": "mcp/x", "version": "1.0"}])
        items = feed["items"]
        assert len(items) == 1
        assert items[0]["verdict"] == "unsupported"
        assert feed["by_verdict"] == {"unsupported": 1}
        assert _bundles(tmp_path)[("mcp-registry", "mcp/x")]["verdict"] == "unsupported"

    def test_dsh_unsupported_is_not_reported_as_pass(self, tmp_path, monkeypatch):
        res, feed = _run(tmp_path, monkeypatch, dsh=[{"name": "bare", "version": "1"}])
        items = feed["items"]
        assert items[0]["verdict"] == "unsupported"
        assert feed["by_verdict"] == {"unsupported": 1}

    def test_dsh_pass_is_reported_as_pass(self, tmp_path, monkeypatch):
        entry = {"name": "ok", "version": "1", "install_verdict": "passed",
                 "security_critical": 0, "security_files_scanned": 3,
                 "security_scanner": "s"}
        res, feed = _run(tmp_path, monkeypatch, dsh=[entry])
        assert feed["items"][0]["verdict"] == "pass-with-findings"

    def test_dsh_fail_is_reported_as_fail(self, tmp_path, monkeypatch):
        entry = {"name": "bad", "version": "1", "install_verdict": "passed",
                 "security_critical": 2}
        res, feed = _run(tmp_path, monkeypatch, dsh=[entry])
        assert feed["items"][0]["verdict"] == "fail"

    def test_run_feed_never_disagrees_with_bundles(self, tmp_path, monkeypatch):
        """The invariant: every feed item's verdict equals its bundle's verdict."""
        dsh = [{"name": "bare", "version": "1"},
               {"name": "ok", "version": "1", "install_verdict": "passed",
                "security_critical": 0, "security_files_scanned": 2,
                "security_scanner": "s"},
               {"name": "bad", "version": "1", "install_verdict": "passed",
                "security_critical": 1}]
        mcp = [{"name": "mcp/a", "version": "1"}]
        res, feed = _run(tmp_path, monkeypatch, dsh=dsh, mcp=mcp)
        bundles = _bundles(tmp_path)
        assert len(feed["items"]) == 4
        for item in feed["items"]:
            key = (item["registry"], item["name"])
            assert key in bundles
            assert item["verdict"] == bundles[key]["verdict"], key
