# -*- coding: utf-8 -*-
"""Feed namespace isolation (BUG-91): a scan must never overwrite the canonical
component-level feed consumers read."""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mock_run(tmp_path, monkeypatch):
    import canari.baseline as bl
    monkeypatch.setattr(bl, "enumerate_top", lambda limit=50, dedupe=True: [])
    monkeypatch.setattr(bl, "pypi_enumerate", lambda limit=500, cache_path=None: [])
    monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda limit=500: [])
    monkeypatch.setattr(bl, "dsh_enumerate", lambda limit=500, with_security=True: [{
        "name": "p1", "version": "1.0.0", "registry": "dsh-registry"}])
    monkeypatch.setattr(bl, "_runner_source_digest", lambda: "d" * 64)
    bl.run_multi(npm_limit=0, pypi_limit=0, registry_limit=0, dsh_limit=1,
                 out_dir=str(tmp_path))


class TestFeedNamespace:
    def test_scan_does_not_touch_canonical_feed(self, tmp_path, monkeypatch):
        from canari.feed import write_feed, build_feed
        _mock_run(tmp_path, monkeypatch)
        fp = write_feed(str(tmp_path))
        before = open(fp, encoding="utf-8").read()
        _mock_run(tmp_path, monkeypatch)  # a second scan
        after = open(fp, encoding="utf-8").read()
        assert before == after, "scan overwrote the canonical feed"
        assert json.loads(after)["store"]["components"] == 1
        run_feeds = glob.glob(os.path.join(str(tmp_path), "feed", "run-feed-*.json"))
        assert run_feeds, "run-level feed missing"
        assert json.loads(open(run_feeds[0], encoding="utf-8").read())["feed_version"] == 2

    def test_canonical_feed_shape(self, tmp_path, monkeypatch):
        from canari.feed import write_feed, build_feed
        _mock_run(tmp_path, monkeypatch)
        feed = build_feed(str(tmp_path))
        assert feed["feed_version"] == 3
        assert feed["store"]["bundle_files"] >= 1
        assert feed["items"] and feed["items"][0]["bundle_file"].endswith(".bundle.json")
