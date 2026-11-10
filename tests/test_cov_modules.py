# -*- coding: utf-8 -*-
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_dead_letter_record_and_summary(tmp_path):
    from canari.dead_letter import DeadLetterLog
    log = DeadLetterLog(str(tmp_path / "dead.json"))
    log.record("fetch", "express", "timeout")
    log.record("fetch", "lodash", "timeout")
    log.record("scan", "pkg", "parse error")
    s = log.summary()
    assert s["total"] == 3
    assert s["by_operation"] == {"fetch": 2, "scan": 1}


def test_dead_letter_truncates_error(tmp_path):
    from canari.dead_letter import DeadLetterLog
    log = DeadLetterLog(str(tmp_path / "d.json"))
    log.record("op", "tgt", "x" * 500)
    assert len(log.entries[0]["error"]) == 200


def test_dead_letter_persists_and_clears(tmp_path):
    from canari.dead_letter import DeadLetterLog
    p = str(tmp_path / "d.json")
    log = DeadLetterLog(p)
    log.record("op", "tgt", "boom")
    log.save()
    reopened = DeadLetterLog(p)
    assert reopened.summary()["total"] == 1
    reopened.clear()
    assert reopened.summary()["total"] == 0
    assert json.load(open(p, encoding="utf-8")) == []


def test_dead_letter_survives_corrupt_file(tmp_path):
    from canari.dead_letter import DeadLetterLog
    p = tmp_path / "d.json"
    p.write_text("{broken", encoding="utf-8")
    assert DeadLetterLog(str(p)).summary()["total"] == 0


def _bundle(path, registry, name, version, verdict="pass", gen="2026-11-10T00:00:00Z"):
    payload = {"subject": {"registry": registry, "name": name, "version": version},
               "verdict": verdict, "generated_at": gen}
    path.write_text(json.dumps({"payload": payload}), encoding="utf-8")


def test_build_feed_picks_latest_per_component(tmp_path):
    from canari.feed import build_feed
    att = tmp_path / "attestations"
    att.mkdir()
    _bundle(att / "a-old.bundle.json", "npm", "express", "5.2.0", gen="2026-11-01T00:00:00Z")
    _bundle(att / "a-new.bundle.json", "npm", "express", "5.3.0", gen="2026-11-09T00:00:00Z")
    _bundle(att / "b.bundle.json", "pypi", "requests", "2.32.0", gen="2026-11-02T00:00:00Z")
    feed = build_feed(str(tmp_path))
    assert feed["store"]["bundle_files"] == 3
    assert feed["store"]["components"] == 2
    assert feed["feed_version"] == 3
    versions = {(i["registry"], i["name"]): i.get("version") for i in feed["items"]}
    assert versions[("npm", "express")] == "5.3.0"
    assert versions[("pypi", "requests")] == "2.32.0"


def test_build_feed_skips_unparsable_bundles(tmp_path):
    from canari.feed import build_feed
    att = tmp_path / "attestations"
    att.mkdir()
    (att / "bad.bundle.json").write_text("{not json", encoding="utf-8")
    _bundle(att / "good.bundle.json", "npm", "x", "1.0.0")
    feed = build_feed(str(tmp_path))
    assert feed["store"]["components"] == 1
    assert feed["store"]["bundle_files"] == 1   # the broken one is not counted


def test_log_setup_is_idempotent():
    from canari.log import setup
    setup("INFO")
    setup("DEBUG")     # must not raise on a second call
