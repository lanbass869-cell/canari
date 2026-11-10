# -*- coding: utf-8 -*-
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_state_store_starts_empty(tmp_path):
    from canari.state import StateStore
    s = StateStore(str(tmp_path / "state.json"))
    assert s.is_first_run is True
    assert s.run_count == 0
    assert s.get_component("nope") is None


def test_state_store_save_and_reload(tmp_path):
    from canari.state import StateStore
    p = str(tmp_path / "state.json")
    s = StateStore(p)
    s.set_component("express", "5.3.0", "aa11", "dd22", meta={"maintainers": ["x"]})
    s.save()
    assert s.run_count == 1
    assert s.is_first_run is False

    s2 = StateStore(p)
    assert s2.run_count == 1
    e = s2.get_component("express")
    assert e["version"] == "5.3.0"
    assert e["sha256"] == "aa11"
    assert e["meta"]["maintainers"] == ["x"]


def test_state_store_save_is_atomic_and_corrupt_tolerant(tmp_path):
    from canari.state import StateStore
    p = str(tmp_path / "state.json")
    open(p, "w", encoding="utf-8").write("{ not json")
    s = StateStore(p)
    assert s.is_first_run is True          # corrupt file falls back to defaults
    s.save()
    assert json.load(open(p, encoding="utf-8"))["run_count"] == 1
    assert not os.path.exists(p + ".tmp")  # tmp cleaned up by os.replace


def test_state_diff_classifies_all_four(tmp_path):
    from canari.state import StateStore
    s = StateStore(str(tmp_path / "s.json"))
    prev = {"a": {"sha256": "1"}, "b": {"sha256": "2"}, "gone": {"sha256": "9"}}
    cur = {"a": {"sha256": "1"}, "b": {"sha256": "CHANGED"}, "new": {"sha256": "3"}}
    d = s.diff(cur, prev)
    assert d["unchanged"] == ["a"]
    assert d["changed"] == ["b"]
    assert d["new"] == ["new"]
    assert d["removed"] == ["gone"]


def test_filelock_acquires_and_releases(tmp_path):
    from canari.state import FileLock
    p = str(tmp_path / "x")
    with FileLock(p, timeout=2):
        assert os.path.exists(p + ".lock")
    # released: a second acquisition must succeed immediately
    with FileLock(p, timeout=2):
        pass


def test_filelock_times_out_when_held(tmp_path):
    from canari.state import FileLock
    p = str(tmp_path / "y")
    inner = FileLock(p, timeout=1)
    inner.__enter__()
    try:
        with pytest.raises(TimeoutError):
            with FileLock(p, timeout=0.2):
                pass
    finally:
        inner.__exit__()


def test_score_errors_on_missing_and_empty_store(tmp_path):
    from canari.score import score
    assert "error" in score(str(tmp_path))
    (tmp_path / "attestations").mkdir()
    assert score(str(tmp_path))["error"] == "empty attestation store"
