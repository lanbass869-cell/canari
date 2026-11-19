# -*- coding: utf-8 -*-
"""The monitor script: two-phase, append-safe, and never turns a sample into a finding.

The verdict logic has its own tests (test_endpoint_history.py). What is tested
here is the plumbing around it, because that plumbing decides whether a run that
dies halfway loses its evidence, and whether a "no evidence" state can leak into
a findings list.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from scripts import monitor_endpoints as mon  # noqa: E402


def _obs(outcome, hour):
    return {"outcome": outcome, "observed_at": "2026-01-01T%02d:00:00Z" % hour,
            "http_status": None, "error": None}


def test_report_only_lists_confirmed_findings_and_nothing_else(tmp_path):
    history_path = str(tmp_path / "h.json")
    out_path = str(tmp_path / "r.json")
    doc = {"schema": "canari.endpoint-history/1", "endpoints": {
        "https://broken/mcp": [_obs("not_mcp", 1), _obs("not_mcp", 12)],
        "https://down/mcp": [_obs("unreachable", 1), _obs("unreachable", 12)],
        "https://fine/mcp": [_obs("alive", 1)],
        "https://flappy/mcp": [_obs("not_mcp", 1), _obs("alive", 6), _obs("not_mcp", 12)],
        "https://authy/mcp": [_obs("auth", 1), _obs("auth", 9)],
    }}
    with open(history_path, "w", encoding="utf-8") as f:
        json.dump(doc, f)

    summary = mon.main(["--report-only", "--history", history_path, "--out", out_path])

    urls = {f["url"] for f in summary["findings"]}
    assert urls == {"https://broken/mcp", "https://down/mcp"}, (
        "only confirmed verdicts may be findings: %r" % (urls,))
    assert "https://flappy/mcp" not in urls, "flapping must not be promoted to a finding"
    assert "https://authy/mcp" not in urls, "a refusal is not a finding"

    with open(out_path, encoding="utf-8") as f:
        written = json.load(f)
    assert written["confirmed_findings"] == 2
    assert written["thresholds"]["min_observations"] >= 2


def test_the_two_failure_classes_stay_separate_in_the_report(tmp_path):
    history_path = str(tmp_path / "h.json")
    out_path = str(tmp_path / "r.json")
    with open(history_path, "w", encoding="utf-8") as f:
        json.dump({"schema": "canari.endpoint-history/1", "endpoints": {
            "https://broken/mcp": [_obs("not_mcp", 1), _obs("not_mcp", 12)],
            "https://down/mcp": [_obs("unreachable", 1), _obs("unreachable", 12)],
        }}, f)
    summary = mon.main(["--report-only", "--history", history_path, "--out", out_path])
    by_url = {f["url"]: f["verdict"] for f in summary["findings"]}
    assert by_url["https://broken/mcp"] == "INCONSISTENT_CONFIRMED"
    assert by_url["https://down/mcp"] == "UNAVAILABLE_CONFIRMED"


def test_probe_all_saves_after_every_probe_so_a_kill_keeps_evidence(tmp_path, monkeypatch):
    """A run that dies halfway must keep what it already observed."""
    import canari.endpoint_history as eh

    saved = []
    real_save = eh.EndpointHistory.save

    def tracking_save(self):
        real_save(self)
        saved.append(len(self._data.get("endpoints", {})))

    monkeypatch.setattr(eh.EndpointHistory, "save", tracking_save)
    monkeypatch.setattr(mon, "probe_endpoint",
                        lambda url, timeout: {"checked_at": "2026-01-01T00:00:00Z",
                                              "outcome": "alive", "http_status": 200,
                                              "error": None})

    history = eh.EndpointHistory(str(tmp_path / "h.json"))
    todo = [({}, "https://a/mcp"), ({}, "https://b/mcp"), ({}, "https://c/mcp")]
    mon.probe_all(todo, timeout=1, history=history, delay=0)

    assert len(saved) == 3, "history must be persisted per probe, got %r" % (saved,)


def test_max_probe_caps_the_work(tmp_path, monkeypatch):
    monkeypatch.setattr(mon, "fetch_registry", lambda limit: {"servers": [
        {"server": {"name": "a", "remotes": [{"url": "https://a/mcp"}]}},
        {"server": {"name": "b", "remotes": [{"url": "https://b/mcp"}]}},
        {"server": {"name": "c", "remotes": [{"url": "https://c/mcp"}]}},
    ]})
    probed = []
    monkeypatch.setattr(mon, "probe_endpoint",
                        lambda url, timeout: probed.append(url) or {
                            "checked_at": "2026-01-01T00:00:00Z", "outcome": "alive",
                            "http_status": 200, "error": None})
    mon.main(["--max-probe", "2", "--delay", "0",
              "--history", str(tmp_path / "h.json"),
              "--out", str(tmp_path / "r.json")])
    assert len(probed) == 2


def test_skip_host_excludes_ephemeral_tunnels():
    data = {"servers": [
        {"server": {"name": "a", "remotes": [{"url": "https://x.trycloudflare.com/mcp"}]}},
        {"server": {"name": "b", "remotes": [{"url": "https://b.example/mcp"}]}},
    ]}
    got = [u for _, u in mon.targets(data, ["trycloudflare.com"])]
    assert got == ["https://b.example/mcp"]


def test_targets_deduplicate_urls_across_entries():
    data = {"servers": [
        {"server": {"name": "a", "remotes": [{"url": "https://same/mcp"}]}},
        {"server": {"name": "b", "remotes": [{"url": "https://same/mcp"}]}},
    ]}
    assert len(mon.targets(data)) == 1
