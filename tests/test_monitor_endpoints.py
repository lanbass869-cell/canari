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

from canari import monitor_cli as mon  # noqa: E402

# The script at scripts/monitor_endpoints.py is a thin shim; test the module that
# actually ships in the wheel, because that is what `canari-monitor` runs.


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
    # fetch_registry is patched on the module `main` actually calls, so no network.
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


def test_weekly_step_runs_end_to_end_and_writes_both_files(tmp_path, monkeypatch):
    """The weekly hook must actually probe, persist, and report, not just return."""
    monkeypatch.setattr(mon, "fetch_registry", lambda limit: {"servers": [
        {"server": {"name": "a", "remotes": [{"url": "https://a/mcp"}]}},
        {"server": {"name": "b", "remotes": [{"url": "https://b/mcp"}]}},
    ]})
    monkeypatch.setattr(mon, "probe_endpoint",
                        lambda url, timeout: {"checked_at": "2026-01-01T00:00:00Z",
                                              "outcome": "alive", "http_status": 200,
                                              "error": None})
    doc = mon.weekly_step(str(tmp_path), limit=10, max_probe=2, timeout=1, delay=0)

    assert (tmp_path / "endpoint_history.json").exists()
    assert (tmp_path / "endpoint_verdicts.json").exists()
    assert doc["endpoints_observed"] == 2
    assert doc["confirmed_findings"] == 0, (
        "one successful probe each is CONSISTENT, never a finding")


def test_weekly_step_with_no_probes_still_produces_a_report(tmp_path, monkeypatch):
    """A registry that returns nothing must not crash the weekly job."""
    monkeypatch.setattr(mon, "fetch_registry", lambda limit: {"servers": []})
    doc = mon.weekly_step(str(tmp_path), limit=10, max_probe=5, timeout=1, delay=0)
    assert doc["endpoints_observed"] == 0
    assert doc["confirmed_findings"] == 0
    assert (tmp_path / "endpoint_verdicts.json").exists()


def test_weekly_step_carries_history_across_runs(tmp_path, monkeypatch):
    """Two separate runs must accumulate into one history, which is the only way
    a verdict can ever be reached under a weekly schedule."""
    seq = iter([
        {"checked_at": "2026-01-01T00:00:00Z", "outcome": "not_mcp",
         "http_status": 200, "error": None},
        {"checked_at": "2026-01-01T07:00:00Z", "outcome": "not_mcp",
         "http_status": 200, "error": None},
    ])
    monkeypatch.setattr(mon, "fetch_registry", lambda limit: {"servers": [
        {"server": {"name": "a", "remotes": [{"url": "https://a/mcp"}]}}]})
    monkeypatch.setattr(mon, "probe_endpoint", lambda url, timeout: next(seq))

    first = mon.weekly_step(str(tmp_path), limit=5, max_probe=1, timeout=1, delay=0)
    assert first["confirmed_findings"] == 0, (
        "the first run must not be able to confirm anything on its own")

    second = mon.weekly_step(str(tmp_path), limit=5, max_probe=1, timeout=1, delay=0)
    assert second["confirmed_findings"] == 1, (
        "the second spaced observation is what makes the verdict")
    assert second["findings"][0]["verdict"] == "INCONSISTENT_CONFIRMED"


# ------------------------------------------------------------------ pagination
#
# Live run 2026-11-19: `--limit 600` died with HTTP 422 because the registry
# rejects any page size above 100. Every test above used small fixtures, so none
# of them could have caught it. These do.


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urllib(monkeypatch, opener):
    """Patch the module's urllib namespace without inventing a new one.

    The first version replaced the whole `urllib` attribute with a synthetic
    object, which dropped `urllib.parse` -- so the test failed inside the fake
    rather than in the code under test.
    """
    import urllib.parse as real_parse

    fake = type("U", (), {
        "request": type("R", (), {
            "urlopen": staticmethod(opener),
            "Request": __import__("urllib.request", fromlist=["Request"]).Request,
        }),
        "parse": real_parse,
    })
    monkeypatch.setattr(mon, "urllib", fake)


def _install_registry(monkeypatch, pages, record):
    def fake_urlopen(req, timeout=None):
        record.append(req.full_url)
        return _FakeResp(pages.pop(0))
    _fake_urllib(monkeypatch, fake_urlopen)


def test_fetch_registry_never_asks_for_more_than_the_api_allows(monkeypatch):
    """The server rejects limit > 100 with 422. The client must page instead."""
    urls = []
    _install_registry(monkeypatch, [
        {"servers": [{"n": i} for i in range(100)], "metadata": {"nextCursor": "c1"}},
        {"servers": [{"n": i} for i in range(100, 200)], "metadata": {}},
    ], urls)

    got = mon.fetch_registry(150)
    assert len(got["servers"]) == 150
    assert len(urls) == 2
    for u in urls:
        assert "limit=100" in u or "limit=" not in u, u
        assert "limit=150" not in u, "a page larger than the cap is a 422: %s" % u
    assert "cursor=c1" in urls[1]


def test_fetch_registry_stops_when_the_cursor_runs_out(monkeypatch):
    urls = []
    _install_registry(monkeypatch, [
        {"servers": [{"n": 1}], "metadata": {"nextCursor": "c1"}},
        {"servers": [{"n": 2}], "metadata": {}},
    ], urls)
    got = mon.fetch_registry(500)
    assert len(got["servers"]) == 2
    assert len(urls) == 2


def test_fetch_registry_has_a_hard_page_cap(monkeypatch):
    """A server that always hands back a cursor must not loop forever."""
    urls = []

    class Loop:
        def __init__(self):
            self.n = 0

        def __call__(self, req, timeout=None):
            self.n += 1
            return _FakeResp({"servers": [{"n": self.n}],
                              "metadata": {"nextCursor": "c%d" % self.n}})

    _fake_urllib(monkeypatch, Loop())
    got = mon.fetch_registry(10000, max_pages=3)
    assert len(got["servers"]) == 3
