# -*- coding: utf-8 -*-
"""BUG-101 regression: a component that vanished from the market must not keep
its old pass standing.

The dsh.so market index is a filtered allowlist (install-verified + low-risk).
When a component drops out of it we can no longer re-verify it, but the ledger
kept serving its previous "pass-with-findings" bundle (zero hash, no disclosure).
That is the same verdict inflation as BUG-98, one level up: the honest record is
"cannot confirm presence; bytes never fetched" -> verdict unsupported.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _run(tmp_path, monkeypatch, dsh):
    import canari.baseline as bl
    monkeypatch.setattr(bl, "enumerate_top", lambda limit=50, dedupe=True: [])
    monkeypatch.setattr(bl, "pypi_enumerate", lambda limit=500, cache_path=None: [])
    monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda limit=500: [])
    monkeypatch.setattr(bl, "dsh_enumerate",
                        lambda limit=500, with_security=True: dsh)
    monkeypatch.setattr(bl, "_runner_source_digest", lambda: "d" * 64)
    res = bl.run_multi(npm_limit=0, pypi_limit=0, registry_limit=0,
                       dsh_limit=len(dsh), out_dir=str(tmp_path))
    feed = json.load(open(res["feed"], encoding="utf-8"))
    bundles = {}
    for f in tmp_path.joinpath("attestations").glob("dsh_*.bundle.json"):
        bp = json.loads(f.read_text(encoding="utf-8"))["payload"]
        bundles[bp["subject"]["name"]] = bp
    return feed, bundles


class TestDelistedComponent:
    def test_absent_component_is_unsupported_with_disclosure(self, tmp_path, monkeypatch):
        feed, bundles = _run(tmp_path, monkeypatch,
                             [{"name": "gone", "version": "1.0.0", "absent": True,
                               "last_seen": "2026-11-09T16:07:59Z"}])
        p = bundles["gone"]
        assert p["verdict"] == "unsupported"
        ids = {c["id"]: c["verdict"] for c in p["checks"]}
        assert ids["L1.1_REGISTRY_PRESENT"] == "unsupported"
        assert ids["L2.0_ARTIFACT_UNVERIFIED"] == "unsupported"
        assert "L1.1_REGISTRY_PRESENT" not in [
            c["id"] for c in p["checks"] if c["verdict"] == "pass"]
        # the run feed must agree with the signed bundle
        assert [i["verdict"] for i in feed["items"]] == ["unsupported"]

    def test_absent_reason_names_the_disappearance(self, tmp_path, monkeypatch):
        _, bundles = _run(tmp_path, monkeypatch,
                          [{"name": "gone2", "version": "1.0.0", "absent": True,
                            "last_seen": "2026-11-09T16:07:59Z"}])
        ev = {c["id"]: c.get("evidence_ref", "") for c in bundles["gone2"]["checks"]}
        assert "market index" in ev["L1.1_REGISTRY_PRESENT"]
        assert "2026-11-09T16:07:59Z" in ev["L1.1_REGISTRY_PRESENT"]
        assert "not fetched or hashed" in ev["L2.0_ARTIFACT_UNVERIFIED"]

    def test_absent_never_reports_pass(self, tmp_path, monkeypatch):
        feed, bundles = _run(tmp_path, monkeypatch,
                             [{"name": "gone3", "version": "1", "absent": True}])
        assert bundles["gone3"]["verdict"] not in ("pass", "pass-with-findings")
        assert feed["by_verdict"] == {"unsupported": 1}

    def test_present_component_path_unaffected(self, tmp_path, monkeypatch):
        feed, bundles = _run(tmp_path, monkeypatch,
                             [{"name": "ok", "version": "1", "install_verdict": "passed",
                               "security_critical": 0, "security_files_scanned": 1,
                               "security_scanner": "s"}])
        assert bundles["ok"]["verdict"] == "pass-with-findings"
        assert "L1.1_REGISTRY_PRESENT" in [c["id"] for c in bundles["ok"]["checks"]]
