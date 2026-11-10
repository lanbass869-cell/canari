# -*- coding: utf-8 -*-
"""BUG-98 regression: absence of evidence must not be reported as a pass."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _run_multi(tmp_path, monkeypatch, dsh=None, mcp=None):
    import canari.baseline as bl
    monkeypatch.setattr(bl, "enumerate_top", lambda limit=50, dedupe=True: [])
    monkeypatch.setattr(bl, "pypi_enumerate", lambda limit=500, cache_path=None: [])
    monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda limit=500: mcp or [])
    monkeypatch.setattr(bl, "dsh_enumerate", lambda limit=500, with_security=True: dsh or [])
    monkeypatch.setattr(bl, "_runner_source_digest", lambda: "d" * 64)
    bl.run_multi(npm_limit=0, pypi_limit=0, registry_limit=len(mcp or []),
                 dsh_limit=len(dsh or []), out_dir=str(tmp_path))
    out = {}
    for f in tmp_path.joinpath("attestations").glob("*.bundle.json"):
        p = json.loads(f.read_text(encoding="utf-8"))["payload"]
        out[p["subject"]["name"]] = p
    return out


class TestNoVerdictInflation:
    def test_dsh_without_data_is_unsupported(self, tmp_path, monkeypatch):
        out = _run_multi(tmp_path, monkeypatch, dsh=[{"name": "bare", "version": "1"}])
        assert out["bare"]["verdict"] == "unsupported"

    def test_dsh_with_security_data_still_passes(self, tmp_path, monkeypatch):
        out = _run_multi(tmp_path, monkeypatch, dsh=[{
            "name": "ok", "version": "1", "install_verdict": "passed",
            "security_critical": 0, "security_files_scanned": 3, "security_scanner": "s"}])
        assert out["ok"]["verdict"] == "pass-with-findings"

    def test_dsh_with_critical_still_fails(self, tmp_path, monkeypatch):
        out = _run_multi(tmp_path, monkeypatch, dsh=[{
            "name": "bad", "version": "1", "install_verdict": "passed",
            "security_critical": 2}])
        assert out["bad"]["verdict"] == "fail"

    def test_mcp_presence_only_is_unsupported(self, tmp_path, monkeypatch):
        out = _run_multi(tmp_path, monkeypatch, mcp=[{"name": "mcp/x", "version": "1.0"}])
        p = out["mcp/x"]
        assert p["verdict"] == "unsupported"
        ids = {c["id"]: c["verdict"] for c in p["checks"]}
        assert ids["L2.0_ARTIFACT_UNVERIFIED"] == "unsupported"


class TestGateBlocksUnsupported:
    def test_gate_does_not_allow_unsupported(self):
        from canari.schema import is_gate_passing
        assert is_gate_passing({"verdict": "unsupported"}) is False

    def test_verdict_semantics_documented(self):
        from canari.schema import verdict_semantics
        sem = verdict_semantics()
        assert set(sem) == {"pass", "pass-with-findings", "fail", "unsupported", "error"}
        assert "NOT a pass" in sem["unsupported"]
