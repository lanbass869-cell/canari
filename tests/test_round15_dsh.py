# -*- coding: utf-8 -*-
"""Round 15: dsh reference checks, run() chain continuity, dead-letter persistence."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _dsh_entry(name, install="passed", critical=0):
    e = {"name": name, "author": "A", "version": "1.0.0", "registry": "dsh-registry"}
    if install is not None:
        e.update({"install_level": "L5", "install_verdict": install,
                  "install_state": install})
    if critical is not None:
        e.update({"security_critical": critical, "security_files_scanned": 10,
                  "security_scanner": "t"})
    return e


class TestDshChecks:
    @pytest.fixture(autouse=True)
    def _mocks(self, tmp_path, monkeypatch):
        import canari.baseline as bl
        monkeypatch.setattr(bl, "enumerate_top", lambda limit=50, dedupe=True: [])
        monkeypatch.setattr(bl, "pypi_enumerate", lambda limit=500: [])
        monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda limit=500: [])
        monkeypatch.setattr(bl, "_runner_source_digest", lambda: "d" * 64)
        self.bl = bl
        self.tmp = tmp_path

    def _run(self, entries):
        self.bl.dsh_enumerate = lambda limit=500, with_security=True: entries
        r = self.bl.run_multi(npm_limit=0, pypi_limit=0, registry_limit=0,
                              dsh_limit=len(entries), out_dir=str(self.tmp))
        out = {}
        for f in self.tmp.joinpath("attestations").glob("dsh_*.bundle.json"):
            p = json.loads(f.read_text(encoding="utf-8"))["payload"]
            out[p["subject"]["name"]] = p
        return out

    def test_all_data_pass(self):
        out = self._run([_dsh_entry("p1")])
        p = out["p1"]
        assert p["verdict"] == "pass-with-findings"
        ids = {c["id"]: c["verdict"] for c in p["checks"]}
        assert ids["L2.8_PLUGIN_INSTALL_REF"] == "pass"
        assert ids["L2.7_PLUGIN_SECURITY_REF"] == "pass"

    def test_critical_blocks(self):
        out = self._run([_dsh_entry("p2", critical=3)])
        assert out["p2"]["verdict"] == "fail"

    def test_missing_data_is_unsupported_with_reason(self):
        out = self._run([_dsh_entry("p3", install=None, critical=None)])
        p = out["p3"]
        cs = {c["id"]: c for c in p["checks"]}
        assert cs["L2.8_PLUGIN_INSTALL_REF"]["verdict"] == "unsupported"
        assert cs["L2.8_PLUGIN_INSTALL_REF"]["evidence_ref"]
        assert cs["L2.7_PLUGIN_SECURITY_REF"]["verdict"] == "unsupported"
        assert cs["L2.7_PLUGIN_SECURITY_REF"]["evidence_ref"]


class TestDeadLetters:
    def test_failures_persisted(self, tmp_path, monkeypatch):
        import canari.baseline as bl
        monkeypatch.setattr(bl, "enumerate_top", lambda limit=50, dedupe=True: [{"name": "bad-pkg"}])
        monkeypatch.setattr(bl, "fetch_packument", lambda name, timeout=90: (_ for _ in ()).throw(OSError("boom")))
        monkeypatch.setattr(bl, "pypi_enumerate", lambda limit=500: [])
        monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda limit=500: [])
        monkeypatch.setattr(bl, "dsh_enumerate", lambda limit=500, with_security=True: [])
        monkeypatch.setattr(bl, "_runner_source_digest", lambda: "d" * 64)
        bl.run_multi(npm_limit=1, pypi_limit=0, registry_limit=0, dsh_limit=0,
                     out_dir=str(tmp_path))
        dl = json.loads((tmp_path / "dead_letters.json").read_text(encoding="utf-8"))
        assert any(e["operation"] == "npm_fetch" and e["target"] == "bad-pkg" for e in dl)
