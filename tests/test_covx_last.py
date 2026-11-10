# -*- coding: utf-8 -*-
"""Last-mile coverage: fallback dataset paths + CLI __main__."""
import io as _io
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class R(_io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


class TestPypiFallbackLastMile:
    def test_no_prefix_match_uses_all_and_error_entry(self, monkeypatch):
        import canari.npm_enum as ne
        fb = json.dumps({"rows": [{"project": "zzz"}, {"project": "yyy"}]}).encode()
        class _Op:
            def open(self, req, timeout=None):
                u = req.full_url
                if "/simple" in u:
                    raise OSError("index down")
                if "top-pypi-packages" in u:
                    return R(fb)
                if "zzz" in u:
                    raise OSError("json down")
                return R(json.dumps({"info": {"version": "1"}, "urls": []}).encode())
        monkeypatch.setattr(ne, "_opener", lambda: _Op())
        out = ne.pypi_enumerate(prefix="mcp-", limit=5)
        names = [x["name"] for x in out]
        assert "zzz" in names and "yyy" in names
        assert any("error" in x for x in out)

    def test_dedupe_lower_version_kept(self, monkeypatch):
        import canari.npm_enum as ne
        page = json.dumps({"servers": [
            {"server": {"name": "a/x", "version": "2.0"}},
            {"server": {"name": "a/x", "version": "1.0"}},
        ], "metadata": {}}).encode()
        class _Op:
            def open(self, req, timeout=None): return R(page)
        monkeypatch.setattr(ne, "_opener", lambda: _Op())
        out = ne.mcp_registry_enumerate(limit=5)
        assert out[0]["version"] == "2.0"


class TestVerifyCliLastMile:
    def test_bad_base64_payload(self):
        from canari.verify_cli import _independent_verify
        ok, detail = _independent_verify({"payloadType": "t", "payload": "%%%notb64%%%"}, {})
        assert ok is False

    def test_main_with_bundle_and_key(self, tmp_path):
        from canari.signing import generate_keypair, sign_attestation
        from canari.verify_cli import main
        signer, pub = generate_keypair()
        V = "https://agentcheck.dev/attestation/v0.1"
        att = {"_type": V, "subject": {"name": "p", "version": "1", "registry": "npm",
                                       "artifact_sha256": "a" * 64, "maintainers": []},
               "host": {"class": "mcp", "host_version": "t"}, "scenario_sha256": "b" * 64,
               "checks": [{"id": "L1.1", "verdict": "pass", "tool": "t"}],
               "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
               "evidence_refs": [],
               "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                         "truncated_fields": []},
               "expires_at": "2026-12-30T00:00:00Z", "generated_at": "2026-11-10T00:00:00Z",
               "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": V}}
        s = sign_attestation(att, signer)
        bp = tmp_path / "b.json"
        bp.write_text(json.dumps({"envelope": s["envelope"], "payload": s["payload"]}),
                      encoding="utf-8")
        kp = tmp_path / "k.json"
        kp.write_text(json.dumps(pub.to_dict()), encoding="utf-8")
        assert main([str(bp), "--key", str(kp)]) == 0

    def test_module_entrypoint_help(self):
        r = subprocess.run([sys.executable, "-m", "canari.verify_cli", "--help"],
                           capture_output=True, text=True,
                           cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        assert r.returncode == 0
