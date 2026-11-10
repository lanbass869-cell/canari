# -*- coding: utf-8 -*-
"""Final coverage push: remaining reachable branches."""
import io as _io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
V = "https://agentcheck.dev/attestation/v0.1"


class R(_io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def Op(mapping):
    class _Op:
        def open(self, req, timeout=None):
            url = getattr(req, "full_url", str(req))
            for sub, payload in mapping:
                if sub in url:
                    if isinstance(payload, Exception):
                        raise payload
                    return R(payload)
            raise OSError("no mock " + url)
    return _Op()


class TestNpmEnumFinal:
    def test_search_zero_retries_returns_none(self):
        import canari.npm_enum as ne
        assert ne.npm_search("x", retries=0) is None

    def test_pypi_zero_limit(self):
        import canari.npm_enum as ne
        assert ne.pypi_enumerate(limit=0) == []

    def test_pypi_fallback_dataset(self, monkeypatch):
        import canari.npm_enum as ne
        fb = json.dumps({"rows": [{"project": "mcp-server-q"}, {"project": "other"}]}).encode()
        pkg = json.dumps({"info": {"version": "1", "author": "a", "home_page": "h"},
                          "urls": [{"digests": {"sha256": "c" * 64}, "url": "f"}]}).encode()
        class _Op:
            def open(self, req, timeout=None):
                u = req.full_url
                if "/simple" in u:
                    raise OSError("index down")
                if "top-pypi-packages" in u:
                    return R(fb)
                return R(pkg)
        monkeypatch.setattr(ne, "_opener", lambda: _Op())
        out = ne.pypi_enumerate(prefix="mcp-server-", limit=5)
        assert out and out[0]["name"] == "mcp-server-q"

    def test_mcp_limit_reached_and_equal_versions(self, monkeypatch):
        import canari.npm_enum as ne
        page = json.dumps({"servers": [
            {"server": {"name": "a/one", "version": "1.0"}},
            {"server": {"name": "a/one", "version": "1.0"}},
            {"server": {"name": "b/two", "version": "1.0"}},
        ], "metadata": {"nextCursor": "c"}}).encode()
        monkeypatch.setattr(ne, "_opener", lambda: Op([("registry.modelcontextprotocol", page)]))
        out = ne.mcp_registry_enumerate(limit=1)
        assert len(out) == 1


class TestVerifyCliFinal:
    def _mk(self, tmp_path, checks=None, verdict="pass", with_env=True):
        from canari.signing import generate_keypair, sign_attestation
        signer, pub = generate_keypair()
        att = {"_type": V,
               "subject": {"name": "p", "version": "1", "registry": "npm",
                           "artifact_sha256": "a" * 64, "maintainers": []},
               "host": {"class": "mcp", "host_version": "t"},
               "scenario_sha256": "b" * 64,
               "checks": checks or [{"id": "L1.1", "verdict": "pass", "tool": "t"}],
               "verdict": verdict, "checker": {"kind": "automation", "id": "t"},
               "evidence_refs": [],
               "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                         "truncated_fields": []},
               "expires_at": "2026-12-30T00:00:00Z", "generated_at": "2026-11-10T00:00:00Z",
               "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": V}}
        s = sign_attestation(att, signer)
        bp = tmp_path / "b.json"
        body = {"envelope": s["envelope"], "payload": s["payload"]} if with_env else {"payload": s["payload"]}
        bp.write_text(json.dumps(body), encoding="utf-8")
        kp = tmp_path / "k.json"
        kp.write_text(json.dumps(pub.to_dict()), encoding="utf-8")
        return str(bp), str(kp)

    def test_no_envelope(self, tmp_path):
        from canari.verify_cli import verify_bundle
        bp, kp = self._mk(tmp_path, with_env=False)
        assert verify_bundle(bp, kp) == 3

    def test_fail_check_counted(self, tmp_path):
        from canari.verify_cli import verify_bundle
        bp, kp = self._mk(tmp_path, checks=[{"id": "X", "verdict": "fail", "tool": "t"}],
                          verdict="fail")
        assert verify_bundle(bp, kp) == 0  # schema ok; verdict fail is printed, not exit

    def test_gate_block_and_review(self, tmp_path):
        from canari.verify_cli import verify_bundle
        bp, kp = self._mk(tmp_path, verdict="fail")
        assert verify_bundle(bp, kp, gate=True) == 5
        bp2, kp2 = self._mk(tmp_path, verdict="pass-with-findings")
        assert verify_bundle(bp2, kp2, gate=True) == 6

    def test_single_bundle_cross_component_pointer(self, tmp_path):
        """A single bundle superseding another component's digest is legal."""
        from canari.verify_cli import verify_chain
        import hashlib
        ad = tmp_path / "attestations"
        ad.mkdir()
        base = {"subject": {"name": "a", "version": "1", "registry": "npm",
                            "artifact_sha256": "a" * 64}, "verdict": "pass",
                "checks": [{"id": "X", "verdict": "pass", "tool": "t"}],
                "generated_at": "2026-11-10T00:00:00Z"}
        other = dict(base, subject={"name": "b", "version": "1", "registry": "npm",
                                    "artifact_sha256": "b" * 64})
        d_other = hashlib.sha256(json.dumps(other, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        a = dict(base, supersedes=d_other)
        # b has no supersedes -> head; a single-bundle component points at b's digest
        (ad / "a1.bundle.json").write_text(json.dumps({"payload": a}), encoding="utf-8")
        (ad / "b1.bundle.json").write_text(json.dumps({"payload": other}), encoding="utf-8")
        assert verify_chain(str(ad)) == 0
