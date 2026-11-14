# -*- coding: utf-8 -*-
"""Coverage pass 6: remaining branches - schema, gate policies, verify_cli
internals, npm_enum edge paths, pypi_native success path, scanner_adapter
subprocess paths, consumer/drift leftovers."""
import base64
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


class TestSchemaMore:
    def test_gate_passing_matrix(self):
        from canari.schema import is_gate_passing
        # 2026-11-14: a passing verdict ALSO requires artifact evidence. A record
        # whose only check is "the name exists in a registry" must not pass.
        art = [{"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "t"}]
        assert is_gate_passing({"verdict": "pass", "checks": art})
        assert is_gate_passing({"verdict": "pass-with-findings", "checks": art})
        for v in ("fail", "error", "unsupported", "", None):
            assert not is_gate_passing({"verdict": v, "checks": art})
        # no artifact evidence -> never passing, whatever the verdict says
        assert not is_gate_passing({"verdict": "pass", "checks": []})
        assert not is_gate_passing(
            {"verdict": "pass", "checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass"}]})

    def test_unverified_reason_helper(self):
        from canari.schema import assert_unverified_has_reason
        assert_unverified_has_reason({"checks": [
            {"id": "x", "verdict": "unsupported", "tool": "t", "evidence_ref": ""}]})
        assert_unverified_has_reason({"checks": []}) is None
        assert_unverified_has_reason({}) is None


class TestGatePoliciesMore:
    def _bundle(self, tmp_path, checks=None, verdict="pass"):
        from canari.signing import generate_keypair, sign_attestation
        signer, pub = generate_keypair()
        att = {"_type": V,
               "subject": {"name": "p", "version": "1", "registry": "npm",
                           "artifact_sha256": "a" * 64, "maintainers": []},
               "host": {"class": "mcp", "host_version": "t"},
               "scenario_sha256": "b" * 64,
               "checks": checks or [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t"},
                                  {"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "t"}],
               "verdict": verdict, "checker": {"kind": "automation", "id": "t"},
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
        return str(bp), str(kp)

    def test_require_native_provenance(self, tmp_path):
        from canari.gate import evaluate_gate
        bp, kp = self._bundle(tmp_path)
        d = evaluate_gate(bp, key_path=kp, policy_name="release-gate")
        assert d.decision in ("REVIEW", "BLOCK")

    def test_allowed_registries(self, tmp_path):
        from canari.gate import evaluate_gate
        bp, kp = self._bundle(tmp_path)
        d = evaluate_gate(bp, key_path=kp,
                          policy_overrides={"allowed_registries": ["pypi"]})
        assert d.decision == "BLOCK"

    def test_block_finding_kinds(self, tmp_path):
        from canari.gate import evaluate_gate
        bp, kp = self._bundle(tmp_path, checks=[
            {"id": "L2.4_RELEASE_CADENCE", "verdict": "pass", "tool": "t",
             "evidence_ref": "finding: release_burst"}], verdict="pass-with-findings")
        d = evaluate_gate(bp, key_path=kp,
                          policy_overrides={"block_finding_kinds": ["release_burst"]})
        assert d.decision == "BLOCK"

    def test_missing_key_registry_path_ignored(self, tmp_path):
        from canari.gate import evaluate_gate
        bp, kp = self._bundle(tmp_path)
        d = evaluate_gate(bp, key_path=kp, key_registry_path=str(tmp_path / "none.json"))
        assert d.decision == "ALLOW"

    def test_no_expiry_is_not_fresh(self, tmp_path):
        # F10 (BUG-104): a missing expires_at used to count as "fresh", so a
        # bundle with no expiry stayed ALLOWable forever under strict policies.
        # Absence of a freshness record is not evidence of freshness.
        from canari.gate import _check_freshness
        fresh, reason = _check_freshness({})
        assert fresh is False
        assert "expires_at" in reason

    def test_policy_file_bad_types(self, tmp_path):
        from canari.gate import load_policy_file
        for bad in ({"allowed_registries": "x"}, {"block_finding_kinds": "x"},
                    {"require_fresh": "yes"}, {"allow_findings": 1}):
            p = tmp_path / "p.json"
            p.write_text(json.dumps(bad), encoding="utf-8")
            with pytest.raises(ValueError):
                load_policy_file(str(p))

    def test_policy_file_not_object(self, tmp_path):
        from canari.gate import load_policy_file
        p = tmp_path / "p.json"
        p.write_text("[1,2]", encoding="utf-8")
        with pytest.raises(ValueError):
            load_policy_file(str(p))


class TestVerifyCliInternals:
    def test_independent_verify_errors(self):
        from canari.verify_cli import _independent_verify
        assert _independent_verify({}, {})[0] is False
        assert _independent_verify({"payloadType": "x", "payload": ""}, {})[0] is False
        assert _independent_verify({"payloadType": "x", "payload": "!!!"}, {})[0] is False
        bad_json = base64.b64encode(b"not json").decode()
        assert _independent_verify({"payloadType": "x", "payload": bad_json}, {})[0] is False
        good = base64.b64encode(b"{}").decode()
        ok, detail = _independent_verify({"payloadType": "wrong", "payload": good}, {})
        assert ok is False and "payloadType" in detail

    def test_verify_chain_self_reference(self, tmp_path):
        from canari.verify_cli import verify_chain
        import hashlib
        ad = tmp_path / "attestations"
        ad.mkdir()
        p = {"subject": {"name": "p", "version": "1", "registry": "npm",
                         "artifact_sha256": "a" * 64}, "verdict": "pass",
             "checks": [{"id": "X", "verdict": "pass", "tool": "t"}],
             "generated_at": "2026-11-10T00:00:00Z"}
        d = hashlib.sha256(json.dumps(p, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        p["supersedes"] = d  # points at itself
        (ad / "self.bundle.json").write_text(json.dumps({"payload": p}), encoding="utf-8")
        assert verify_chain(str(ad)) == 4

    def test_main_chain_flag(self, tmp_path):
        from canari.verify_cli import main
        ad = tmp_path / "attestations"
        ad.mkdir()
        assert main(["--chain", str(ad)]) == 0


class TestNpmEnumMore:
    def test_fetch_simple_index_caches(self, tmp_path, monkeypatch):
        import canari.npm_enum as ne
        body = b"<a>mcp-a</a>"
        monkeypatch.setattr(ne, "_opener", lambda: Op([("pypi.org/simple/", body)]))
        cache = str(tmp_path / "s.html")
        assert ne.fetch_simple_index(cache_path=cache) == body.decode()
        # second call must not hit network
        monkeypatch.setattr(ne, "_opener", lambda: (_ for _ in ()).throw(OSError("no net")))
        assert ne.fetch_simple_index(cache_path=cache) == body.decode()

    def test_enumerate_top_paginates(self, monkeypatch):
        import canari.npm_enum as ne
        pages = [
            json.dumps({"objects": [{"package": {"name": "a", "description": "",
                                                 "links": {}, "version": "1"}}],
                        "total": 2}).encode(),
            json.dumps({"objects": [{"package": {"name": "b", "description": "",
                                                 "links": {}, "version": "1"}}],
                        "total": 2}).encode(),
        ]
        state = {"i": 0}
        class _Op:
            def open(self, req, timeout=None):
                out = pages[min(state["i"], 1)]
                state["i"] += 1
                return R(out)
        monkeypatch.setattr(ne, "_opener", lambda: _Op())
        out = ne.enumerate_top(limit=10)
        assert {x["name"] for x in out} == {"a", "b"}

    def test_npm_search_retry_then_success(self, monkeypatch):
        import canari.npm_enum as ne
        calls = {"n": 0}
        body = json.dumps({"objects": [], "total": 0}).encode()
        class _Op:
            def open(self, req, timeout=None):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise OSError("flaky")
                return R(body)
        monkeypatch.setattr(ne, "_opener", lambda: _Op())
        assert ne.npm_search("x", retries=2)["total"] == 0

    def test_dsh_without_author(self, monkeypatch):
        import canari.npm_enum as ne
        market = json.dumps({"plugins": [{"name": "p", "author": ""}]}).encode()
        monkeypatch.setattr(ne, "_opener", lambda: Op([("cdn.dsh.so", market)]))
        out = ne.dsh_enumerate(limit=2)
        assert len(out) == 1 and "install_verdict" not in out[0]


class TestPypiNativeMore:
    def test_fetch_success(self, monkeypatch):
        import canari.pypi_native as pn
        body = json.dumps({"urls": [
            {"filename": "f.whl", "digests": {"sha256": "d"},
             "attestations": [{"predicateType": "x"}]},
            {"filename": "g.whl", "digests": {"sha256": "e"}}]}).encode()
        monkeypatch.setattr(pn, "_opener", lambda: Op([("pypi.org", body)]))
        files = pn.fetch_pypi_attestations("p")
        assert files and files[0]["filename"] == "f.whl"

    def test_verify_bundle_ok_and_fail(self, monkeypatch):
        import canari.pypi_native as pn
        class V:
            @staticmethod
            def production():
                class Ver:
                    def verify_dsse(self, bundle, policy):
                        return ("t", b"")
                return Ver()
        # success path via patched sigstore modules
        import types
        fake_verify = types.SimpleNamespace(Verifier=V, policy=types.SimpleNamespace(UnsafeNoOp=lambda: None))
        monkeypatch.setitem(sys.modules, "sigstore.verify", fake_verify)
        monkeypatch.setitem(sys.modules, "sigstore.verify.policy",
                            types.SimpleNamespace(UnsafeNoOp=lambda: None))
        out = pn.verify_pypi_bundle("B")
        assert out["ok"] is True


class TestScannerSubprocess:
    def _scanner(self, tmp_path, body):
        root = tmp_path / "scanner"
        s = root / "scripts"
        s.mkdir(parents=True)
        (s / "aggregate_json.py").write_text("", encoding="utf-8")
        (s / "auto_scan.py").write_text(
            "import sys\nprint(%r)\n" % body, encoding="utf-8")
        return str(root)

    def test_windows_path_parses_json(self, tmp_path):
        from canari.scanner_adapter import run_repo_forensics
        root = self._scanner(tmp_path, '{"summary": {"total": 0}, "scanner_count": 1}')
        r = run_repo_forensics(str(tmp_path), scanner_root=root)
        assert r.get("summary", {}).get("total") == 0 and "_canari_source_digest" in r

    def test_bad_json(self, tmp_path):
        from canari.scanner_adapter import run_repo_forensics
        root = self._scanner(tmp_path, "not json at all")
        r = run_repo_forensics(str(tmp_path), scanner_root=root)
        assert "error" in r


class TestConsumerLeftovers:
    def test_skips_unreadable_bundle(self, tmp_path):
        from canari.consumer import iter_bundles, list_components
        ad = tmp_path / "attestations"
        ad.mkdir()
        (ad / "bad.bundle.json").write_text("{oops", encoding="utf-8")
        assert list(iter_bundles(str(tmp_path))) == []
        assert list_components(str(tmp_path)) == []

    def test_version_miss(self, tmp_path):
        from canari.consumer import latest_attestation
        ad = tmp_path / "attestations"
        ad.mkdir()
        p = {"subject": {"name": "p", "version": "1", "registry": "npm"},
             "generated_at": "2026-11-10T00:00:00Z"}
        (ad / "a.bundle.json").write_text(json.dumps({"payload": p}), encoding="utf-8")
        assert latest_attestation(str(tmp_path), "npm", "p", version="9") is None

