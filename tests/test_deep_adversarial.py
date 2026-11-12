# -*- coding: utf-8 -*-
"""Adversarial tests: signature games, key lifecycle, path traversal, atomic
writes, oversized payloads, MCP garbage input."""
import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
V = "https://agentcheck.dev/attestation/v0.1"


def _signed(name="t"):
    from canari.signing import generate_keypair, sign_attestation
    signer, pub = generate_keypair()
    att = {"_type": V,
           "subject": {"name": name, "version": "1", "registry": "npm",
                       "artifact_sha256": "a" * 64, "maintainers": []},
           "host": {"class": "mcp", "host_version": "t"},
           "scenario_sha256": "b" * 64,
           "checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t/0.1"}],
           "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
           "evidence_refs": [],
           "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                     "truncated_fields": []},
           "expires_at": "2026-12-30T00:00:00Z", "generated_at": "2026-11-10T00:00:00Z",
           "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": V}}
    return sign_attestation(att, signer), pub


class TestSignatureGames:
    def test_keyid_spoof_breaks_signature(self):
        from canari.signing import verify_signed
        signed, pub = _signed()
        env = json.loads(json.dumps(signed["envelope"]))
        # rewriting keyid inside the payload must invalidate the signature
        payload = json.loads(base64.b64decode(env["payload"]))
        # DSSE payload is an in-toto Statement v1; the attestation (and its
        # inline signature block) lives in `predicate`.
        payload["predicate"]["signature"]["keyid"] = "00" * 32
        env["payload"] = base64.b64encode(json.dumps(
            payload, ensure_ascii=False, sort_keys=True).encode()).decode()
        assert verify_signed(env, pub.to_dict())[0] is False

    def test_payload_swap_between_bundles(self):
        from canari.signing import verify_signed
        a, pa = _signed("a")
        b, pb = _signed("b")
        env = json.loads(json.dumps(a["envelope"]))
        env["payload"] = b["envelope"]["payload"]  # B's payload under A's sig
        assert verify_signed(env, pa.to_dict())[0] is False

    def test_truncated_signature(self):
        from canari.signing import verify_signed
        signed, pub = _signed()
        env = json.loads(json.dumps(signed["envelope"]))
        sig = env["signatures"][0]["sig"]
        env["signatures"][0]["sig"] = sig[:-8]
        assert verify_signed(env, pub.to_dict())[0] is False

    def test_wrong_payload_type(self):
        from canari.signing import verify_signed
        signed, pub = _signed()
        env = json.loads(json.dumps(signed["envelope"]))
        env["payloadType"] = "application/json"
        assert verify_signed(env, pub.to_dict())[0] is False


class TestKeyLifecycle:
    def _bundle(self, tmp_path):
        signed, pub = _signed()
        bp = tmp_path / "b.json"
        bp.write_text(json.dumps({"envelope": signed["envelope"],
                                  "payload": signed["payload"]}), encoding="utf-8")
        kp = tmp_path / "k.json"
        kp.write_text(json.dumps(pub.to_dict()), encoding="utf-8")
        return str(bp), str(kp), pub

    def test_revoked_key_blocks(self, tmp_path):
        from canari.signing import create_key_registry_entry, revoke_key, save_key_registry
        from canari.gate import evaluate_gate
        bp, kp, pub = self._bundle(tmp_path)
        reg = revoke_key(create_key_registry_entry(pub, str(tmp_path / "priv.pem")), "leak")
        rp = str(tmp_path / "reg.json")
        save_key_registry(reg, rp)
        assert evaluate_gate(bp, key_path=kp, key_registry_path=rp).decision == "BLOCK"

    def test_expired_key_blocks(self, tmp_path):
        from canari.signing import create_key_registry_entry, save_key_registry, is_key_valid
        from canari.gate import evaluate_gate
        bp, kp, pub = self._bundle(tmp_path)
        reg = create_key_registry_entry(pub, str(tmp_path / "priv.pem"))
        reg["valid_until"] = "2020-01-01T00:00:00Z"
        rp = str(tmp_path / "reg.json")
        save_key_registry(reg, rp)
        assert is_key_valid(reg)[0] is False
        assert evaluate_gate(bp, key_path=kp, key_registry_path=rp).decision == "BLOCK"


class TestPathTraversal:
    def test_bundle_filename_sanitised(self, tmp_path, monkeypatch):
        import canari.baseline as bl
        # any attempt to escape the attestations dir must be neutralised
        monkeypatch.setattr(bl, "enumerate_top", lambda limit=50, dedupe=True: [])
        monkeypatch.setattr(bl, "pypi_enumerate", lambda limit=500, cache_path=None: [])
        monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda limit=500: [])
        monkeypatch.setattr(bl, "dsh_enumerate", lambda limit=500, with_security=True: [{
            "name": "../../../evil", "version": "1", "registry": "dsh-registry"}])
        monkeypatch.setattr(bl, "_runner_source_digest", lambda: "d" * 64)
        bl.run_multi(npm_limit=0, pypi_limit=0, registry_limit=0, dsh_limit=1,
                     out_dir=str(tmp_path))
        produced = [str(p) for p in tmp_path.joinpath("attestations").glob("*.bundle.json")]
        assert produced, "expected a bundle"
        assert all(os.path.abspath(p).startswith(os.path.abspath(str(tmp_path))) for p in produced)


class TestAtomicWrites:
    def test_no_partial_bundle_on_crash(self, tmp_path, monkeypatch):
        """json.dump raising mid-write must not leave a .bundle.json behind."""
        import canari.baseline as bl
        monkeypatch.setattr(bl, "enumerate_top", lambda limit=50, dedupe=True: [])
        monkeypatch.setattr(bl, "pypi_enumerate", lambda limit=500, cache_path=None: [])
        monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda limit=500: [])
        monkeypatch.setattr(bl, "dsh_enumerate", lambda limit=500, with_security=True: [{
            "name": "ok", "version": "1", "registry": "dsh-registry"}])
        monkeypatch.setattr(bl, "_runner_source_digest", lambda: "d" * 64)
        real_dump = json.dump
        calls = {"n": 0}
        def boom(obj, fp, **kw):
            calls["n"] += 1
            if calls["n"] == 2:  # feed write succeeds, bundle write explodes
                raise OSError("disk full")
            return real_dump(obj, fp, **kw)
        # patch inside the module's json reference
        monkeypatch.setattr(bl.json, "dump", boom)
        try:
            bl.run_multi(npm_limit=0, pypi_limit=0, registry_limit=0, dsh_limit=1,
                         out_dir=str(tmp_path))
        except OSError:
            pass
        leftovers = list(tmp_path.joinpath("attestations").glob("*.bundle.json"))
        tmps = list(tmp_path.joinpath("attestations").glob("*.tmp"))
        assert leftovers == [], "partial bundle must not be published"
        assert tmps, "tmp file proves the atomic path was used"


class TestOversized:
    def test_10mb_payload_sign_verify(self):
        from canari.signing import sign_attestation, verify_signed
        signed, pub = _signed()
        big = "x" * (10 * 1024 * 1024)
        signed["payload"]["evidence_refs"] = [big]  # bare attestation body
        from canari.signing import sign_attestation as sa
        # re-sign the large payload with a fresh signer
        from canari.signing import generate_keypair
        s2, p2 = generate_keypair()
        payload = dict(signed["payload"])
        out = sa(payload, s2)
        ok, _, err = verify_signed(out["envelope"], p2.to_dict())
        assert ok, err


class TestMCPGarbage:
    def test_malformed_lines_ignored(self):
        import io as _io
        from canari.mcp_server import serve
        stdin = _io.StringIO("not json\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
        out = _io.StringIO()
        serve(stdin=stdin, stdout=out, store="out")
        lines = [l for l in out.getvalue().splitlines() if l.strip()]
        assert len(lines) == 1
        assert json.loads(lines[0])["result"] == {}

    def test_unknown_tool_errors(self):
        from canari.mcp_server import _handle
        r = _handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "nope", "arguments": {}}}, "out", None)
        assert "error" in r
