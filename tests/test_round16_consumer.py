# -*- coding: utf-8 -*-
"""Round 16: consumer lookup + gate CLI + drift report + MCP server."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk_bundle(tmp_path, name, version, verdict, checks=None, gen="2026-11-09T00:00:00Z",
               sha="a" * 64, registry="npm", fname=None):
    """Bundle + matching public key, i.e. what a real store ships.

    The gate fails closed without a key (2026-11-13), so fixtures must publish
    the key they signed with instead of relying on an unsigned ALLOW.
    """
    from canari.signing import generate_keypair, sign_attestation, export_public_key
    signer, pub = generate_keypair()
    att = {"_type": "https://agentcheck.dev/attestation/v0.1",
           "subject": {"name": name, "version": version, "registry": registry,
                       "artifact_sha256": sha, "maintainers": []},
           "host": {"class": "mcp", "host_version": "t"},
           "scenario_sha256": "b" * 64,
           "checks": checks or [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t/0.1"},
                                  {"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "t/0.1"}],
           "verdict": verdict, "checker": {"kind": "automation", "id": "t"},
           "evidence_refs": [],
           "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
           "expires_at": "2026-12-30T00:00:00Z", "generated_at": gen,
           "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                         "payload_type": "https://agentcheck.dev/attestation/v0.1"}}
    s = sign_attestation(att, signer)
    (tmp_path / "public_key.json").write_text(export_public_key(pub), encoding="utf-8")
    ad = tmp_path / "attestations"
    ad.mkdir(exist_ok=True)
    fp = ad / (fname or ("%s_%s_%s.bundle.json" % (registry, name.replace("/", "_"), gen.replace(":", ""))))
    fp.write_text(json.dumps({"envelope": s["envelope"], "payload": s["payload"]}), encoding="utf-8")
    return str(fp), pub.to_dict()


class TestConsumer:
    def test_latest_resolution(self, tmp_path):
        from canari.consumer import latest_attestation
        _mk_bundle(tmp_path, "pkg", "1.0.0", "pass", gen="2026-11-08T00:00:00Z", fname="a.bundle.json")
        _mk_bundle(tmp_path, "pkg", "1.0.1", "fail", gen="2026-11-09T00:00:00Z", fname="b.bundle.json")
        fp, p = latest_attestation(str(tmp_path), "npm", "pkg")
        assert p["subject"]["version"] == "1.0.1"

    def test_version_pin(self, tmp_path):
        from canari.consumer import latest_attestation
        _mk_bundle(tmp_path, "pkg", "1.0.0", "pass", gen="2026-11-08T00:00:00Z", fname="a.bundle.json")
        _mk_bundle(tmp_path, "pkg", "1.0.1", "fail", gen="2026-11-09T00:00:00Z", fname="b.bundle.json")
        fp, p = latest_attestation(str(tmp_path), "npm", "pkg", version="1.0.0")
        assert p["subject"]["version"] == "1.0.0"

    def test_missing_component_blocks(self, tmp_path):
        from canari.consumer import check_component
        r = check_component(str(tmp_path), "npm", "ghost")
        assert r["found"] is False and r["decision"] == "BLOCK"


class TestGateCLI:
    def test_allow_exit_0(self, tmp_path):
        from canari.gate_cli import main
        fp, pub = _mk_bundle(tmp_path, "pkg", "1.0.0", "pass", fname="a.bundle.json")
        key = tmp_path / "k.json"
        key.write_text(json.dumps(pub), encoding="utf-8")
        rc = main(["--store", str(tmp_path), "--registry", "npm", "--name", "pkg",
                   "--key", str(key)])
        assert rc == 0

    def test_block_exit_5(self, tmp_path):
        from canari.gate_cli import main
        fp, pub = _mk_bundle(tmp_path, "pkg", "1.0.0", "fail", fname="a.bundle.json")
        key = tmp_path / "k.json"
        key.write_text(json.dumps(pub), encoding="utf-8")
        rc = main(["--store", str(tmp_path), "--registry", "npm", "--name", "pkg",
                   "--key", str(key)])
        assert rc == 5


class TestDrift:
    def test_verdict_flip(self, tmp_path):
        from canari.drift import compute_drift
        _mk_bundle(tmp_path, "pkg", "1.0.0", "pass", gen="2026-11-08T00:00:00Z", fname="a.bundle.json")
        _mk_bundle(tmp_path, "pkg", "1.0.0", "fail", gen="2026-11-09T00:00:00Z", fname="b.bundle.json")
        rep = compute_drift(str(tmp_path))
        assert len(rep["verdict_flips"]) == 1
        assert rep["verdict_flips"][0]["same_version"] is True

    def test_silent_same_version_hash_change(self, tmp_path):
        from canari.drift import compute_drift
        _mk_bundle(tmp_path, "pkg", "1.0.0", "pass", gen="2026-11-08T00:00:00Z",
                   sha="a" * 64, fname="a.bundle.json")
        _mk_bundle(tmp_path, "pkg", "1.0.0", "pass", gen="2026-11-09T00:00:00Z",
                   sha="c" * 64, fname="b.bundle.json")
        rep = compute_drift(str(tmp_path))
        assert len(rep["silent_changes"]) == 1
        assert rep["silent_changes"][0]["hash_changed"] is True

    def test_findings_added(self, tmp_path):
        from canari.drift import compute_drift
        _mk_bundle(tmp_path, "pkg", "1.0.0", "pass", gen="2026-11-08T00:00:00Z", fname="a.bundle.json")
        _mk_bundle(tmp_path, "pkg", "1.0.0", "pass-with-findings", gen="2026-11-09T00:00:00Z",
                   checks=[{"id": "L2.4_RELEASE_CADENCE", "verdict": "pass", "tool": "t",
                            "evidence_ref": "finding: release_burst"}], fname="b.bundle.json")
        rep = compute_drift(str(tmp_path))
        assert any("L2.4" in ",".join(f["checks"]) for f in rep["findings_added"])


class TestMCPServer:
    def _call(self, msg, store):
        from canari.mcp_server import _handle
        return _handle(msg, store, None)

    def test_initialize(self, tmp_path):
        r = self._call({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {}}, str(tmp_path))
        assert r["result"]["protocolVersion"]
        assert r["result"]["serverInfo"]["name"] == "canari"

    def test_tools_list(self, tmp_path):
        r = self._call({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, str(tmp_path))
        names = {t["name"] for t in r["result"]["tools"]}
        assert names == {"gate_check", "verify_bundle", "store_summary"}

    def test_tools_call_gate(self, tmp_path):
        _mk_bundle(tmp_path, "pkg", "1.0.0", "pass", fname="a.bundle.json")
        r = self._call({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "gate_check",
                                   "arguments": {"registry": "npm", "name": "pkg"}}}, str(tmp_path))
        payload = json.loads(r["result"]["content"][0]["text"])
        assert payload["decision"] == "ALLOW"

    def test_unknown_method_errors(self, tmp_path):
        r = self._call({"jsonrpc": "2.0", "id": 4, "method": "nope"}, str(tmp_path))
        assert r["error"]["code"] == -32601

    def test_notification_no_response(self, tmp_path):
        r = self._call({"jsonrpc": "2.0", "method": "notifications/initialized"}, str(tmp_path))
        assert r is None
