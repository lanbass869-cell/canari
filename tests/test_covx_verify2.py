# -*- coding: utf-8 -*-
"""Coverage push: verify_cli remaining branches."""
import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
V = "https://agentcheck.dev/attestation/v0.1"


def _mk(tmp_path, name="p", checks=None, verdict="pass", fname="a.bundle.json",
        expires="2026-12-30T00:00:00Z"):
    from canari.signing import generate_keypair, sign_attestation
    signer, pub = generate_keypair()
    att = {"_type": V,
           "subject": {"name": name, "version": "1", "registry": "npm",
                       "artifact_sha256": "a" * 64, "maintainers": []},
           "host": {"class": "mcp", "host_version": "t"},
           "scenario_sha256": "b" * 64,
           "checks": checks or [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t"},
                                  {"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "t"}],
           "verdict": verdict, "checker": {"kind": "automation", "id": "t"},
           "evidence_refs": [],
           "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                     "truncated_fields": []},
           "expires_at": expires, "generated_at": "2026-11-10T00:00:00Z",
           "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": V}}
    s = sign_attestation(att, signer)
    ad = tmp_path / "attestations"
    ad.mkdir(exist_ok=True)
    fp = ad / fname
    fp.write_text(json.dumps({"envelope": s["envelope"], "payload": s["payload"]}),
                  encoding="utf-8")
    kp = tmp_path / "pub.json"
    kp.write_text(json.dumps(pub.to_dict()), encoding="utf-8")
    return str(fp), str(kp)


def _signed_bundle_file(path, payload):
    import json as _json
    from canari.signing import generate_keypair, sign_attestation
    base = {"_type": "https://agentcheck.dev/attestation/v0.1",
            "subject": payload.get("subject", {}),
            "host": {"class": "mcp", "host_version": "t"},
            "scenario_sha256": "a" * 64,
            "checks": payload.get("checks", []),
            "checker": {"kind": "automation", "id": "t"},
            "evidence_refs": [],
            "evidence_completeness": {"dropped_logs": 0,
                                      "missing_observers": [],
                                      "truncated_fields": []},
            "expires_at": "2027-01-01T00:00:00Z",
            "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                          "payload_type": ""}}
    base.update(payload)
    signer, _pub = generate_keypair()
    s = sign_attestation(base, signer)
    path.write_text(_json.dumps({"envelope": s["envelope"],
                                 "payload": s["payload"]}), encoding="utf-8")

class TestVerifyBundleBranches:
    def test_bad_key_json(self, tmp_path, capsys):
        from canari.verify_cli import verify_bundle
        bp, _ = _mk(tmp_path)
        kp = tmp_path / "bad.json"
        kp.write_text("{not json", encoding="utf-8")
        assert verify_bundle(bp, str(kp)) == 3

    def test_noncanonical_payload_rejected(self, tmp_path):
        from canari.signing import generate_keypair, DSSE_PAYLOAD_TYPE
        from canari.verify_cli import verify_bundle, _independent_pae
        signer, pub = generate_keypair()
        payload = {"_type": V, "subject": {"name": "p", "version": "1", "registry": "npm",
                                           "artifact_sha256": "a" * 64, "maintainers": []},
                   "host": {"class": "mcp", "host_version": "t"},
                   "scenario_sha256": "b" * 64,
                   "checks": [{"id": "L1.1", "verdict": "pass", "tool": "t"}],
                   "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
                   "evidence_refs": [],
                   "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                             "truncated_fields": []},
                   "expires_at": "2026-12-30T00:00:00Z",
                   "generated_at": "2026-11-10T00:00:00Z",
                   "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                                 "payload_type": V}}
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=False).encode()
        from in_toto.models.metadata import Envelope
        env_obj = Envelope(payload=raw, payload_type=DSSE_PAYLOAD_TYPE, signatures={})
        env_obj.sign(signer)  # signs in place; returns a Signature object
        env = env_obj.to_dict()
        bp = tmp_path / "b.json"
        bp.write_text(json.dumps({"envelope": env, "payload": payload}), encoding="utf-8")
        kp = tmp_path / "k.json"
        kp.write_text(json.dumps(pub.to_dict()), encoding="utf-8")
        assert verify_bundle(str(bp), str(kp)) == 1

    def test_verbose_counts_all_verdicts(self, tmp_path):
        from canari.verify_cli import verify_bundle
        checks = [{"id": "A", "verdict": "pass", "tool": "t"},
                  {"id": "B", "verdict": "skip", "tool": "t"},
                  {"id": "C", "verdict": "unsupported", "tool": "t", "evidence_ref": "why"},
                  {"id": "D", "verdict": "error", "tool": "t", "evidence_ref": "boom"}]
        bp, kp = _mk(tmp_path, checks=checks, verdict="pass-with-findings")
        assert verify_bundle(bp, kp, verbose=True) == 0

    def test_gate_policy_file(self, tmp_path):
        from canari.verify_cli import verify_bundle
        bp, kp = _mk(tmp_path)
        pf = tmp_path / "p.json"
        pf.write_text(json.dumps({"name": "x", "block_on_findings": True}), encoding="utf-8")
        assert verify_bundle(bp, kp, gate=True, gate_policy_file=str(pf)) == 0


class TestChainBranches:
    def test_unparsable_bundle_is_an_error(self, tmp_path):
        # F3 (BUG-104): a file we cannot interpret used to be skipped and the
        # audit still printed "all valid", so corruption could hide silently.
        # It must now fail the chain audit.
        from canari.verify_cli import verify_chain
        ad = tmp_path / "attestations"
        ad.mkdir()
        (ad / "bad.bundle.json").write_text("{broken", encoding="utf-8")
        assert verify_chain(str(ad), require_signatures=False) == 4

    def test_single_no_supersedes_ok(self, tmp_path):
        from canari.verify_cli import verify_chain
        _mk(tmp_path, fname="a.bundle.json")
        assert verify_chain(str(tmp_path / "attestations"), require_signatures=False) == 0

    def test_single_self_pointer_errors(self, tmp_path):
        from canari.verify_cli import verify_chain
        import hashlib
        ad = tmp_path / "attestations"
        ad.mkdir()
        p = {"subject": {"name": "p", "version": "1", "registry": "npm",
                         "artifact_sha256": "a" * 64}, "verdict": "pass",
             "checks": [{"id": "X", "verdict": "pass", "tool": "t"}],
             "generated_at": "2026-11-10T00:00:00Z"}
        d = hashlib.sha256(json.dumps(p, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        p["supersedes"] = d
        _signed_bundle_file(ad / "s.bundle.json", p)
        assert verify_chain(str(ad), require_signatures=False) == 4

    def test_no_head_cycle(self, tmp_path):
        from canari.verify_cli import verify_chain
        ad = tmp_path / "attestations"
        ad.mkdir()
        base = {"subject": {"name": "p", "version": "1", "registry": "npm",
                            "artifact_sha256": "a" * 64}, "verdict": "pass",
                "checks": [{"id": "X", "verdict": "pass", "tool": "t"}],
                "generated_at": "2026-11-10T00:00:00Z"}
        a = dict(base, supersedes="0" * 64)
        b = dict(base, supersedes="1" * 64)
        _signed_bundle_file(ad / "a.bundle.json", a)
        _signed_bundle_file(ad / "b.bundle.json", b)
        assert verify_chain(str(ad), require_signatures=False) == 4

    def test_diamond_dag(self, tmp_path):
        from canari.verify_cli import verify_chain
        import hashlib
        ad = tmp_path / "attestations"
        ad.mkdir()
        # The producer defines a supersedes digest with payload_digest(), which
        # canonically hashes the attestation EXCLUDING the inline signature
        # block (so re-signing cannot orphan the chain).
        import json as _json
        from canari.signing import payload_digest
        base = {"subject": {"name": "p", "version": "1", "registry": "npm",
                            "artifact_sha256": "a" * 64}, "verdict": "pass",
                "checks": [{"id": "X", "verdict": "pass", "tool": "t"}],
                "generated_at": "2026-11-10T00:00:00Z"}
        _signed_bundle_file(ad / "0.bundle.json", base)
        hd = payload_digest(_json.loads(
            (ad / "0.bundle.json").read_text(encoding="utf-8"))["payload"])
        parent = tmp_path / "attestations"
        _signed_bundle_file(ad / "1.bundle.json",
                            dict(base, generated_at="2026-11-11T00:00:00Z",
                                 supersedes=hd))
        d1 = payload_digest(_json.loads(
            (ad / "1.bundle.json").read_text(encoding="utf-8"))["payload"])
        _signed_bundle_file(ad / "2.bundle.json",
                            dict(base, generated_at="2026-11-12T00:00:00Z",
                                 supersedes=hd))
        _signed_bundle_file(ad / "3.bundle.json",
                            dict(base, generated_at="2026-11-13T00:00:00Z",
                                 supersedes=d1))
        # both children hang off head; leaf extends the c1 branch -> all reachable
        assert verify_chain(str(ad), require_signatures=False) == 0


class TestMainBranches:
    def test_chain_flag(self, tmp_path):
        from canari.verify_cli import main
        ad = tmp_path / "attestations"
        ad.mkdir()
        assert main(["--chain", str(ad)]) == 0

    def test_missing_args_errors(self):
        from canari.verify_cli import main
        with pytest.raises(SystemExit):
            main([])

    def test_missing_dir_returns_3(self, tmp_path):
        from canari.verify_cli import verify_chain
        assert verify_chain(str(tmp_path / "nope")) == 3
