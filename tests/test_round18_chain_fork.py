# -*- coding: utf-8 -*-
"""Round 18: forked supersession (a crashed run + retry both supersede the same
parent) must verify as a DAG, not fail as an unreachable branch."""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk(tmp_path, fname, version, supersedes=None):
    from canari.signing import generate_keypair, sign_attestation
    signer, pub = generate_keypair()
    att = {"_type": "https://agentcheck.dev/attestation/v0.1",
           "subject": {"name": "pkg", "version": version, "registry": "npm",
                       "artifact_sha256": "a" * 64, "maintainers": []},
           "host": {"class": "mcp", "host_version": "t"},
           "scenario_sha256": "b" * 64,
           "checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t/0.1"},
                       {"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "t/0.1"}],
           "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
           "evidence_refs": [],
           "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
           "expires_at": "2026-12-30T00:00:00Z", "generated_at": "2026-11-10T00:00:00Z",
           "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                         "payload_type": "https://agentcheck.dev/attestation/v0.1"}}
    if supersedes:
        att["supersedes"] = supersedes
    s = sign_attestation(att, signer)
    ad = tmp_path / "attestations"
    ad.mkdir(exist_ok=True)
    (ad / fname).write_text(json.dumps({"envelope": s["envelope"], "payload": s["payload"]}),
                            encoding="utf-8")
    # supersession digest is signature-independent (same function the producer
    # and verify_chain use); hashing the inline signature block would break
    # every chain on re-sign.
    from canari.signing import payload_digest
    return payload_digest(s["payload"])


class TestForkedSupersession:
    def test_retry_fork_verifies(self, tmp_path):
        from canari.verify_cli import verify_chain
        parent = _mk(tmp_path, "a.bundle.json", "1.0.0")
        # crashed run + retry both supersede the same parent digest
        _mk(tmp_path, "b.bundle.json", "1.0.0", supersedes=parent)
        _mk(tmp_path, "c.bundle.json", "1.0.0", supersedes=parent)
        assert verify_chain(str(tmp_path / "attestations"), require_signatures=False) == 0

    def test_dangling_supersedes_still_errors(self, tmp_path):
        from canari.verify_cli import verify_chain
        _mk(tmp_path, "a.bundle.json", "1.0.0")
        _mk(tmp_path, "b.bundle.json", "2.0.0", supersedes="f" * 64)
        assert verify_chain(str(tmp_path / "attestations"), require_signatures=False) == 4
