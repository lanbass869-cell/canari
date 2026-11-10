# -*- coding: utf-8 -*-
"""Round 17: canari-guard - install-command gate wrapper."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canari.guard import parse_install, main as guard_main


def _mk(tmp_path, name, verdict, registry="dsh-registry", checks=None):
    from canari.signing import generate_keypair, sign_attestation
    signer, pub = generate_keypair()
    att = {"_type": "https://agentcheck.dev/attestation/v0.1",
           "subject": {"name": name, "version": "1.0.0", "registry": registry,
                       "artifact_sha256": "a" * 64, "maintainers": []},
           "host": {"class": "mcp", "host_version": "t"},
           "scenario_sha256": "b" * 64,
           "checks": checks or [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t"}],
           "verdict": verdict, "checker": {"kind": "automation", "id": "t"},
           "evidence_refs": [],
           "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
           "expires_at": "2026-12-30T00:00:00Z", "generated_at": "2026-11-10T00:00:00Z",
           "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                         "payload_type": "https://agentcheck.dev/attestation/v0.1"}}
    s = sign_attestation(att, signer)
    ad = tmp_path / "attestations"
    ad.mkdir(exist_ok=True)
    (ad / ("%s_%s.bundle.json" % (registry, name.replace("/", "_")))).write_text(
        json.dumps({"envelope": s["envelope"], "payload": s["payload"]}), encoding="utf-8")


class TestParser:
    @pytest.mark.parametrize("argv,expected", [
        (["dsh", "plugin", "--profile", "wbpj", "add", "dsh-purge"], [("dsh-registry", "dsh-purge", None)]),
        (["dsh", "plugin", "add", "a", "b"], [("dsh-registry", "a", None), ("dsh-registry", "b", None)]),
        (["npm", "install", "@scope/pkg@1.2.3"], [("npm", "@scope/pkg", "1.2.3")]),
        (["npm", "i", "-D", "left-pad"], [("npm", "left-pad", None)]),
        (["pip", "install", "mcp-server-fetch==0.2.1"], [("pypi", "mcp-server-fetch", "0.2.1")]),
        (["ls", "-la"], []),
    ])
    def test_parse(self, argv, expected):
        assert parse_install(argv) == expected


class TestGuard:
    def test_block_refuses(self, tmp_path):
        _mk(tmp_path, "bad", "fail")
        rc = guard_main(["--store", str(tmp_path), "--dry-run", "--",
                         "dsh", "plugin", "add", "bad"])
        assert rc == 5

    def test_review_needs_flag(self, tmp_path):
        _mk(tmp_path, "ish", "pass-with-findings")
        rc = guard_main(["--store", str(tmp_path), "--dry-run", "--",
                         "dsh", "plugin", "add", "ish"])
        assert rc == 6

    def test_review_allowed(self, tmp_path):
        _mk(tmp_path, "ish", "pass-with-findings")
        rc = guard_main(["--store", str(tmp_path), "--dry-run", "--allow-review", "--",
                         "dsh", "plugin", "add", "ish"])
        assert rc == 0

    def test_allow(self, tmp_path):
        _mk(tmp_path, "good", "pass")
        rc = guard_main(["--store", str(tmp_path), "--dry-run", "--",
                         "dsh", "plugin", "add", "good"])
        assert rc == 0

    def test_unknown_component_blocks(self, tmp_path):
        rc = guard_main(["--store", str(tmp_path), "--dry-run", "--",
                         "npm", "install", "never-seen"])
        assert rc == 5

    def test_passthrough(self, tmp_path):
        rc = guard_main(["--store", str(tmp_path), "--dry-run", "--", "ls", "-la"])
        assert rc == 0
