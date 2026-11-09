# -*- coding: utf-8 -*-
"""Round 14: parallel-generation chain verification, legacy path-shaped
supersedes guard, typosquatting family-prefix false positives."""
import hashlib
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canari.typosquat import check_typosquatting


class TestTyposquatFamilyFP:
    """BUG-80: within-family similarity is not typosquatting."""

    @pytest.mark.parametrize("candidate,trusted", [
        ("mcp-server-2", "mcp-server-b24"),
        ("mcp-server-aistudio", "mcp-server-3daistudio"),
        ("mcp-server-akf", "mcp-server-anki"),
        ("mcp-server-fetch", "mcp-server-fetch"),
    ])
    def test_family_names_are_clean(self, candidate, trusted):
        assert check_typosquatting(candidate, {trusted}) is None

    @pytest.mark.parametrize("candidate,trusted", [
        ("mcp-server-fecth", "mcp-server-fetch"),      # transposition
        ("mcp-server-weather", "mcp-server-wether"),   # deletion
        ("reqests", "requests"),                        # global typo
        ("python-dateutil", "python-dateutils"),        # one-char extension
    ])
    def test_true_typos_fire(self, candidate, trusted):
        r = check_typosquatting(candidate, {trusted})
        assert r is not None
        assert "typosquatting" in r["evidence_ref"]


class TestParallelGenerations:
    """BUG-72: two generations of the same component with no supersedes link
    are legitimate; the chain verifier must exit 0 and report a note."""

    def _bundle(self, tmp_path, name, version, extra=None):
        from canari.signing import generate_keypair, sign_attestation
        signer, pub = generate_keypair()
        att = {"_type": "https://agentcheck.dev/attestation/v0.1",
               "subject": {"name": name, "version": version, "registry": "npm",
                           "artifact_sha256": "a" * 64, "maintainers": []},
               "host": {"class": "mcp", "host_version": "t"},
               "scenario_sha256": "b" * 64,
               "checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t/0.1"}],
               "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
               "evidence_refs": [],
               "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
               "expires_at": "2026-12-01T00:00:00Z", "generated_at": "2026-11-09T00:00:00Z",
               "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                             "payload_type": "https://agentcheck.dev/attestation/v0.1"}}
        if extra:
            att.update(extra)
        s = sign_attestation(att, signer)
        fp = tmp_path / ("%s_%s.bundle.json" % (name.replace("/", "_"), version))
        fp.write_text(json.dumps({"envelope": s["envelope"], "payload": s["payload"]}),
                      encoding="utf-8")
        return fp

    def test_two_generations_ok(self, tmp_path):
        from canari.verify_cli import verify_chain
        self._bundle(tmp_path, "pkg", "1.0.0")
        self._bundle(tmp_path, "pkg", "1.0.0-b")
        rc = verify_chain(str(tmp_path))
        assert rc == 0

    def test_unbridged_supersedes_target_is_error(self, tmp_path):
        from canari.verify_cli import verify_chain
        self._bundle(tmp_path, "pkg", "1.0.0")
        # second bundle claims to supersede a digest that does not exist
        self._bundle(tmp_path, "pkg", "2.0.0", extra={"supersedes": "f" * 64})
        rc = verify_chain(str(tmp_path))
        assert rc == 4


class TestSupersedesDigestGuard:
    """BUG-79: a legacy state entry with a FILE PATH in attestation_digest must
    not leak into the signed payload as a bogus supersedes pointer."""

    def test_path_shaped_digest_is_ignored(self, tmp_path, monkeypatch):
        import canari.baseline as bl

        class FakeState:
            def __init__(self, *a, **k):
                pass
            def get_component(self, name):
                return {"version": "0.1", "sha256": "0" * 64,
                        "attestation_digest": "E:\\Temp\\out\\attestations\\x.bundle.json"}
            def set_component(self, *a, **k):
                pass
            def save(self):
                pass

        monkeypatch.setattr(bl, "StateStore", FakeState)
        monkeypatch.setattr(bl, "enumerate_top", lambda limit=50, dedupe=True: [
            {"name": "pkg-guard", "description": "d", "links": {"homepage": "https://x"}}])
        monkeypatch.setattr(bl, "fetch_packument", lambda name, timeout=90: {
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"dist": {"integrity": "sha512-" + __import__("base64").b64encode(bytes(64)).decode(),
                                            "tarball": "https://x"}}},
            "maintainers": [{"name": "a"}]})
        monkeypatch.setattr(bl, "_download_sha256", lambda url, timeout=60: "e" * 64)
        monkeypatch.setattr(bl, "native_ingest", lambda n, v: None)
        monkeypatch.setattr(bl, "pypi_enumerate", lambda limit=500: [])
        monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda limit=500: [])
        monkeypatch.setattr(bl, "dsh_enumerate", lambda limit=500, with_security=True: [])
        monkeypatch.setattr(bl, "_runner_source_digest", lambda: "d" * 64)

        r = bl.run_multi(npm_limit=1, pypi_limit=0, registry_limit=0, dsh_limit=0,
                         out_dir=str(tmp_path))
        bundles = list((tmp_path / "attestations").glob("*.bundle.json"))
        assert bundles, "expected one bundle"
        payload = json.loads(bundles[0].read_text(encoding="utf-8"))["payload"]
        assert "supersedes" not in payload
