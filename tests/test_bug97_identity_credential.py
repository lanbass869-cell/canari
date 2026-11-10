# -*- coding: utf-8 -*-
"""Regression tests for BUG-97: git SHAs in provenance identities must not be
mistaken for credentials (they silently destroyed real attestations)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SHA = "af0ad67cb4b7ea17212cd4cd48640ab8e60e96df"
IDENT = "https://github.com/SylphxAI/mcp-kit/.github/workflows/release.yml@" + SHA


class TestProvenanceIdentityNotCredential:
    def test_sha_identity_is_clean(self):
        from canari.signing import credential_shapes
        assert credential_shapes({"native_provenance": {"v1_identity": IDENT}}) == []

    def test_real_hex_secret_still_caught(self):
        from canari.signing import credential_shapes
        assert credential_shapes({"note": "secret " + "a" * 40})

    def test_raw_hex_leaf_still_caught(self):
        """Only the identity FIELD is exempt - a bare hex blob elsewhere is not."""
        from canari.signing import credential_shapes
        assert credential_shapes({"native_provenance": {"leak": "b" * 40}})

    def test_signing_succeeds_with_sha_identity(self):
        """Before the fix this raised CREDENTIAL_IN_PAYLOAD and the package was
        downgraded to verdict=error with an empty version."""
        from canari.signing import generate_keypair, sign_attestation, verify_signed
        signer, pub = generate_keypair()
        V = "https://agentcheck.dev/attestation/v0.1"
        att = {"_type": V,
               "subject": {"name": "@sylphx/anymd", "version": "8.5.11", "registry": "npm",
                           "artifact_sha256": "a" * 64, "maintainers": []},
               "host": {"class": "mcp", "host_version": "t"},
               "scenario_sha256": "b" * 64,
               "checks": [{"id": "L1.1", "verdict": "pass", "tool": "t"}],
               "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
               "evidence_refs": [],
               "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                         "truncated_fields": []},
               "expires_at": "2026-12-30T00:00:00Z", "generated_at": "2026-11-10T00:00:00Z",
               "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": V},
               "native_provenance": {"present": True, "v1_verified": True,
                                     "v1_identity": IDENT}}
        signed = sign_attestation(att, signer)   # must not raise
        ok, payload, err = verify_signed(signed["envelope"], pub.to_dict())
        assert ok, err
        assert payload["native_provenance"]["v1_identity"] == IDENT
