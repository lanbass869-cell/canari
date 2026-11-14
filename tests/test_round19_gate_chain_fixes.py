# -*- coding: utf-8 -*-
"""Round 19 regression: seven real defects found in the 2026-11-14 deep audit.

F1  evaluate_gate() skipped signature verification when key_path was None -> ALLOW.
F2  consumer/guard never auto-discovered the store's public_key.json.
F3  verify_chain() checked structure but never signatures -> self-signed chains rc=0.
F4  a verdict backed only by L1.1_REGISTRY_PRESENT read as installable.
F5  symmetric typosquat flags (both names flag each other) were reported as findings.
F6  state.diff() ignored VERSION changes (same sha256 -> "unchanged").
F7  H2 metadata baseline was a truthy-but-empty {"tier":"meta"} snapshot.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari.signing import generate_keypair, sign_attestation, export_public_key
from canari.gate import evaluate_gate

V = "https://agentcheck.dev/attestation/v0.1"


def _att(verdict="pass", name="pkg-a", checks=None, version="1.0.0"):
    return {
        "_type": V,
        "subject": {"name": name, "version": version, "registry": "npm",
                    "artifact_sha256": "a" * 64, "maintainers": []},
        "host": {"class": "mcp", "host_version": "t"},
        "scenario_sha256": "b" * 64,
        "checks": checks if checks is not None else [
            {"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t"},
            {"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "t"}],
        "verdict": verdict,
        "checker": {"kind": "automation", "id": "t"},
        "evidence_refs": [],
        "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                  "truncated_fields": []},
        "expires_at": "2027-01-01T00:00:00Z",
        "generated_at": "2026-11-11T00:00:00Z",
        "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": ""},
    }


def _signed(tmp_path, **kw):
    signer, pub = generate_keypair()
    signed = sign_attestation(_att(**kw), signer)
    bundle = {"envelope": signed["envelope"], "payload": signed["payload"]}
    bp = tmp_path / "b.bundle.json"
    bp.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
    kp = tmp_path / "public_key.json"
    kp.write_text(export_public_key(pub), encoding="utf-8")
    return bp, kp, pub


def _store(tmp_path, signer=None, names=("pkg-a",)):
    """Write <tmp>/attestations/<n>.bundle.json signed by signer (one keypair)."""
    ad = tmp_path / "attestations"
    ad.mkdir(exist_ok=True)
    if signer is None:
        signer, pub = generate_keypair()
    else:
        pub = None
    for n in names:
        signed = sign_attestation(_att(name=n), signer)
        (ad / ("%s.bundle.json" % n)).write_text(
            json.dumps({"envelope": signed["envelope"], "payload": signed["payload"]},
                       ensure_ascii=False), encoding="utf-8")
    return ad


class TestF1FailClosedOnMissingKey:
    def test_pass_bundle_without_key_blocks(self, tmp_path):
        bp, kp, _ = _signed(tmp_path, verdict="pass")
        dec = evaluate_gate(str(bp), key_path=None, policy_name="lax")
        assert dec.decision == "BLOCK", dec.reasons
        assert any("no public key" in r.lower() for r in dec.reasons), dec.reasons

    def test_allow_unsigned_never_allows(self, tmp_path):
        bp, kp, _ = _signed(tmp_path, verdict="pass")
        dec = evaluate_gate(str(bp), key_path=None, policy_name="lax",
                            allow_unsigned=True)
        assert dec.decision == "REVIEW", dec.reasons
        assert any("UNVERIFIED" in r for r in dec.reasons), dec.reasons

    def test_pass_bundle_with_key_allows(self, tmp_path):
        bp, kp, _ = _signed(tmp_path, verdict="pass")
        dec = evaluate_gate(str(bp), key_path=str(kp), policy_name="lax")
        assert dec.decision == "ALLOW", dec.reasons


class TestF2KeyAutoDiscovery:
    def test_resolve_key_none_when_absent(self, tmp_path):
        from canari.consumer import resolve_key
        assert resolve_key(str(tmp_path)) is None

    def test_resolve_key_finds_store_key(self, tmp_path):
        from canari.consumer import resolve_key
        kp = tmp_path / "public_key.json"
        kp.write_text("{}", encoding="utf-8")
        assert resolve_key(str(tmp_path)) == str(kp)

    def test_resolve_key_explicit_wins(self, tmp_path):
        from canari.consumer import resolve_key
        assert resolve_key(str(tmp_path), "explicit.json") == "explicit.json"

    def test_check_component_uses_store_key(self, tmp_path):
        from canari.consumer import check_component
        signer, pub = generate_keypair()
        _store(tmp_path, signer=signer, names=("pkg-a",))
        # no key beside the store -> the gate must fail closed
        dec = check_component(str(tmp_path), "npm", "pkg-a", policy="lax")
        assert dec["found"] is True
        assert dec["decision"] == "BLOCK", dec.get("reasons")
        # ship the store key -> auto-discovered -> ALLOW
        (tmp_path / "public_key.json").write_text(export_public_key(pub),
                                                  encoding="utf-8")
        dec2 = check_component(str(tmp_path), "npm", "pkg-a", policy="lax")
        assert dec2["decision"] == "ALLOW", dec2.get("reasons")


class TestF3ChainVerifiesSignatures:
    def test_no_key_fails_closed(self, tmp_path):
        from canari.verify_cli import verify_chain
        _store(tmp_path, names=("pkg-a",))
        assert verify_chain(str(tmp_path / "attestations")) == 4

    def test_wrong_key_rejected(self, tmp_path):
        from canari.verify_cli import verify_chain
        _store(tmp_path, names=("pkg-a",))
        _, other_pub = generate_keypair()
        (tmp_path / "public_key.json").write_text(export_public_key(other_pub),
                                                  encoding="utf-8")
        assert verify_chain(str(tmp_path / "attestations")) == 4

    def test_matching_key_ok(self, tmp_path):
        from canari.verify_cli import verify_chain
        signer, pub = generate_keypair()
        _store(tmp_path, signer=signer, names=("pkg-a",))
        (tmp_path / "public_key.json").write_text(export_public_key(pub),
                                                  encoding="utf-8")
        assert verify_chain(str(tmp_path / "attestations")) == 0

    def test_two_different_keys_cannot_join(self, tmp_path):
        """Two bundles signed by DIFFERENT throwaway keys are not one ledger."""
        from canari.verify_cli import verify_chain
        s1, p1 = generate_keypair()
        s2, p2 = generate_keypair()
        _store(tmp_path, signer=s1, names=("pkg-one",))
        _store(tmp_path, signer=s2, names=("pkg-two",))
        (tmp_path / "public_key.json").write_text(export_public_key(p1),
                                                  encoding="utf-8")
        assert verify_chain(str(tmp_path / "attestations")) == 4

    def test_structural_mode_skips_signature(self, tmp_path):
        from canari.verify_cli import verify_chain
        _store(tmp_path, names=("pkg-a",))
        assert verify_chain(str(tmp_path / "attestations"),
                            require_signatures=False) == 0


class TestF4ArtifactEvidenceRequired:
    def test_registry_only_is_not_passing(self):
        from canari.schema import has_artifact_evidence, is_gate_passing
        att = {"verdict": "pass-with-findings",
               "checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t"}]}
        assert has_artifact_evidence(att) is False
        assert is_gate_passing(att) is False

    def test_artifact_hash_pass_counts(self):
        from canari.schema import has_artifact_evidence
        att = {"checks": [{"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "t"}]}
        assert has_artifact_evidence(att) is True

    def test_static_scan_pass_counts(self):
        from canari.schema import has_artifact_evidence
        att = {"checks": [{"id": "L3.1_STATIC_SCAN", "verdict": "pass", "tool": "t"}]}
        assert has_artifact_evidence(att) is True

    def test_artifact_hash_unsupported_is_not_evidence(self):
        from canari.schema import has_artifact_evidence, is_gate_passing
        att = {"verdict": "pass",
               "checks": [{"id": "L2.1_ARTIFACT_HASH", "verdict": "unsupported",
                           "tool": "t", "evidence_ref": "not downloaded"}]}
        assert has_artifact_evidence(att) is False
        assert is_gate_passing(att) is False

    def test_gate_blocks_registry_only_record(self, tmp_path):
        """The live 346-record shape: one registry check, pass-with-findings."""
        bp, kp, _ = _signed(tmp_path, verdict="pass-with-findings",
                            checks=[{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass",
                                     "tool": "t"}])
        dec = evaluate_gate(str(bp), key_path=str(kp), policy_name="lax")
        assert dec.decision == "BLOCK", dec.reasons


class TestF5MutualTyposquat:
    def test_find_mutual_pairs_is_symmetric(self):
        from canari.typosquat import find_mutual_pairs
        mp = find_mutual_pairs(["mcp-server-deepresearch", "mcp-server-deepsearch"])
        assert ("mcp-server-deepresearch", "mcp-server-deepsearch") in mp
        assert ("mcp-server-deepsearch", "mcp-server-deepresearch") in mp

    def test_mutual_pair_suppressed(self):
        from canari.typosquat import find_mutual_pairs, check_typosquatting
        names = ["mcp-server-deepresearch", "mcp-server-deepsearch"]
        mp = find_mutual_pairs(names)
        assert check_typosquatting("mcp-server-deepresearch",
                                   {"mcp-server-deepsearch"}, mutual_pairs=mp) is None

    def test_real_typo_still_fires_without_mutual(self):
        from canari.typosquat import check_typosquatting
        r = check_typosquatting("mcp-server-fetcch", {"mcp-server-fetch"})
        assert r is not None and "typosquatting" in r["evidence_ref"]

    def test_age_rank_suppresses_older_candidate(self):
        from canari.typosquat import check_typosquatting
        assert check_typosquatting("mcp-server-fetch", {"mcp-server-xfetch"},
                                   age_rank={"mcp-server-fetch": 10,
                                             "mcp-server-xfetch": 1}) is None

    def test_age_rank_still_fires_for_newer_candidate(self):
        from canari.typosquat import check_typosquatting
        r = check_typosquatting("mcp-server-xfetch", {"mcp-server-fetch"},
                                age_rank={"mcp-server-fetch": 10,
                                          "mcp-server-xfetch": 1})
        assert r is not None and "typosquatting" in r["evidence_ref"]


class TestF6VersionChangeIsAChange:
    def test_version_only_change_is_changed(self, tmp_path):
        from canari.state import StateStore
        st = StateStore(str(tmp_path / "state.json"))
        st.set_component("npm:pkg", "2.0.0", "a" * 64, "d" * 64)
        current = {"npm:pkg": {"version": "1.0.0", "sha256": "a" * 64}}
        d = st.diff(current, prev=st._data["components"])
        assert "npm:pkg" in d["changed"]
        assert d["unchanged"] == []

    def test_same_version_and_hash_is_unchanged(self, tmp_path):
        from canari.state import StateStore
        st = StateStore(str(tmp_path / "state.json"))
        st.set_component("npm:pkg", "1.0.0", "a" * 64, "d" * 64)
        current = {"npm:pkg": {"version": "1.0.0", "sha256": "a" * 64}}
        d = st.diff(current, prev=st._data["components"])
        assert d["unchanged"] == ["npm:pkg"]
        assert d["changed"] == []


class TestF7MetadataBaselineUsable:
    def test_tier_only_meta_is_not_usable(self):
        from canari.baseline import _usable_meta
        assert _usable_meta({"tier": "meta"}) is False
        assert _usable_meta(None) is False
        assert _usable_meta("nope") is False

    def test_real_meta_is_usable(self):
        from canari.baseline import _usable_meta
        assert _usable_meta({"maintainers": []}) is True
        assert _usable_meta({"homepage": "https://x"}) is True

    def test_detect_metadata_anomaly_on_real_change(self):
        from canari.anomaly import detect_metadata_anomaly
        cur = {"maintainers": ["alice"], "homepage": "https://x"}
        prev = {"maintainers": ["bob"], "homepage": "https://x"}
        f = detect_metadata_anomaly(cur, prev)
        assert f and "maintainer_identity_change" in f[0]["evidence_ref"]

    def test_tier_only_baseline_yields_nothing(self):
        from canari.anomaly import detect_metadata_anomaly
        cur = {"maintainers": ["alice"], "homepage": "https://x"}
        assert detect_metadata_anomaly(cur, {"tier": "meta"}) == []

class TestF8PolicyFieldsAreUnique:
    """A duplicate dataclass field silently overrides its neighbour's default.

    gate.py declared `review_findings` twice (copy/paste). Same value hid it, so
    nothing failed; a later edit to only one copy would have been ignored.
    """

    def test_no_duplicate_field_names(self):
        import dataclasses
        from canari.gate import GatePolicy
        names = [f.name for f in dataclasses.fields(GatePolicy)]
        assert len(names) == len(set(names)), names

    def test_every_policy_field_is_constructible(self):
        from canari.gate import GatePolicy, BUILTIN_POLICIES
        for name, pol in BUILTIN_POLICIES.items():
            assert pol.name == name
            assert isinstance(pol.review_findings, bool)
