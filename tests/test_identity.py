# -*- coding: utf-8 -*-
"""canari.identity - the pair verdict, and the things that must never be "same"."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari.identity import classify, main, normalize_repo


class TestNormalizeRepo:
    def test_git_suffix_and_scheme_and_case_all_collapse(self):
        a = normalize_repo("https://github.com/AISenseAPI/aamio-js.git")
        b = normalize_repo("git+https://GitHub.com/aisenseapi/aamio-js/")
        c = normalize_repo("git@github.com:aisenseapi/aamio-js.git")
        assert a == b == c == "github.com/aisenseapi/aamio-js"

    def test_dict_form_is_accepted(self):
        assert (normalize_repo({"url": "https://github.com/x/y.git", "type": "git"})
                == "github.com/x/y")

    def test_empty_and_none(self):
        assert normalize_repo(None) is None
        assert normalize_repo("") is None
        assert normalize_repo({}) is None
        assert normalize_repo("   ") is None

    def test_unknown_host_is_kept_but_normalised(self):
        assert normalize_repo("https://razin.ai/deputy/") == "https://razin.ai/deputy"

    def test_different_owners_do_not_collide(self):
        assert (normalize_repo("https://github.com/william-laverty/ato-mcp")
                != normalize_repo("https://github.com/bigred97/ato-mcp"))

    def test_subpaths_on_the_same_repo_collapse(self):
        assert (normalize_repo("https://github.com/o/r/tree/main/pkg")
                == normalize_repo("https://github.com/o/r"))


class TestClassify:
    def test_same(self):
        v, why = classify("github.com/o/r", "github.com/o/r")
        assert v == "same" and "github.com/o/r" in why

    def test_different(self):
        v, why = classify("github.com/a/x", "github.com/b/r")
        assert v == "different"
        assert "different repositories" in why

    def test_missing_url_is_unknown_not_same(self):
        # The whole point: absence of evidence is never "same".
        assert classify(None, "github.com/o/r")[0] == "unknown"
        assert classify("github.com/o/r", None)[0] == "unknown"
        assert classify(None, None)[0] == "unknown"


class TestCli:
    def test_usage_error_without_registry_prefix(self, capsys):
        # A bare name must not be silently treated as "some registry:name"; it is
        # a usage error, and it exits 2 rather than inventing a verdict.
        assert main(["check", "ato-mcp", "pypi:ato-mcp"]) == 2
        err = capsys.readouterr().err
        assert "registry:name" in err


class TestRepositoryCapture:
    """The attestation has to carry the repository, or the identity layer has
    nothing to work with at scan time."""

    def test_npm_packument_dict_and_string_forms(self):
        from canari.baseline import repo_from_npm_packument
        assert (repo_from_npm_packument({"repository": {"url": "https://github.com/o/r.git"}})
                == "github.com/o/r")
        assert repo_from_npm_packument({"repository": "git+https://github.com/o/r"}) == "github.com/o/r"
        assert repo_from_npm_packument({}) is None
        assert repo_from_npm_packument(None) is None

    def test_pypi_prefers_a_repo_like_project_url(self):
        from canari.baseline import repo_from_pypi_doc
        doc = {"info": {"project_urls": {"Homepage": "https://example.com/x",
                                         "Source Code": "https://github.com/o/r"},
                        "home_page": "https://example.com/x"}}
        assert repo_from_pypi_doc(doc) == "github.com/o/r"

    def test_pypi_falls_back_to_home_page(self):
        from canari.baseline import repo_from_pypi_doc
        doc = {"info": {"project_urls": {}, "home_page": "https://github.com/o/r"}}
        assert repo_from_pypi_doc(doc) == "github.com/o/r"

    def test_pypi_without_any_url_is_none(self):
        from canari.baseline import repo_from_pypi_doc
        assert repo_from_pypi_doc({"info": {}}) is None
        assert repo_from_pypi_doc(None) is None


class TestSchemaAcceptsRepository:
    def _att(self, **subject_extra):
        subject = {"name": "p", "version": "1", "registry": "npm",
                   "artifact_sha256": "a" * 64, "maintainers": []}
        subject.update(subject_extra)
        return {"_type": "https://agentcheck.dev/attestation/v0.1",
                "subject": subject,
                "host": {"class": "mcp", "host_version": "t"},
                "scenario_sha256": "b" * 64,
                "checks": [{"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "t"}],
                "verdict": "pass",
                "checker": {"kind": "automation", "id": "t"},
                "evidence_refs": [],
                "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                          "truncated_fields": []},
                "expires_at": "2026-12-30T00:00:00Z",
                "generated_at": "2026-11-18T00:00:00Z",
                "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                              "payload_type": "https://agentcheck.dev/attestation/v0.1"}}

    def test_repository_is_allowed(self):
        from canari.schema import validate_attestation
        assert validate_attestation(self._att(repository="github.com/o/r")) == []

    def test_repository_is_not_required(self):
        # Old records stay valid: absent repository means UNKNOWN, not invalid.
        from canari.schema import validate_attestation
        assert validate_attestation(self._att()) == []


def _rec(registry, name, repo=None, version="1"):
    subj = {"name": name, "version": version, "registry": registry,
            "artifact_sha256": "a" * 64}
    if repo:
        subj["repository"] = repo
    return {"subject": subj}


class TestClusters:
    def test_same_repository_is_one_cluster_across_registries(self):
        from canari.identity import build_clusters
        built = build_clusters([_rec("npm", "aamio", "https://github.com/o/aamio-js"),
                                _rec("pypi", "aamio", "git+https://github.com/o/aamio-js.git")])
        assert len(built["clusters"]) == 1
        c = built["clusters"][0]
        assert c["registries"] == ["npm", "pypi"]
        assert {m["registry"] for m in c["members"]} == {"npm", "pypi"}

    def test_missing_repository_is_counted_not_clustered(self):
        from canari.identity import build_clusters
        built = build_clusters([_rec("npm", "x"), _rec("npm", "y", "https://github.com/o/y")])
        assert len(built["clusters"]) == 1
        assert built["without_repository"] == 1

    def test_cluster_id_is_deterministic_and_content_addressed(self):
        from canari.identity import build_clusters
        a = build_clusters([_rec("npm", "x", "https://github.com/o/r")])
        b = build_clusters([_rec("pypi", "x", "https://github.com/o/r/")])
        assert a["clusters"][0]["id"] == b["clusters"][0]["id"]
        assert a["clusters"][0]["id"].startswith("sha256:")

    def test_duplicate_member_is_not_double_counted(self):
        from canari.identity import build_clusters
        built = build_clusters([_rec("npm", "x", "https://github.com/o/r"),
                                _rec("npm", "x", "https://github.com/o/r")])
        assert len(built["clusters"][0]["members"]) == 1


class TestConflicts:
    def test_repository_changed_for_same_component(self):
        from canari.identity import find_conflicts
        got = find_conflicts([_rec("npm", "x", "https://github.com/old/x"),
                              _rec("npm", "x", "https://github.com/new/x")])
        assert len(got["repo_changed"]) == 1
        assert got["repo_changed"][0]["repositories"] == [
            "github.com/new/x", "github.com/old/x"]

    def test_name_collision_across_registries(self):
        from canari.identity import find_conflicts
        got = find_conflicts([_rec("npm", "ato-mcp", "https://github.com/a/ato-mcp"),
                              _rec("pypi", "ato-mcp", "https://github.com/b/ato-mcp")])
        assert len(got["name_collision"]) == 1
        assert got["name_collision"][0]["registries"] == ["npm", "pypi"]

    def test_same_name_same_repo_is_not_a_conflict(self):
        from canari.identity import find_conflicts
        got = find_conflicts([_rec("npm", "aether", "https://github.com/o/r"),
                              _rec("pypi", "aether", "https://github.com/o/r")])
        assert got["name_collision"] == []

    def test_missing_repository_never_manufactures_a_conflict(self):
        from canari.identity import find_conflicts
        got = find_conflicts([_rec("npm", "x"), _rec("pypi", "x", "https://github.com/o/r")])
        assert got["name_collision"] == [] and got["repo_changed"] == []


class TestStoreLoading:
    def test_unreadable_file_is_reported_not_ignored(self, tmp_path):
        from canari.identity import load_store
        (tmp_path / "attestations").mkdir()
        (tmp_path / "attestations" / "bad.json").write_text("{not json", encoding="utf-8")
        records, unreadable = load_store(str(tmp_path))
        assert records == []
        assert len(unreadable) == 1 and "bad.json" in unreadable[0]["path"]


def _signed_bundle(tmp_path, att):
    import json as _json
    from canari.signing import sign_attestation
    signer, pub = _signed_bundle.signer, _signed_bundle.pub
    bundle = sign_attestation(att, signer)
    p = tmp_path / ("%s.bundle.json" % att["subject"]["name"])
    p.write_text(_json.dumps(bundle), encoding="utf-8")
    return p


def _make_store(tmp_path, repos):
    """tmp_path/store/attestations with one signed record per (registry, name, repo)."""
    import json as _json
    from canari.signing import generate_keypair
    signer, pub = generate_keypair()
    _signed_bundle.signer, _signed_bundle.pub = signer, pub
    d = tmp_path / "store" / "attestations"
    d.mkdir(parents=True)
    for i, (reg, name, repo) in enumerate(repos):
        att = {"_type": "https://agentcheck.dev/attestation/v0.1",
               "subject": {"name": name, "version": "1", "registry": reg,
                           "artifact_sha256": "a" * 64, "maintainers": [],
                           "repository": repo},
               "host": {"class": "mcp", "host_version": "t"},
               "scenario_sha256": "b" * 64,
               "checks": [{"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "t"}],
               "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
               "evidence_refs": [], "evidence_completeness": {
                   "dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
               "expires_at": "2026-12-30T00:00:00Z",
               "generated_at": "2026-11-18T00:00:00Z",
               "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                             "payload_type": "https://agentcheck.dev/attestation/v0.1"}}
        b = _signed_bundle(tmp_path, att)
        b.rename(d / ("%d_%s.bundle.json" % (i, name.replace("/", "_"))))
    kp = tmp_path / "k.pem"
    from canari.signing import save_private_key
    save_private_key(signer, str(kp))
    pubp = tmp_path / "pub.json"
    pubp.write_text(_json.dumps(pub.to_dict()), encoding="utf-8")
    return tmp_path / "store", kp, pubp


class TestClaims:
    def test_claim_shape_and_validation(self):
        from canari.identity import build_claim, validate_claim
        cluster = {"id": "sha256:abc", "repository": "github.com/o/r",
                   "registries": ["npm", "pypi"],
                   "members": [{"registry": "npm", "name": "a", "version": "1"},
                               {"registry": "pypi", "name": "a", "version": "1"}]}
        claim = build_claim(cluster, {"name_collision": []}, "2026-11-18T00:00:00Z")
        assert validate_claim(claim) == []
        assert claim["members"] == cluster["members"]
        assert claim["method"] == "publishing-repository/v1"

    def test_claim_rejects_missing_repository(self):
        from canari.identity import build_claim, validate_claim
        cluster = {"id": "sha256:abc", "repository": "", "registries": ["npm"],
                   "members": [{"registry": "npm", "name": "a", "version": "1"}]}
        claim = build_claim(cluster, {}, "2026-11-18T00:00:00Z")
        assert any("repository" in e for e in validate_claim(claim))

    def test_claim_rejects_empty_members(self):
        from canari.identity import build_claim, validate_claim
        cluster = {"id": "sha256:abc", "repository": "github.com/o/r",
                   "registries": [], "members": []}
        claim = build_claim(cluster, {}, "2026-11-18T00:00:00Z")
        assert any("members" in e for e in validate_claim(claim))

    def test_sign_then_verify_end_to_end(self, tmp_path):
        from canari.identity import main
        store, key, pub = _make_store(tmp_path, [
            ("npm", "aamio", "https://github.com/o/aamio-js"),
            ("pypi", "aamio", "https://github.com/o/aamio-js"),
        ])
        assert main(["clusters", "--store", str(store)]) == 0
        assert main(["sign", "--store", str(store), "--key", str(key)]) == 0
        claims = tmp_path / "store" / "identity"
        assert len(list(claims.glob("*.identity.json"))) == 1
        assert main(["verify", "--claims", str(claims), "--key", str(pub)]) == 0

    def test_tampered_claim_fails_verification(self, tmp_path):
        import json as _json
        from canari.identity import main
        store, key, pub = _make_store(tmp_path, [
            ("npm", "x", "https://github.com/o/r"),
            ("pypi", "x", "https://github.com/o/r"),
        ])
        main(["sign", "--store", str(store), "--key", str(key)])
        claims = tmp_path / "store" / "identity"
        path = next(claims.glob("*.identity.json"))
        bundle = _json.loads(path.read_text(encoding="utf-8"))
        # Corrupt the signed bytes: an attacker who edits the claim must not be
        # able to keep a valid signature.
        env = bundle["envelope"]
        raw = env["payload"]
        env["payload"] = raw[:-8] + ("A" if raw[-8] != "A" else "B") + raw[-7:]
        path.write_text(_json.dumps(bundle), encoding="utf-8")
        assert main(["verify", "--claims", str(claims), "--key", str(pub)]) == 1


class TestGateIdentity:
    """Opt-in identity enforcement at the gate. Default behaviour must not move."""

    def _setup(self, tmp_path, repo="github.com/o/r", claim_repo=None):
        import json as _json
        from canari.signing import (generate_keypair, save_private_key,
                                    sign_attestation)
        signer, pub = generate_keypair()
        subj = {"name": "p", "version": "1", "registry": "npm",
                "artifact_sha256": "a" * 64, "maintainers": []}
        if repo:
            subj["repository"] = repo
        att = {"_type": "https://agentcheck.dev/attestation/v0.1", "subject": subj,
               "host": {"class": "mcp", "host_version": "t"},
               "scenario_sha256": "b" * 64,
               "checks": [{"id": "L2.1_ARTIFACT_HASH", "verdict": "pass", "tool": "t"}],
               "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
               "evidence_refs": [], "evidence_completeness": {
                   "dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
               "expires_at": "2026-12-30T00:00:00Z",
               "generated_at": "2026-11-18T00:00:00Z",
               "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                             "payload_type": "https://agentcheck.dev/attestation/v0.1"}}
        bp = tmp_path / "att.json"
        bp.write_text(_json.dumps(sign_attestation(att, signer)), encoding="utf-8")
        kp = tmp_path / "pub.json"
        kp.write_text(_json.dumps(pub.to_dict()), encoding="utf-8")
        claim = {"_type": "https://agentcheck.dev/identity/v0.1",
                 "subject": {"repository": claim_repo or repo or "github.com/o/r",
                             "cluster_id": "sha256:abc"},
                 "members": [{"registry": "npm", "name": "p", "version": "1"}],
                 "registries": ["npm"], "method": "publishing-repository/v1",
                 "method_note": "n", "conflicts": {"name_collision": []},
                 "observed_at": "2026-11-18T00:00:00Z"}
        cp = tmp_path / "claim.json"
        cp.write_text(_json.dumps(sign_attestation(claim, signer)), encoding="utf-8")
        return str(bp), str(kp), str(cp)

    def test_default_policy_is_unaffected(self, tmp_path):
        from canari.gate import evaluate_gate
        bp, kp, _cp = self._setup(tmp_path)
        assert evaluate_gate(bp, key_path=kp).decision == "ALLOW"

    def test_matching_claim_allows(self, tmp_path):
        from canari.gate import evaluate_gate
        bp, kp, cp = self._setup(tmp_path)
        d = evaluate_gate(bp, key_path=kp, identity_claim_path=cp)
        assert d.decision == "ALLOW", d.reasons

    def test_claim_for_a_different_repository_blocks(self, tmp_path):
        from canari.gate import evaluate_gate
        bp, kp, cp = self._setup(tmp_path, claim_repo="github.com/other/r")
        d = evaluate_gate(bp, key_path=kp, identity_claim_path=cp)
        assert d.decision == "BLOCK"
        assert any("identity mismatch" in r for r in d.reasons)

    def test_attestation_without_repository_blocks(self, tmp_path):
        from canari.gate import evaluate_gate
        bp, kp, cp = self._setup(tmp_path, repo=None)
        d = evaluate_gate(bp, key_path=kp, identity_claim_path=cp)
        assert d.decision == "BLOCK"
        assert any("no publishing repository" in r for r in d.reasons)

    def test_require_identity_without_claim_blocks(self, tmp_path):
        from canari.gate import evaluate_gate
        bp, kp, _cp = self._setup(tmp_path)
        d = evaluate_gate(bp, key_path=kp,
                          policy_overrides={"require_identity": True})
        assert d.decision == "BLOCK"
        assert any("--identity-claim" in r for r in d.reasons)

    def test_tampered_claim_blocks(self, tmp_path):
        import json as _json
        from canari.gate import evaluate_gate
        bp, kp, cp = self._setup(tmp_path)
        claim = _json.loads(open(cp, encoding="utf-8").read())
        env = claim["envelope"]
        env["payload"] = env["payload"][:-6] + "ZZZZZZ"
        open(cp, "w", encoding="utf-8").write(_json.dumps(claim))
        d = evaluate_gate(bp, key_path=kp, identity_claim_path=cp)
        assert d.decision == "BLOCK"
        assert any("signature FAILED" in r for r in d.reasons)


class TestMonorepoIsNotSameness:
    """Measured on real data 2026-11-18: modelcontextprotocol/servers publishes
    mcp-server-fetch, mcp-server-git and mcp-server-time - three different
    servers in one repository. A repository link is a project link, not proof
    that two names are the same package."""

    def test_one_repo_two_names_is_flagged_monorepo(self):
        from canari.identity import build_clusters
        built = build_clusters([
            _rec("pypi", "mcp-server-fetch", "https://github.com/o/servers"),
            _rec("pypi", "mcp-server-git", "https://github.com/o/servers"),
        ])
        c = built["clusters"][0]
        assert c["kind"] == "monorepo"
        assert c["distinct_names"] == 2

    def test_single_name_is_a_package_cluster(self):
        from canari.identity import build_clusters
        built = build_clusters([
            _rec("npm", "a", "https://github.com/o/r"),
            _rec("pypi", "a", "https://github.com/o/r"),
        ])
        assert built["clusters"][0]["kind"] == "package"

    def test_claim_carries_the_kind(self):
        from canari.identity import build_claim
        cluster = {"id": "sha256:abc", "repository": "github.com/o/servers",
                   "registries": ["pypi"], "kind": "monorepo", "distinct_names": 3,
                   "members": [{"registry": "pypi", "name": "a", "version": "1"}]}
        claim = build_claim(cluster, {}, "2026-11-18T00:00:00Z")
        assert claim["kind"] == "monorepo" and claim["distinct_names"] == 3
        assert "monorepo" in claim["method_note"]


class TestEntryPointsEnforceIdentity:
    """canari-guard and canari-mcp-gate are the commands that actually stop a
    package. `--identity-dir` must refuse when the claim for this component is
    missing, not silently skip the check."""

    def test_claim_filename_matches_what_sign_writes(self, tmp_path):
        from canari.identity import claim_filename, cluster_id
        repo = "https://github.com/o/r.git"
        assert claim_filename(repo) == cluster_id(repo).split(":")[-1] + ".identity.json"

    def test_identity_claim_for_resolves_by_repository(self, tmp_path):
        from canari.guard import _identity_claim_for
        store, key, _pub = _make_store(tmp_path, [("npm", "x", "https://github.com/o/r")])
        idir = tmp_path / "identity"
        idir.mkdir()
        from canari.identity import claim_filename
        (idir / claim_filename("https://github.com/o/r")).write_text("{}", encoding="utf-8")
        got = _identity_claim_for(str(store), "npm", "x", None, None, str(idir))
        assert got is not None and got.endswith(".identity.json")

    def test_identity_claim_for_returns_none_without_repository(self, tmp_path):
        from canari.guard import _identity_claim_for
        store, _key, _pub = _make_store(tmp_path, [("npm", "y", None)])
        idir = tmp_path / "identity"; idir.mkdir()
        assert _identity_claim_for(str(store), "npm", "y", None, None, str(idir)) is None

    def test_guard_blocks_when_identity_dir_has_no_claim(self, tmp_path, capsys):
        from canari.guard import main
        store, key, _pub = _make_store(tmp_path, [("npm", "x", "https://github.com/o/r")])
        idir = tmp_path / "identity"; idir.mkdir()
        rc = main(["--store", str(store), "--key", str(key), "--identity-dir", str(idir),
                   "--dry-run", "--", "npm", "install", "x"])
        out = capsys.readouterr().out
        assert rc != 0
        assert "no signed claim" in out

    def test_mcp_gate_blocks_when_identity_dir_has_no_claim(self, tmp_path, monkeypatch):
        import canari.mcp_gate as mg
        store, key, _pub = _make_store(tmp_path, [("npm", "x", "https://github.com/o/r")])
        idir = tmp_path / "identity"; idir.mkdir()
        ran = []
        monkeypatch.setattr(mg, "_proxy", lambda argv: ran.append(argv) or 0)
        rc = mg.main(["--store", str(store), "--key", str(key),
                      "--identity-dir", str(idir), "--registry", "npm", "--name", "x",
                      "--", "node", "s.js"])
        assert rc == 5 and ran == []
