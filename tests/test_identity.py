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
