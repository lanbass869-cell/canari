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
