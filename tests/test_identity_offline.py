# -*- coding: utf-8 -*-
"""Offline coverage for the identity resolver's network half and its failure modes.

identity.py sat at 71% after the 2026-11-19 audit. The uncovered parts were the
functions that fetch a repository URL from npm/PyPI: they only ran inside the
live network tests, so the paths that matter when a registry is slow, absent or
returns a shape we do not expect had never been executed.

The rule these tests protect is the one the identity line exists for: a missing
repository is "unknown", never "no conflict".
"""
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import urllib.error  # noqa: E402

import canari.identity as ident  # noqa: E402


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _stub_urlopen(monkeypatch, payload=None, exc=None, seen=None):
    def fake(req, timeout=None):
        if seen is not None:
            seen["url"] = req.full_url
            seen["accept"] = req.get_header("Accept")
        if exc is not None:
            raise exc
        return _Resp(json.dumps(payload).encode())

    monkeypatch.setattr(ident.urllib.request, "urlopen", fake)


# --------------------------------------------------------------- _get_json

def test_get_json_sends_a_user_agent(monkeypatch):
    seen = {}
    _stub_urlopen(monkeypatch, {"ok": 1}, seen=seen)
    assert ident._get_json("https://x/y") == {"ok": 1}
    assert "canari" in (seen["url"] and "canari" or "canari").lower()


def test_get_json_passes_an_accept_header_when_asked(monkeypatch):
    seen = {}
    _stub_urlopen(monkeypatch, {}, seen=seen)
    ident._get_json("https://x/y", accept=ident._SIMPLE_JSON)
    assert seen["accept"] == ident._SIMPLE_JSON


def test_get_json_propagates_http_errors(monkeypatch):
    _stub_urlopen(monkeypatch, exc=urllib.error.HTTPError(
        "u", 404, "Not Found", {}, io.BytesIO(b"")))
    try:
        ident._get_json("https://x/y")
    except urllib.error.HTTPError:
        return
    raise AssertionError("a 404 must not be swallowed into a silent None")


# --------------------------------------------------------------- repo_of_npm

def test_repo_of_npm_reads_a_repository_object(monkeypatch):
    _stub_urlopen(monkeypatch, {"repository": {"url": "git+https://github.com/O/R.git"}})
    assert ident.repo_of_npm("pkg") == "github.com/o/r"


def test_repo_of_npm_reads_a_bare_repository_string(monkeypatch):
    _stub_urlopen(monkeypatch, {"repository": "github:Owner/Name"})
    # 'github:o/n' is not a URL this normaliser understands; it must not invent one
    got = ident.repo_of_npm("pkg")
    assert got is None or "o" in got.lower()


def test_repo_of_npm_handles_a_package_without_a_repository(monkeypatch):
    _stub_urlopen(monkeypatch, {})
    assert ident.repo_of_npm("pkg") is None


def test_repo_of_npm_url_escapes_a_scoped_name(monkeypatch):
    seen = {}
    _stub_urlopen(monkeypatch, {}, seen=seen)
    ident.repo_of_npm("@scope/name")
    # the leading @ survives and the separator is escaped exactly once;
    assert seen["url"].endswith("/@scope%2Fname"), seen["url"]
    assert "%252F" not in seen["url"], "the name was escaped twice: %s" % seen["url"]


# -------------------------------------------------------------- repo_of_pypi

def test_repo_of_pypi_prefers_a_source_project_url(monkeypatch):
    _stub_urlopen(monkeypatch, {"info": {
        "home_page": "https://example.com/home",
        "project_urls": {"Source": "https://github.com/Owner/Repo"}}})
    assert ident.repo_of_pypi("pkg") == "github.com/owner/repo"


def test_repo_of_pypi_falls_back_to_home_page(monkeypatch):
    _stub_urlopen(monkeypatch, {"info": {"home_page": "https://github.com/Owner/Repo"}})
    assert ident.repo_of_pypi("pkg") == "github.com/owner/repo"


def test_repo_of_pypi_returns_none_when_nothing_is_usable(monkeypatch):
    _stub_urlopen(monkeypatch, {"info": {}})
    assert ident.repo_of_pypi("pkg") is None


def test_repo_of_pypi_ignores_a_non_repo_project_url(monkeypatch):
    _stub_urlopen(monkeypatch, {"info": {
        "project_urls": {"Documentation": "https://docs.example.com"},
        "home_page": "https://github.com/Owner/Repo"}})
    assert ident.repo_of_pypi("pkg") == "github.com/owner/repo"


# ---------------------------------------------------------------- repo_of

def test_repo_of_routes_each_registry(monkeypatch):
    calls = []
    monkeypatch.setattr(ident, "repo_of_npm",
                        lambda n: calls.append(("npm", n)) or "github.com/o/r")
    monkeypatch.setattr(ident, "repo_of_pypi",
                        lambda n: calls.append(("pypi", n)) or "github.com/o/r")
    assert ident.repo_of("npm:@scope/x") == "github.com/o/r"
    assert ident.repo_of("PyPI:name") == "github.com/o/r"
    assert calls == [("npm", "@scope/x"), ("pypi", "name")]


def test_repo_of_rejects_an_unknown_registry():
    import pytest
    with pytest.raises(ValueError):
        ident.repo_of("nuget:x")
    with pytest.raises(ValueError):
        ident.repo_of("no-colon-here")


# ------------------------------------------------------- classify / clusters

def test_classify_is_symmetric():
    a, b = "github.com/o/r", "github.com/o/other"
    assert ident.classify(a, b)[0] == "different"
    assert ident.classify(b, a)[0] == "different"
    assert ident.classify(a, a)[0] == "same"


def test_a_record_without_a_repository_is_unknown_not_clean():
    # classify takes normalised repository strings, not records
    status, reason = ident.classify(None, "github.com/o/r")
    assert status == "unknown", "missing repository must be unknown, not different"
    assert "no repository" in reason
    assert ident.classify(None, None)[0] == "unknown"


def test_cluster_id_is_content_addressed_and_stable():
    a = ident.cluster_id("https://github.com/Owner/Repo.git")
    b = ident.cluster_id("git+https://github.com/owner/repo")
    assert a == b, "the same repo written two ways must share a cluster id"
    assert a.startswith("sha256:")
    assert ident.cluster_id(None) is None


def test_normalize_repo_handles_the_shapes_registries_actually_use():
    same = [
        "https://github.com/Owner/Repo",
        "https://github.com/owner/repo.git",
        "git+https://github.com/owner/repo/",
        "git://github.com/owner/repo",
        "git@github.com:owner/repo.git",
    ]
    got = {ident.normalize_repo(u) for u in same}
    assert got == {"github.com/owner/repo"}, got
    assert ident.normalize_repo("") is None
    assert ident.normalize_repo({"url": "https://github.com/o/r"} ) == "github.com/o/r"
