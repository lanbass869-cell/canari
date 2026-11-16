# -*- coding: utf-8 -*-
"""Regression: H3 typosquatting must not be recomputed per package.

Guard against: O(n^3) weekly sweep.
2026-11-16 measured: find_mutual_pairs() over the 620-name PyPI namespace cost
10.4s; calling it once per package (620 times) burned ~108 min of pure CPU and
pushed the weekly job past its 2h ExecutionTimeLimit, so it never wrote the
drift report. The namespace-wide result is loop-invariant, so it must be
computed once per registry.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import canari.baseline as bl
import canari.typosquat as tq


def _npm_pkgs(n):
    return [{"name": "pkg-%02d" % i, "version": "1.0.%d" % i} for i in range(n)]


def _pypi_pkgs(n):
    # "_json" mirrors what pypi_enumerate() attaches in production. Without it
    # the per-package fallback fires a real HTTPS GET at pypi.org, which would
    # make this "offline" test depend on the network.
    fake_json = {"info": {"version": "1.0.0", "author": "alice", "home_page": ""},
                 "releases": {}, "urls": []}
    return [{"name": "mcp-server-%02d" % i, "version": "1.0.%d" % i,
             "artifact_sha256": "%064x" % (i + 1), "tarball": "",
             "maintainers": ["alice"], "links": {"homepage": ""},
             "_json": dict(fake_json)}
            for i in range(n)]


def test_mutual_pairs_computed_once_per_namespace(tmp_path, monkeypatch):
    npm_n, pypi_n = 12, 9
    calls = []

    def counting_mutual(names):
        calls.append(len(names))
        return set()

    monkeypatch.setattr(tq, "find_mutual_pairs", counting_mutual)

    packument = {"time": {"created": "2025-01-01T00:00:00.000Z",
                          "modified": "2026-11-01T00:00:00.000Z"}}
    lv = {"version": "1.0.0", "tarball": "https://example.invalid/x.tgz",
          "maintainers": ["alice"], "homepage": "https://example.invalid"}

    monkeypatch.setattr(bl, "enumerate_top", lambda limit=50: _npm_pkgs(npm_n))
    monkeypatch.setattr(bl, "fetch_packument", lambda name: packument)
    monkeypatch.setattr(bl, "latest_version_info", lambda pack: dict(lv))
    monkeypatch.setattr(bl, "_download_sha256", lambda url, timeout=60: "e" * 64)
    monkeypatch.setattr(bl, "pypi_enumerate", lambda **kw: _pypi_pkgs(pypi_n))
    monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda **kw: [])
    monkeypatch.setattr(bl, "dsh_enumerate", lambda **kw: [])
    monkeypatch.setattr(bl, "native_ingest", lambda *a, **k: None)
    monkeypatch.setattr(bl, "pypi_native_ingest", lambda *a, **k: None)

    signer, pub_key = bl.generate_keypair()
    bl.run_multi(npm_limit=npm_n, pypi_limit=pypi_n, registry_limit=0,
                 dsh_limit=0, signer=signer, pub_key=pub_key,
                 out_dir=str(tmp_path))

    # Exactly one call per registry namespace - not one per package.
    assert calls == [npm_n, pypi_n], (
        "find_mutual_pairs called %d times (sizes=%s); expected 2 calls "
        "(one per namespace). A per-package call is the O(n^3) regression."
        % (len(calls), calls))

def test_mutual_pair_failure_degrades_to_error_check(tmp_path, monkeypatch):
    """If find_mutual_pairs() blows up once, every package must still get an
    auditable L2.6 row instead of silently passing or crashing the sweep."""
    def boom(names):
        raise RuntimeError("similarity backend exploded")

    monkeypatch.setattr(tq, "find_mutual_pairs", boom)

    packument = {"time": {"created": "2025-01-01T00:00:00.000Z",
                          "modified": "2026-11-01T00:00:00.000Z"}}
    lv = {"version": "1.0.0", "tarball": "https://example.invalid/x.tgz",
          "maintainers": ["alice"], "homepage": "https://example.invalid"}

    monkeypatch.setattr(bl, "enumerate_top", lambda limit=50: [])
    monkeypatch.setattr(bl, "fetch_packument", lambda name: packument)
    monkeypatch.setattr(bl, "latest_version_info", lambda pack: dict(lv))
    monkeypatch.setattr(bl, "_download_sha256", lambda url, timeout=60: "e" * 64)
    monkeypatch.setattr(bl, "pypi_enumerate", lambda **kw: _pypi_pkgs(2))
    monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda **kw: [])
    monkeypatch.setattr(bl, "dsh_enumerate", lambda **kw: [])
    monkeypatch.setattr(bl, "native_ingest", lambda *a, **k: None)
    monkeypatch.setattr(bl, "pypi_native_ingest", lambda *a, **k: None)

    signer, pub_key = bl.generate_keypair()
    res = bl.run_multi(npm_limit=0, pypi_limit=2, registry_limit=0,
                       dsh_limit=0, signer=signer, pub_key=pub_key,
                       out_dir=str(tmp_path))

    import json
    assert res["total"] == 2
    for item in res["results"]:
        bundle = json.load(open(item["bundle"], encoding="utf-8"))
        rows = [c for c in bundle["payload"]["checks"]
                if c["id"] == "L2.6_TYPOSQUATTING"]
        assert len(rows) == 1, rows
        assert rows[0]["verdict"] == "error", rows
        assert "similarity backend exploded" in rows[0]["evidence_ref"]

# ---------------------------------------------------------------------------
# corpus commitment: a similarity verdict is relative to a name set, so the
# record has to say which set. Without it the verdict cannot be re-derived
# (see experiments/corpus_dependence).
# ---------------------------------------------------------------------------

def test_corpus_commitment_is_order_and_duplicate_insensitive():
    from canari.typosquat import corpus_commitment

    a = corpus_commitment(["b-x", "A-y", "a-y"], "pypi", as_of="2026-11-16T00:00:00Z")
    b = corpus_commitment(["A-y", "b-x"], "pypi", as_of="2026-11-16T00:00:00Z")
    assert a["digest"] == b["digest"], "casefold+dedup must make order irrelevant"
    assert a["size"] == 2


def test_corpus_commitment_changes_when_the_set_changes():
    from canari.typosquat import corpus_commitment

    a = corpus_commitment(["A-y", "b-x"], "pypi", as_of="2026-11-16T00:00:00Z")
    b = corpus_commitment(["A-y", "b-x", "c-z"], "pypi", as_of="2026-11-16T00:00:00Z")
    assert a["digest"] != b["digest"]
    assert b["size"] == 3


def test_corpus_ref_is_greppable():
    from canari.typosquat import corpus_commitment, corpus_ref

    c = corpus_commitment(["A-y", "b-x"], "npm", as_of="2026-11-16T00:00:00Z")
    ref = corpus_ref(c)
    assert ref.startswith("corpus:npm:sha256:")
    assert ref.endswith(":n=2")
    assert corpus_ref(None) is None


def test_attestation_carries_the_comparison_corpus(tmp_path, monkeypatch):
    """Every L2.6 row and every attestation must name the set it compared against."""
    import json

    monkeypatch.setattr(tq, "find_mutual_pairs", lambda names: set())

    packument = {"time": {"created": "2025-01-01T00:00:00.000Z",
                          "modified": "2026-11-01T00:00:00.000Z"}}
    lv = {"version": "1.0.0", "tarball": "https://example.invalid/x.tgz",
          "maintainers": ["alice"], "homepage": "https://example.invalid"}

    monkeypatch.setattr(bl, "enumerate_top", lambda limit=50: _npm_pkgs(3))
    monkeypatch.setattr(bl, "fetch_packument", lambda name: packument)
    monkeypatch.setattr(bl, "latest_version_info", lambda pack: dict(lv))
    monkeypatch.setattr(bl, "_download_sha256", lambda url, timeout=60: "e" * 64)
    monkeypatch.setattr(bl, "pypi_enumerate", lambda **kw: _pypi_pkgs(3))
    monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda **kw: [])
    monkeypatch.setattr(bl, "dsh_enumerate", lambda **kw: [])
    monkeypatch.setattr(bl, "native_ingest", lambda *a, **k: None)
    monkeypatch.setattr(bl, "pypi_native_ingest", lambda *a, **k: None)

    signer, pub_key = bl.generate_keypair()
    res = bl.run_multi(npm_limit=3, pypi_limit=3, registry_limit=0,
                       dsh_limit=0, signer=signer, pub_key=pub_key,
                       out_dir=str(tmp_path))

    seen = {"npm": 0, "pypi": 0}
    for item in res["results"]:
        payload = json.load(open(item["bundle"], encoding="utf-8"))["payload"]
        reg = payload["subject"]["registry"]
        row = [c for c in payload["checks"] if c["id"] == "L2.6_TYPOSQUATTING"]
        assert len(row) == 1, row
        corpus = row[0].get("comparison_corpus")
        assert corpus, "L2.6 must name its comparison corpus: %s" % row[0]
        assert corpus["registry"] == reg
        assert corpus["size"] == 3
        assert corpus["digest"].startswith("sha256:")
        assert corpus["canonicalization"]
        assert corpus["as_of"]
        # the same commitment must also appear in the attestation-level refs
        assert any(r == "corpus:%s:%s:n=3" % (reg, corpus["digest"])
                   for r in payload["evidence_refs"]), payload["evidence_refs"]
        # and the attestation must still validate against the published schema:
        # comparison_corpus is an additive field, not a schema break
        from canari.schema import validate_attestation
        assert validate_attestation(payload) == [], validate_attestation(payload)
        seen[reg] += 1
    assert seen == {"npm": 3, "pypi": 3}, seen
