# -*- coding: utf-8 -*-
"""Offline tests for PyPI PEP 740 ingestion.

The live tests in test_pypi_native.py are marked `network` and skipped by
default (they were 25-58s each and could not distinguish "no attestations"
from "fetch failed"). This file covers the same code paths with a mocked
opener, so coverage no longer depends on pypi.org being reachable.
"""
import json
import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import canari.pypi_native as pn  # noqa: E402


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(payload):
    class _Op:
        def open(self, req, timeout=None):
            if isinstance(payload, Exception):
                raise payload
            return _Resp(payload)
    return lambda: _Op()


def test_fetch_reads_attestations_from_http(monkeypatch):
    payload = {"urls": [
        {"filename": "a-1.0.tar.gz", "digests": {"sha256": "aa" * 32},
         "attestations": [{"predicateType": "https://slsa.dev/provenance/v1"}]},
        {"filename": "b.whl", "digests": {"sha256": "bb" * 32}},
    ]}
    monkeypatch.setattr(pn, "_opener", _opener(payload))
    got = pn.fetch_pypi_attestations("pkg", version="1.0")
    assert len(got) == 1
    assert got[0]["filename"] == "a-1.0.tar.gz"
    assert got[0]["digest"] == "aa" * 32


def test_fetch_returns_none_when_no_attestations(monkeypatch):
    monkeypatch.setattr(pn, "_opener", _opener({"urls": [
        {"filename": "x.whl", "digests": {"sha256": "cc" * 32}}]}))
    assert pn.fetch_pypi_attestations("pkg") is None


def test_fetch_returns_none_on_network_error(monkeypatch):
    monkeypatch.setattr(pn, "_opener", _opener(OSError("down")))
    assert pn.fetch_pypi_attestations("pkg") is None


def test_fetch_uses_supplied_json(monkeypatch):
    def boom():
        raise AssertionError("must not open the network when pypi_json is given")
    monkeypatch.setattr(pn, "_opener", boom)
    got = pn.fetch_pypi_attestations(
        "pkg", pypi_json={"urls": [
            {"filename": "z.whl", "digests": {"sha256": "dd" * 32},
             "attestations": [{"predicateType": "x/y"}]}]})
    assert got and got[0]["filename"] == "z.whl"


def test_ingest_returns_none_without_files(monkeypatch):
    monkeypatch.setattr(pn, "fetch_pypi_attestations", lambda *a, **k: None)
    assert pn.ingest_pypi("pkg") is None


def test_ingest_collects_predicate_types(monkeypatch):
    files = [{"filename": "a", "digest": "ee" * 32,
              "attestations": [{"predicateType": "https://slsa.dev/provenance/v1"},
                               {"predicate_type": "https://pypi.org/attestation/v1"}]}]
    monkeypatch.setattr(pn, "fetch_pypi_attestations", lambda *a, **k: files)
    monkeypatch.setattr(pn, "convert_pep740_to_bundle", lambda a: "bundle")
    monkeypatch.setattr(pn, "verify_pypi_bundle",
                        lambda b: {"ok": True, "error": None})
    out = pn.ingest_pypi("pkg")
    assert out["present"] is True
    assert out["v1_verified"] is True
    assert "v1" in out["predicate_types"]


def test_ingest_marks_conversion_failure(monkeypatch):
    files = [{"filename": "a", "digest": "ee" * 32,
              "attestations": [{"predicateType": "x/y"}]}]

    def boom(a):
        raise ValueError("bad attestation")

    monkeypatch.setattr(pn, "fetch_pypi_attestations", lambda *a, **k: files)
    monkeypatch.setattr(pn, "convert_pep740_to_bundle", boom)
    out = pn.ingest_pypi("pkg")
    assert out["v1_verified"] is False
    assert "bad attestation" in out["v1_error"]


def test_verify_bundle_reports_error(monkeypatch):
    # force the verification path to fail without importing sigstore internals
    r = pn.verify_pypi_bundle(object())
    assert r["ok"] is False and r["error"]
