# -*- coding: utf-8 -*-
"""Offline coverage for the native-ingestion transport and the verifier's
failure path.

Found 2026-11-19 by the deficiency audit: native.py sat at 63% because the only
tests of fetch_attestations and verify_v1_cert were the live-network ones, which
are skipped unless CANARI_NETWORK_TESTS=1. So the failure paths -- the ones that
matter when the registry is down or the bundle is malformed -- had never been
executed at all.
"""
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import canari.native as native  # noqa: E402


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_fetch_attestations_parses_a_real_shaped_body(monkeypatch):
    body = json.dumps({"attestations": [{"predicateType": ".../provenance/v1"}]}).encode()
    seen = {}

    class _Opener:
        def open(self, req, timeout=None):
            seen["url"] = req.full_url
            seen["timeout"] = timeout
            return _Resp(body)

    # _opener() builds a fresh object on every call, so patch the factory.
    monkeypatch.setattr(native, "_opener", lambda: _Opener())
    got = native.fetch_attestations("pkg", "1.0.0", timeout=11)
    assert got and got["attestations"][0]["predicateType"].endswith("v1")
    assert "pkg@1.0.0" in seen["url"]
    assert seen["timeout"] == 11


def test_fetch_attestations_returns_none_when_the_registry_errors(monkeypatch):
    def boom(*a, **k):
        raise OSError("connection reset")
    monkeypatch.setattr(native, "_opener", lambda: type("O", (), {"open": boom})())
    assert native.fetch_attestations("pkg", "1.0.0") is None


def test_fetch_attestations_returns_none_on_a_404(monkeypatch):
    import urllib.error

    def not_found(*a, **k):
        raise urllib.error.HTTPError("u", 404, "Not Found", {}, io.BytesIO(b""))
    monkeypatch.setattr(native, "_opener", lambda: type("O", (), {"open": not_found})())
    assert native.fetch_attestations("missing", "1.0.0") is None


def test_verify_v1_cert_reports_failure_instead_of_raising():
    """A malformed bundle must come back as ok=False, never as an exception:
    a crash here would take down the whole scan for one bad package."""
    got = native.verify_v1_cert({"not": "a bundle"})
    assert got["ok"] is False
    assert got["error"], "the failure must carry a reason"
    assert got["identity"] is None


def test_verify_v1_cert_rejects_a_string_that_is_not_json():
    got = native.verify_v1_cert("definitely not a bundle")
    assert got["ok"] is False


def test_ingest_returns_none_when_there_is_no_attestation(monkeypatch):
    monkeypatch.setattr(native, "fetch_attestations", lambda n, v, timeout=30: None)
    assert native.ingest("pkg", "1.0.0") is None


def test_ingest_returns_none_on_an_empty_attestation_list(monkeypatch):
    monkeypatch.setattr(native, "fetch_attestations",
                        lambda n, v, timeout=30: {"attestations": []})
    assert native.ingest("pkg", "1.0.0") is None


def test_ingest_records_v0_presence_without_claiming_verification(monkeypatch):
    """A v0.1 publicKey bundle cannot be verified here, so the record must say
    "presence only" and must not set v1_verified to True."""
    monkeypatch.setattr(native, "fetch_attestations", lambda n, v, timeout=30: {
        "attestations": [{"predicateType": ".../publish/v0.1",
                          "bundle": {"verificationMaterial": {"publicKey": {"hint": "x"}}}}]
    })
    got = native.ingest("pkg", "1.0.0")
    assert got["present"] is True
    assert got["v0_presence_only"] == 1
    assert got["v1_verified"] is None, "v0 presence must never read as v1 verification"


def test_ingest_does_not_call_the_verifier_for_v0_only(monkeypatch):
    called = []
    monkeypatch.setattr(native, "fetch_attestations", lambda n, v, timeout=30: {
        "attestations": [{"predicateType": ".../publish/v0.1",
                          "bundle": {"verificationMaterial": {"publicKey": {"hint": "x"}}}}]
    })
    monkeypatch.setattr(native, "verify_v1_cert", lambda b, i=None: called.append(b) or {})
    native.ingest("pkg", "1.0.0")
    assert called == []


def test_ingest_verifies_the_first_v1_entry(monkeypatch):
    seen = []
    monkeypatch.setattr(native, "fetch_attestations", lambda n, v, timeout=30: {
        "attestations": [{"predicateType": ".../provenance/v1",
                          "bundle": {"verificationMaterial": {"certificate": "c"}}}]
    })
    monkeypatch.setattr(native, "verify_v1_cert",
                        lambda b, i=None: seen.append(b) or {
                            "ok": True, "identity": "repo:o/r", "error": None})
    got = native.ingest("pkg", "1.0.0")
    assert got["v1_verified"] is True
    assert got["v1_identity"] == "repo:o/r"
    assert seen and seen[0]["verificationMaterial"]["certificate"] == "c"
