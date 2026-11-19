# -*- coding: utf-8 -*-
"""Native-provenance ingestion must not fail silently.

Found 2026-11-19: build_attestation wrapped the native ingest in

    try:
        native_prov = _with_timeout(...)
    except Exception:
        native_prov = None

so a broken ingestion and an upstream that simply publishes nothing produced
byte-identical records. Measured consequence: npm shows 52.5% (559/1064) native
provenance while PyPI shows 0% (0/2051) -- and nothing in the data could say
whether PyPI's zero was "nobody publishes attestations" or "our pipeline is
down".

The record now carries an explicit L1.3_NATIVE_PROVENANCE check with three
distinguishable outcomes, and a failure is written to the dead-letter log when
the caller supplies one.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import canari.baseline as baseline  # noqa: E402
from canari.dead_letter import DeadLetterLog  # noqa: E402

SCENARIO = "d" * 64


def _meta(registry="npm"):
    return {"name": "pkg", "version": "1.0.0", "registry": registry,
            "tarball": "", "integrity": "", "maintainers": [],
            "description": "d", "homepage": "https://x", "fetch_ms": 0}


def _check(att):
    hits = [c for c in att["checks"] if c["id"] == "L1.3_NATIVE_PROVENANCE"]
    assert len(hits) == 1, "expected exactly one L1.3 check, got %r" % (att["checks"],)
    return hits[0]


def test_absence_of_native_attestations_is_recorded_as_a_check(monkeypatch):
    monkeypatch.setattr(baseline, "native_ingest", lambda name, version: None)
    att = baseline.build_attestation("pkg", _meta(), {}, SCENARIO)
    check = _check(att)
    assert check["verdict"] == "pass"
    assert "no native attestation published" in check["evidence_ref"]


def test_a_native_attestation_is_recorded(monkeypatch):
    monkeypatch.setattr(baseline, "native_ingest",
                        lambda name, version: {"present": True, "v1_verified": True})
    att = baseline.build_attestation("pkg", _meta(), {}, SCENARIO)
    assert att["native_provenance"]["present"] is True
    assert _check(att)["verdict"] == "pass"


def test_an_ingestion_failure_is_an_error_check_not_a_silent_none(monkeypatch):
    def boom(name, version):
        raise RuntimeError("upstream returned garbage")

    monkeypatch.setattr(baseline, "native_ingest", boom)
    att = baseline.build_attestation("pkg", _meta(), {}, SCENARIO)
    check = _check(att)
    assert check["verdict"] == "error", (
        "a failed ingestion must not look like 'upstream has none'")
    assert "upstream returned garbage" in check["evidence_ref"]
    assert att.get("native_provenance") is None


def test_the_failure_reaches_the_dead_letter_log(monkeypatch, tmp_path):
    def boom(name, version):
        raise RuntimeError("connection reset")

    monkeypatch.setattr(baseline, "native_ingest", boom)
    dead = DeadLetterLog(str(tmp_path / "dead.json"))
    baseline.build_attestation("pkg", _meta(), {}, SCENARIO, dead=dead)
    assert len(dead.entries) == 1
    entry = dead.entries[0]
    assert entry["operation"] == "native_ingest"
    assert entry["target"] == "pkg@1.0.0"
    assert "connection reset" in entry["error"]


def test_the_three_outcomes_are_distinguishable(monkeypatch):
    """found / not-published / we-broke must not collapse into two states."""
    monkeypatch.setattr(baseline, "native_ingest", lambda n, v: None)
    absent = _check(baseline.build_attestation("p", _meta(), {}, SCENARIO))

    monkeypatch.setattr(baseline, "native_ingest", lambda n, v: {"present": True})
    found = _check(baseline.build_attestation("p", _meta(), {}, SCENARIO))

    def boom(n, v):
        raise RuntimeError("x")
    monkeypatch.setattr(baseline, "native_ingest", boom)
    broken = _check(baseline.build_attestation("p", _meta(), {}, SCENARIO))

    assert absent["evidence_ref"] != broken["evidence_ref"]
    assert broken["verdict"] == "error"
    assert absent["verdict"] != "error"
    assert found["evidence_ref"] != absent["evidence_ref"]
