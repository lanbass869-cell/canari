# -*- coding: utf-8 -*-
"""Tests for the OpenTimestamps anchor wrapper.

The security-relevant behaviour is the stage classifier: a *pending* calendar
acknowledgement proves nothing about the past, and the script must never report
it as a Bitcoin anchor. These tests run entirely offline against synthetic
Timestamp objects.
"""
import hashlib
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

pytest.importorskip("opentimestamps")

import anchor_ots  # noqa: E402
from opentimestamps.core.op import OpSHA256  # noqa: E402
from opentimestamps.core.notary import (BitcoinBlockHeaderAttestation,  # noqa: E402
                                        PendingAttestation)
from opentimestamps.core.timestamp import Timestamp  # noqa: E402


def test_digest_of_matches_sha256(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello")
    assert anchor_ots.digest_of(str(p)) == hashlib.sha256(b"hello").digest()


def test_stage_pending():
    ts = Timestamp(b"\x00" * 32)
    ts.attestations.add(PendingAttestation("https://example.invalid"))
    assert anchor_ots._stage(ts) == "pending"


def test_stage_bitcoin_beats_pending():
    ts = Timestamp(b"\x00" * 32)
    ts.attestations.add(PendingAttestation("https://example.invalid"))
    child = ts.ops.add(OpSHA256())
    child.attestations.add(BitcoinBlockHeaderAttestation(800000))
    assert anchor_ots._stage(ts) == "bitcoin"


def test_stage_unknown_without_attestations():
    assert anchor_ots._stage(Timestamp(b"\x00" * 32)) == "unknown"


def test_status_without_proof_is_error(tmp_path):
    p = tmp_path / "x.json"
    p.write_bytes(b"{}")

    class A:
        target = str(p)

    assert anchor_ots.cmd_status(A()) == 3


def test_roundtrip_proof_file(tmp_path):
    p = tmp_path / "x.json"
    p.write_bytes(b"{}")
    digest = hashlib.sha256(b"{}").digest()
    ts = Timestamp(digest)
    ts.attestations.add(PendingAttestation("https://example.invalid"))
    proof = str(p) + ".ots"
    n = anchor_ots._save(ts, proof)
    assert n > 0
    got = anchor_ots._load(proof, digest)
    assert anchor_ots._stage(got) == "pending"


def test_no_calendar_reachable_is_failure(tmp_path, monkeypatch):
    p = tmp_path / "x.json"
    p.write_bytes(b"{}")

    def boom(*a, **k):
        raise OSError("no network")

    monkeypatch.setattr("opentimestamps.calendar.RemoteCalendar.submit", boom)

    class A:
        target = str(p)
        timeout = 1

    assert anchor_ots.cmd_submit(A()) == 3


class TestMutableTargetGuard:
    """The bug this encodes, found in production 2026-11-15: an OTS proof was
    made over docs/log/head-latest.json. The next daily run rewrote that file,
    so the commitment no longer matched any bytes on disk and all four
    calendars returned CommitmentNotFoundError -- the proof was permanently
    dead while still looking like a valid .ots file. Timestamps must only ever
    cover write-once bytes."""

    @pytest.mark.parametrize("name", [
        "head-latest.json", "log.jsonl", "heads.jsonl", "index.html",
    ])
    def test_mutable_names_are_refused(self, tmp_path, name):
        p = tmp_path / name
        p.write_bytes(b"{}")
        assert anchor_ots.check_mutable_target(str(p)) != ""

    def test_content_addressed_head_is_allowed(self, tmp_path):
        p = tmp_path / "000021-92f6b635deadbeef.json"
        p.write_bytes(b"{}")
        assert anchor_ots.check_mutable_target(str(p)) == ""

    def test_submit_refuses_mutable_target(self, tmp_path):
        # No calendar should be contacted for a file we already refuse.
        p = tmp_path / "head-latest.json"
        p.write_bytes(b"{}")

        def boom(*a, **k):            # pragma: no cover - must not be called
            raise AssertionError("submitted a mutable target")

        import opentimestamps.calendar as cal
        old = cal.RemoteCalendar.submit
        cal.RemoteCalendar.submit = boom
        try:
            class A:
                target = str(p)
                timeout = 1
            assert anchor_ots.cmd_submit(A()) == 3
        finally:
            cal.RemoteCalendar.submit = old
