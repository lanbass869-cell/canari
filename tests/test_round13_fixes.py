# -*- coding: utf-8 -*-
"""Round 13 regression tests: BUG-63/69/71/73/74/75/76/77 fixes.

GUARDS_AGAINST: cadence FP on active packages (mid-history dormancy), cadence
dead against live PyPI (upload_time field mismatch), acceleration baseline
pollution, silent key regeneration, PyPI native version misattribution,
H2/H3 dead code, misleading signature labels."""
import io
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canari.cadence import analyze_release_cadence, _parse_upload_time


class _FakeResp(io.BytesIO):
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


def _mock_pypi(releases):
    body = json.dumps({"releases": releases}).encode("utf-8")
    class _Opener:
        def open(self, req, timeout=None):
            return _FakeResp(body)
    return _Opener


class TestParseUploadTime:
    def test_iso_8601_field_preferred(self):
        rec = {"upload_time": "2024-12-04T17:35:26",
               "upload_time_iso_8601": "2024-12-04T17:35:26.475808Z"}
        t = _parse_upload_time(rec)
        assert t is not None
        assert t.year == 2024

    def test_plain_upload_time_fallback_gets_z(self):
        rec = {"upload_time": "2024-12-04T17:35:26"}
        t = _parse_upload_time(rec)
        assert t is not None  # BUG-77: was None before fix

    def test_garbage_returns_none(self):
        assert _parse_upload_time({"upload_time": "garbage"}) is None
        assert _parse_upload_time("not a dict") is None


class TestCadenceDormancy:
    def test_current_dormancy_fires(self):
        with patch("canari.cadence._opener", _mock_pypi({
            "0.1.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00.000000Z"}],
            "0.2.0": [{"upload_time_iso_8601": "2026-11-08T00:00:00.000000Z"}],
        })):
            f = analyze_release_cadence("pkg", "0.2.0")
        assert any("release_after_dormancy" in x["evidence_ref"] for x in f)

    def test_midhistory_gap_does_not_fire(self):
        # BUG-69: package active now (2-day gaps) with an old historical gap
        # must NOT be flagged as dormant
        with patch("canari.cadence._opener", _mock_pypi({
            "0.1.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00.000000Z"}],
            "0.2.0": [{"upload_time_iso_8601": "2026-11-01T00:00:00.000000Z"}],
            "0.3.0": [{"upload_time_iso_8601": "2026-11-07T00:00:00.000000Z"}],
            "0.4.0": [{"upload_time_iso_8601": "2026-11-09T00:00:00.000000Z"}],
        })):
            f = analyze_release_cadence("pkg", "0.4.0")
        assert not any("release_after_dormancy" in x["evidence_ref"] for x in f)


class TestCadenceAcceleration:
    def test_baseline_excludes_current_interval(self):
        # BUG-71: median must not include the tiny current interval
        releases = {
            "0.1.0": [{"upload_time_iso_8601": "2026-06-01T00:00:00.000000Z"}],
            "0.2.0": [{"upload_time_iso_8601": "2026-06-22T00:00:00.000000Z"}],  # 21d
            "0.3.0": [{"upload_time_iso_8601": "2026-07-13T00:00:00.000000Z"}],  # 21d
            "0.4.0": [{"upload_time_iso_8601": "2026-08-03T00:00:00.000000Z"}],  # 21d
            "0.5.0": [{"upload_time_iso_8601": "2026-08-03T01:00:00.000000Z"}],  # 1h burst
        }
        with patch("canari.cadence._opener", _mock_pypi(releases)):
            f = analyze_release_cadence("pkg", "0.5.0")
        assert any("release_cadence_acceleration" in x["evidence_ref"] for x in f)


class TestLoadOrGenerateKeypair:
    def test_corrupt_key_backed_up_not_destroyed(self, tmp_path, capsys):
        from canari.signing import load_or_generate_keypair
        kp = tmp_path / "k.pem"
        kp.write_bytes(b"NOT A PEM FILE")
        signer, pub, is_new = load_or_generate_keypair(str(kp))
        assert is_new is True
        out = capsys.readouterr().out
        assert "corrupt" in out.lower()
        backups = list(tmp_path.glob("k.pem.corrupt-*"))
        assert len(backups) == 1
        assert backups[0].read_bytes() == b"NOT A PEM FILE"


class TestPyPINativeVersion:
    def test_version_changes_url(self):
        from canari.pypi_native import fetch_pypi_attestations
        captured = {}
        class _Op:
            def open(self, req, timeout=None):
                captured["url"] = req.full_url
                raise OSError("stop")
        with patch("canari.pypi_native._opener", _Op):
            fetch_pypi_attestations("six", version="1.16.0")
        assert "six/1.16.0/json" in captured["url"]


class TestStateMeta:
    def test_set_component_stores_meta(self, tmp_path):
        from canari.state import StateStore
        s = StateStore(str(tmp_path / "state.json"))
        s.set_component("p", "1.0", "a" * 64, "b" * 64,
                        meta={"maintainers": ["alice"], "homepage": "https://x"})
        got = s.get_component("p")
        assert got["meta"]["maintainers"] == ["alice"]


class TestTyposquatWiring:
    def test_check_exists_and_callable(self):
        from canari.typosquat import check_typosquatting
        r = check_typosquatting("reqests", {"requests"})
        assert r is not None and "typosquatting" in r["evidence_ref"]

    def test_run_multi_source_wires_heuristics(self):
        src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "canari", "baseline.py"), encoding="utf-8").read()
        multi = src[src.find("def run_multi"):]
        assert "analyze_release_cadence" in multi
        assert "detect_metadata_anomaly" in multi
        assert "check_typosquatting" in multi


class TestVerifyCLILabel:
    def test_no_misleading_signature_label(self):
        src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "canari", "verify_cli.py"), encoding="utf-8").read()
        assert "signature (independent PAE)" not in src
        assert "canonical payload (independent PAE)" in src
