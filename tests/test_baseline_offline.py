# -*- coding: utf-8 -*-
"""Baseline attestation builder tests (offline: no npm calls, injected meta)."""

# GUARDS_AGAINST: false pass on download failure (zero sha256), false fail on empty description, TTL drift
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canari.baseline import build_attestation, _sha512_integrity_to_hex

SCENARIO = "c" * 64


class TestIntegrity:
    def test_sha512_b64_to_hex(self):
        import base64
        raw = bytes(range(64))
        s = "sha512-" + base64.b64encode(raw).decode()
        assert _sha512_integrity_to_hex(s) == raw.hex()

    def test_bad_format_none(self):
        assert _sha512_integrity_to_hex("sha256-abc") is None
        assert _sha512_integrity_to_hex("") is None
        assert _sha512_integrity_to_hex("sha512-!!!") is None


class TestBuildAttestation:
    # build_attestation() calls native_ingest() with a 90-second budget. This
    # file says "offline: no npm calls" in its own docstring, and it was not
    # true: the fetch ran for real and cost up to 16s per test.
    @pytest.fixture(autouse=True)
    def _offline(self, no_native_ingest):
        return no_native_ingest

    @pytest.fixture(autouse=True)
    def _mock_download(self, monkeypatch):
        """Tests are offline: fake successful tarball download."""
        import canari.baseline as bl
        monkeypatch.setattr(bl, "_download_sha256", lambda url, timeout=60: "e" * 64)

    def _meta(self, **kw):
        import base64 as _b64; integ = "sha512-" + _b64.b64encode(bytes(64)).decode()
        m = {"version": "1.2.3", "dist_integrity": integ,
             "tarball": "https://registry.npmjs.org/fake/-/fake-1.2.3.tgz",
             "maintainers": ["alice"], "fetch_ms": 5}
        m.update(kw)
        return m

    def test_all_pass(self):
        search_meta = {"description": "A thing", "links": {"homepage": "https://x"}}
        # Pass the packument so L2.4 can actually be evaluated. Without it the
        # cadence check now reports "unknown" (it used to fetch PyPI with an npm
        # name and report that as "pass"), and an unrun check correctly keeps
        # the verdict out of a clean "pass".
        packument = {"time": {"created": "2025-01-01T00:00:00.000Z",
                              "modified": "2026-11-01T00:00:00.000Z",
                              "1.0.0": "2026-05-01T00:00:00.000Z",
                              "1.2.3": "2026-11-01T00:00:00.000Z"}}
        att = build_attestation("pkg-a", self._meta(), search_meta, SCENARIO,
                                packument=packument)
        assert att["verdict"] == "pass", [c["id"] for c in att["checks"]
                                           if c["verdict"] != "pass"]
        ids = [c["id"] for c in att["checks"]]
        assert "L1.1_REGISTRY_PRESENT" in ids and "L2.3_MANIFEST_FIELDS" in ids

    def test_no_maintainers_fails_L22(self):
        att = build_attestation("pkg-b", self._meta(maintainers=[]),
                                {"description": "d"}, SCENARIO)
        assert att["verdict"] == "fail"
        l22 = [c for c in att["checks"] if c["id"] == "L2.2_MAINTAINER_SET"][0]
        assert l22["verdict"] == "fail"

    def test_download_failure_fails_L21_and_zero_sha256(self, monkeypatch):
        # download FAILED (mock returns None) -> check FAIL; schema still
        # requires a valid hex string so we bind all-zeros and record failure.
        import canari.baseline as bl
        monkeypatch.setattr(bl, "_download_sha256", lambda url, timeout=60: None)
        att = build_attestation("pkg-c", self._meta(),
                                {"description": "d"}, SCENARIO)
        l21 = [c for c in att["checks"] if c["id"] == "L2.1_ARTIFACT_HASH"][0]
        assert l21["verdict"] == "fail"
        assert att["subject"]["artifact_sha256"] == "0" * 64

    def test_empty_description_pass_with_findings(self):
        att = build_attestation("pkg-d", self._meta(), {"description": ""}, SCENARIO)
        assert att["verdict"] == "pass-with-findings"

    def test_expiry_exceeds_the_scan_cadence(self):
        # was 7 days for a 7-day scan -- zero margin, so one late run expired
        # every record and the gate blocked everything. The TTL must cover at
        # least two scan cycles.
        att = build_attestation("pkg-e", self._meta(), {"description": "d"}, SCENARIO)
        assert att["expires_at"] > att["generated_at"]
        import datetime
        g = datetime.datetime.strptime(att["generated_at"], "%Y-%m-%dT%H:%M:%SZ")
        e = datetime.datetime.strptime(att["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
        days = (e - g).total_seconds() / 86400
        assert days >= 14, (
            "TTL is %.1f days for a weekly scan: one missed run blocks the gate" % days)

    def test_scenario_hash_recorded(self):
        att = build_attestation("pkg-f", self._meta(), {"description": "d"}, SCENARIO)
        assert att["scenario_sha256"] == SCENARIO

