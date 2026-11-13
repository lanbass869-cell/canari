# -*- coding: utf-8 -*-
"""Heuristics must leave an auditable trace.

The project's own rule is "absence of evidence is not evidence of safety".
Violating it: cadence / anomaly / typosquatting returned [] when a package was
CLEAN, so a clean attestation carried no row proving the check had run.
Measured before the fix: 16 of 389 PyPI attestations had an L2.4 row - the other
373 were indistinguishable from "never scanned".

Regression pin: a clean returns-list must be turned into an explicit pass row by
the producer, and a module that cannot run must record unsupported/error.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari import cadence, anomaly, typosquat


class TestCleanInputsProduceNoFindings:
    """The modules themselves still return [] for clean input - that is fine."""

    def test_cadence_clean_is_empty(self):
        # no releases at all -> nothing to judge
        assert cadence.analyze_release_cadence("p", "1.0", pypi_json={"releases": {}}) == []

    def test_cadence_accepts_prefetched_json(self):
        """Must not re-fetch when the caller passes the document (perf fix)."""
        doc = {"releases": {"1.0": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}]}}
        assert cadence.analyze_release_cadence("p", "1.0", pypi_json=doc) == []

    def test_anomaly_clean_is_empty(self):
        meta = {"maintainers": ["alice"], "homepage": "https://x.example"}
        assert anomaly.detect_metadata_anomaly(meta, meta) == []

    def test_typosquat_clean_is_none(self):
        assert typosquat.check_typosquatting("mcp-server-foo", {"mcp-server-foo"}) is None


class TestPypiNativeAcceptsPrefetched:
    def test_ingest_accepts_pypi_json(self):
        from canari import pypi_native
        # no urls -> no attestations -> None, and no network call is made
        assert pypi_native.ingest_pypi("p", "1", pypi_json={"urls": []}) is None


class TestProducerRecordsPass:
    """The scan loop must convert a clean result into an explicit pass row."""

    @staticmethod
    def _src():
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return open(os.path.join(root, "canari", "baseline.py"), encoding="utf-8").read()

    def test_cadence_pass_row_emitted(self):
        src = self._src()
        assert '"id": "L2.4_RELEASE_CADENCE", "verdict": "pass"' in src
        assert "no cadence anomaly" in src

    def test_anomaly_pass_row_emitted(self):
        src = self._src()
        assert '"id": "L2.5_METADATA_ANOMALY", "verdict": "pass"' in src

    def test_typosquat_pass_row_emitted(self):
        src = self._src()
        assert '"id": "L2.6_TYPOSQUATTING", "verdict": "pass"' in src

    def test_unavailable_data_is_unsupported_not_pass(self):
        src = self._src()
        assert '"id": "L2.4_RELEASE_CADENCE", "verdict": "unsupported"' in src
