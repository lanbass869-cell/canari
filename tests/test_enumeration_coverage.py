# -*- coding: utf-8 -*-
"""Enumeration coverage: the head of each ecosystem must be in the ledger.

Two real defects found 2026-11-12 while trying to showcase the ledger with
popular MCP packages:

  npm   `scope:modelcontextprotocol` returns total=0 on npm's search backend,
        so that query had ALWAYS contributed nothing. The official head
        packages (@modelcontextprotocol/server-filesystem, .../server-everything,
        .../server, .../server-memory) were absent from the ledger entirely.
  PyPI  matching names were truncated alphabetically ("[:limit]"), so with
        limit=100 the scan stopped at mcp-server-dagster and mcp-server-fetch
        (position 177 of 620) had never been scanned.

These tests pin both. They are offline - they exercise the selection logic and
the query list, not the network.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari import npm_enum


class TestNpmQueries:
    def test_no_unsupported_scope_qualifier(self):
        """npm search ignores `scope:`; such a query silently returns 0."""
        offenders = [q for q in npm_enum.QUERIES if q.strip().startswith("scope:")]
        assert not offenders, (
            "npm search does not implement the scope: qualifier (measured: "
            "total=0), so these queries contribute nothing: %s" % offenders)

    def test_official_scope_is_searched(self):
        assert any("modelcontextprotocol" in q for q in npm_enum.QUERIES), (
            "the official @modelcontextprotocol packages must be reachable by "
            "at least one query; got %s" % npm_enum.QUERIES)


class TestPypiSelection:
    """The selection helper must never silently drop the alphabetical tail."""

    @staticmethod
    def _names(n=620, prefix="mcp-server-"):
        return ["%s%04d" % (prefix, i) for i in range(n)]

    def test_full_coverage_when_limit_exceeds_population(self):
        names = self._names(620)
        picked = npm_enum._stratified_pick(names, 700, what="test")
        assert picked == names, "with a large enough cap ALL packages must be kept"

    def test_spread_when_capped(self):
        names = self._names(620)
        picked = npm_enum._stratified_pick(names, 100, what="test")
        assert len(picked) == 100
        assert picked[-1] >= names[600], "selection stopped early: %r" % picked[-1]

    def test_deterministic(self):
        names = self._names()
        assert (npm_enum._stratified_pick(names, 50, what="t")
                == npm_enum._stratified_pick(names, 50, what="t"))

    def test_zero_limit_returns_nothing(self):
        assert npm_enum._stratified_pick(self._names(), 0) == []

    def test_reports_how_many_were_dropped(self, capsys):
        npm_enum._stratified_pick(self._names(620), 100, what="pypi:drop")
        out = capsys.readouterr().out
        assert "dropping 520" in out, out


class TestPypiDefault:
    def test_default_limit_covers_current_population(self):
        """620 packages match 'mcp-server-' today; the default must cover them."""
        import inspect
        sig = inspect.signature(npm_enum.pypi_enumerate)
        assert sig.parameters["limit"].default >= 700

    def test_weekly_job_default_covers_population(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        src = open(os.path.join(root, "run_weekly.py"), encoding="utf-8").read()
        assert 'CANARI_PYPI_DEEP", "700"' in src, (
            "run_weekly must default to a cap that covers every mcp-server-* "
            "package, otherwise the ledger goes back to alphabetical truncation")
