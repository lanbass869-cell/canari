# -*- coding: utf-8 -*-
"""Shared pytest configuration.

Why a `network` marker exists: the suite had tests labelled "offline" that
called functions performing live HTTP (build_attestation runs native_ingest with
a 90-second budget; a pypi test fetched real PyPI metadata). On a slow link the
suite went from 101s to 778s, and every one of those seconds was a timeout, not
work.

Two rules, both enforced here rather than by discipline:

1. A test that needs the open internet is marked `network`. It is skipped by
   default and runs only with CANARI_NETWORK_TESTS=1. A suite whose runtime
   depends on someone else's server is a suite people stop running.
2. A test that claims to be offline must not reach the network. The fixtures
   below patch the two live entry points at module scope so an accidental
   dependency fails loudly (or at least fast) instead of silently costing 90
   seconds.
"""
import os

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "network: hits the open internet; skipped unless "
                   "CANARI_NETWORK_TESTS=1")


def pytest_collection_modifyitems(config, items):
    if os.environ.get("CANARI_NETWORK_TESTS") == "1":
        return
    skip = pytest.mark.skip(
        reason="network test; set CANARI_NETWORK_TESTS=1 to run")
    for item in items:
        if "network" in item.keywords:
            item.add_marker(skip)


@pytest.fixture()
def no_native_ingest(monkeypatch):
    """Cut the live npm provenance fetch out of build_attestation.

    build_attestation() calls native_ingest() inside a 90-second budget. Tests
    that do not care about native provenance must not pay that budget, and must
    not silently depend on npm being reachable.
    """
    import canari.baseline as bl
    monkeypatch.setattr(bl, "native_ingest", lambda *a, **k: None)
    return monkeypatch


@pytest.fixture()
def no_pypi_native(monkeypatch):
    import canari.baseline as bl
    monkeypatch.setattr(bl, "pypi_native_ingest", lambda *a, **k: None)
    return monkeypatch
