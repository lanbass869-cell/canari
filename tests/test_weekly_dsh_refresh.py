# -*- coding: utf-8 -*-
"""Regression: the weekly job must re-verify dsh, not just record metadata.

Before: deep_scan_with_metadata called run_multi(dsh_limit=0), so dsh only
got a metadata pass and the 500+ dsh attestations were never re-checked -
their verdicts aged indefinitely. Now the tracked dsh components are passed
to dsh_enumerate(names=...) every run.
"""
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_dsh_enumerate_names_filters_full_index(monkeypatch):
    """names=... must filter the whole index, not a truncated prefix."""
    import canari.npm_enum as ne

    class _Resp:
        def __init__(self, payload):
            self._b = json.dumps(payload).encode()
        def read(self):
            return self._b
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    plugins = [{"name": "p%d" % i, "author": "a"} for i in range(50)]
    monkeypatch.setattr(ne, "_opener", lambda: type('O', (), {
        "open": lambda self, req, timeout=0: _Resp({"plugins": plugins})})())

    got = ne.dsh_enumerate(limit=3, with_security=False, names={"p40", "p7"})
    assert sorted(x["name"] for x in got) == ["p40", "p7"]

    prefix = ne.dsh_enumerate(limit=3, with_security=False)
    assert [x["name"] for x in prefix] == ["p0", "p1", "p2"]


def test_run_multi_accepts_dsh_names(tmp_path, monkeypatch):
    import canari.baseline as bl
    monkeypatch.setattr(bl, "enumerate_top", lambda limit=50, dedupe=True: [])
    monkeypatch.setattr(bl, "pypi_enumerate", lambda limit=500, cache_path=None: [])
    monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda limit=500: [])
    monkeypatch.setattr(bl, "_runner_source_digest", lambda: "d" * 64)
    seen = {}

    def fake_dsh(limit=500, with_security=True, names=None):
        seen["names"] = names
        return []
    monkeypatch.setattr(bl, "dsh_enumerate", fake_dsh)

    bl.run_multi(npm_limit=0, pypi_limit=0, registry_limit=0, dsh_limit=0,
                 dsh_names=["a", "b"], out_dir=str(tmp_path))
    assert seen["names"] == ["a", "b"]


def test_deep_scan_passes_tracked_dsh_names(tmp_path, monkeypatch):
    """deep_scan_with_metadata must hand run_multi the components the ledger
    already tracks, so they are re-verified instead of silently aging."""
    import canari.baseline as bl

    out = tmp_path
    (out / "attestations").mkdir(parents=True)
    st = {"components": {"dsh-registry:x": {"version": "1", "sha256": "",
                         "attestation_digest": ""},
                         "dsh-registry:y": {"version": "1", "sha256": "",
                         "attestation_digest": ""},
                         "npm:z": {"version": "1", "sha256": "",
                                  "attestation_digest": ""}}}
    (out / "state.json").write_text(json.dumps(st), encoding="utf-8")

    captured = {}
    monkeypatch.setattr(bl, "run_multi",
                        lambda **kw: captured.update(kw) or {
                            "total": 0, "errors": 0, "feed": str(out / "feed.json"),
                            "by_registry": {}, "results": []})
    monkeypatch.setattr(bl, "metadata_scan", lambda *a, **k: [])

    bl.deep_scan_with_metadata(npm_deep=0, pypi_deep=0, npm_meta=0,
                               pypi_meta=0, dsh_meta=0, out_dir=str(out))
    assert captured["dsh_names"] == ["x", "y"]
