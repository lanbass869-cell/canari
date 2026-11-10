# -*- coding: utf-8 -*-
"""Final: fallback-dataset failure path."""
import io as _io
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class R(_io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def test_fallback_dataset_failure_returns_empty(monkeypatch):
    import canari.npm_enum as ne
    class _Op:
        def open(self, req, timeout=None):
            u = req.full_url
            if "/simple" in u:
                raise OSError("index down")
            raise OSError("top-pypi down too")
    monkeypatch.setattr(ne, "_opener", lambda: _Op())
    assert ne.pypi_enumerate(prefix="mcp-", limit=5) == []
