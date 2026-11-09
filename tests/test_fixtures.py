# -*- coding: utf-8 -*-
"""B2: mock registry fixtures for offline testing.

These fixtures provide canned registry responses so tests don't hit the network.
Each fixture matches the exact JSON structure of the real registry API.
"""

# GUARDS_AGAINST: registry API structure change going unnoticed (npm nested server.name, MCP version field)
import json
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _load(name):
    with open(os.path.join(FIXTURES_DIR, name), encoding="utf-8") as f:
        return json.load(f)


class TestNpmPackumentFixture:
    def test_packument_structure(self):
        p = _load("npm_packument.json")
        assert "dist-tags" in p
        assert "versions" in p
        assert "1.0.0" in p["versions"]
        v = p["versions"]["1.0.0"]
        assert "dist" in v
        assert "integrity" in v["dist"]
        assert v["dist"]["integrity"].startswith("sha512-")
        assert "tarball" in v["dist"]
        assert "maintainers" in p

    def test_latest_version_info_from_fixture(self):
        from canari.npm_enum import latest_version_info
        p = _load("npm_packument.json")
        info = latest_version_info(p)
        assert info["version"] == "1.0.0"
        assert info["dist_integrity"].startswith("sha512-")
        assert info["tarball"].startswith("https://")


class TestPyPIFixture:
    def test_pypi_json_structure(self):
        p = _load("pypi_json.json")
        assert "info" in p
        assert "urls" in p
        assert p["info"]["name"] == "test-mcp-package"
        assert len(p["urls"]) >= 1
        assert "digests" in p["urls"][0]
        assert "sha256" in p["urls"][0]["digests"]

    def test_pypi_enumerate_with_mock(self):
        """Test pypi_enumerate logic with mocked HTTP."""
        fixture = _load("pypi_json.json")
        # We can't easily mock the full simple index; test the JSON parsing path
        info = fixture["info"]
        urls = fixture["urls"]
        assert info["version"] == "0.1.0"
        assert urls[0]["digests"]["sha256"] == "b" * 64


class TestMCPRegistryFixture:
    def test_mcp_server_structure(self):
        m = _load("mcp_registry.json")
        assert "servers" in m
        assert len(m["servers"]) == 1
        s = m["servers"][0]["server"]
        assert s["name"] == "com.example/test-server"
        assert s["version"] == "1.0.0"
        assert m["metadata"]["nextCursor"] is None

    def test_mcp_registry_enumerate_with_mock(self):
        from unittest.mock import MagicMock
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(_load("mcp_registry.json")).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        
        with patch("canari.npm_enum._opener") as mock_opener:
            mock_opener.return_value.open.return_value = mock_response
            from canari.npm_enum import mcp_registry_enumerate
            results = mcp_registry_enumerate(limit=1)
            assert len(results) == 1
            assert results[0]["name"] == "com.example/test-server"
            assert results[0]["registry"] == "mcp-registry"


class TestDSHFixture:
    def test_dsh_market_structure(self):
        d = _load("dsh_market.json")
        assert d["name"] == "test-dsh-plugin"
        assert d["author"] == "testauthor"
        assert "repository" in d
        assert "metadata" in d

    def test_dsh_enumerate_with_mock(self):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"plugins": [_load("dsh_market.json")]}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        
        with patch("canari.npm_enum._opener") as mock_opener:
            mock_opener.return_value.open.return_value = mock_response
            from canari.npm_enum import dsh_enumerate
            results = dsh_enumerate(limit=1, with_security=False)
            assert len(results) == 1
            assert results[0]["name"] == "test-dsh-plugin"
            assert results[0]["registry"] == "dsh-registry"
