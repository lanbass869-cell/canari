# -*- coding: utf-8 -*-
"""Coverage push: npm_enum remaining branches (all mocked, no network)."""
import io as _io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class R(_io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def Op(mapping):
    class _Op:
        def open(self, req, timeout=None):
            url = getattr(req, "full_url", str(req))
            for sub, payload in mapping:
                if sub in url:
                    if isinstance(payload, Exception):
                        raise payload
                    return R(payload)
            raise OSError("no mock " + url)
    return _Op()


PACK = {"dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {"dist": {"integrity": "", "tarball": "https://r/x.tgz"}}},
        "maintainers": [{"name": "a"}]}


class TestEnumerateTopEdges:
    def test_empty_page_breaks_and_nameless_skipped(self, monkeypatch):
        import canari.npm_enum as ne
        pages = [json.dumps({"objects": [{"package": {}},
                                         {"package": {"name": "ok", "description": "",
                                                      "links": {}, "version": "1"}}],
                             "total": 2}).encode(),
                 json.dumps({"objects": [], "total": 2}).encode()]
        state = {"i": 0}
        class _Op:
            def open(self, req, timeout=None):
                out = pages[min(state["i"], 1)]
                state["i"] += 1
                return R(out)
        monkeypatch.setattr(ne, "_opener", lambda: _Op())
        out = ne.enumerate_top(limit=10)
        assert [x["name"] for x in out] == ["ok"]


class TestNpmSearchRetry:
    def test_exhausted_raises(self, monkeypatch):
        import canari.npm_enum as ne
        monkeypatch.setattr(ne, "_opener", lambda: Op([("npmjs.org", OSError("down"))]))
        import time as _t
        monkeypatch.setattr(_t, "sleep", lambda s: None)
        with pytest.raises(OSError):
            ne.npm_search("x", retries=2)


class TestFetchPackument:
    def test_ok(self, monkeypatch):
        import canari.npm_enum as ne
        monkeypatch.setattr(ne, "_opener", lambda: Op([("registry.npmjs.org/pkg", json.dumps(PACK).encode())]))
        assert ne.fetch_packument("pkg")["dist-tags"]["latest"] == "1.0.0"


class TestSimpleIndex:
    def test_cache_read_oserror_falls_through(self, tmp_path, monkeypatch):
        import canari.npm_enum as ne
        p = tmp_path / "c.html"
        p.write_text("x", encoding="utf-8")
        real_open = open
        def boom(path, *a, **k):
            if str(path) == str(p):
                raise OSError("perm")
            return real_open(path, *a, **k)
        monkeypatch.setattr("builtins.open", boom)
        monkeypatch.setattr(ne, "_opener", lambda: Op([("pypi.org/simple", b"<html></html>")]))
        assert ne.fetch_simple_index(cache_path=str(p)) == "<html></html>"

    def test_download_success_writes_cache(self, tmp_path, monkeypatch):
        import canari.npm_enum as ne
        cache = tmp_path / "sub" / "c.html"
        monkeypatch.setattr(ne, "_opener", lambda: Op([("pypi.org/simple", b"<a>mcp-x</a>")]))
        assert ne.fetch_simple_index(cache_path=str(cache)) == "<a>mcp-x</a>"
        assert cache.read_text(encoding="utf-8") == "<a>mcp-x</a>"

    def test_both_attempts_fail(self, monkeypatch):
        import canari.npm_enum as ne
        monkeypatch.setattr(ne, "_opener", lambda: Op([("pypi.org/simple", OSError("down"))]))
        assert ne.fetch_simple_index() is None

    def test_budget_exceeded(self, monkeypatch):
        import canari.npm_enum as ne
        class _R(_io.BytesIO):
            def read(self, n=-1): return b"x" * 10
        class _Op:
            def open(self, req, timeout=None): return _R()
        monkeypatch.setattr(ne, "_opener", lambda: _Op())
        import time as _t
        calls = {"n": 0}
        real = _t.time
        def fake_time():
            calls["n"] += 1
            return real() + (10_000 if calls["n"] > 1 else 0)
        monkeypatch.setattr(_t, "time", fake_time)
        assert ne.fetch_simple_index(total_budget_s=1) is None

    def test_max_bytes_break(self, monkeypatch):
        import canari.npm_enum as ne
        class _Op:
            def open(self, req, timeout=None): return _io.BytesIO(b"y" * 100)
        monkeypatch.setattr(ne, "_opener", lambda: _Op())
        out = ne.fetch_simple_index(max_bytes=10)
        assert out == "y" * 100


class TestPypiMainPath:
    def test_index_success_and_per_package_error(self, monkeypatch):
        import canari.npm_enum as ne
        idx = b'<html>\n<a href="/a/">mcp-server-a</a>\n<a href="/b/">mcp-server-b</a>\n</html>'
        good = json.dumps({"info": {"version": "1", "summary": "s", "author": "a",
                                    "home_page": "h"},
                           "urls": [{"digests": {"sha256": "c" * 64}, "url": "f"}]}).encode()
        class _Op:
            def open(self, req, timeout=None):
                url = req.full_url
                if "/simple" in url:
                    return R(idx)
                if "mcp-server-a" in url:
                    return R(good)
                raise OSError("no json")
        monkeypatch.setattr(ne, "_opener", lambda: _Op())
        out = ne.pypi_enumerate(prefix="mcp-server-", limit=5)
        assert len(out) == 2
        assert any("error" in x for x in out)

    def test_empty_prefix_falls_back_to_all(self, monkeypatch):
        import canari.npm_enum as ne
        idx = b'<html>\n<a href="/z/">zzz</a>\n</html>'
        good = json.dumps({"info": {"version": "1"}, "urls": []}).encode()
        class _Op:
            def open(self, req, timeout=None):
                if "/simple" in req.full_url:
                    return R(idx)
                return R(good)
        monkeypatch.setattr(ne, "_opener", lambda: _Op())
        out = ne.pypi_enumerate(prefix="no-such-prefix-", limit=5)
        # index path honours the prefix strictly (no fallback-to-all here)
        assert out == []


class TestMcpRegistryEdges:
    def test_cursor_error_and_empty(self, monkeypatch):
        import canari.npm_enum as ne
        p1 = json.dumps({"servers": [{"server": {"name": "a/one", "version": "1.0"}}],
                         "metadata": {"nextCursor": "c2"}}).encode()
        state = {"n": 0}
        class _Op:
            def open(self, req, timeout=None):
                state["n"] += 1
                if state["n"] == 1:
                    return R(p1)
                raise OSError("page2 down")
        monkeypatch.setattr(ne, "_opener", lambda: _Op())
        out = ne.mcp_registry_enumerate(limit=10)
        assert [x["name"] for x in out] == ["a/one"]

    def test_empty_servers_and_no_cursor(self, monkeypatch):
        import canari.npm_enum as ne
        p = json.dumps({"servers": [], "metadata": {}}).encode()
        monkeypatch.setattr(ne, "_opener", lambda: Op([("registry.modelcontextprotocol", p)]))
        assert ne.mcp_registry_enumerate(limit=5) == []

    def test_nameless_and_unparsable_versions(self, monkeypatch):
        import canari.npm_enum as ne
        p = json.dumps({"servers": [
            {"server": {"name": ""}},
            {"server": {"name": "x/y", "version": ""}},
            {"server": {"name": "x/y", "version": "1.0"}},
        ], "metadata": {}}).encode()
        monkeypatch.setattr(ne, "_opener", lambda: Op([("registry.modelcontextprotocol", p)]))
        out = ne.mcp_registry_enumerate(limit=10)
        assert len(out) == 1 and out[0]["version"] == "1.0"


class TestDshEdges:
    def test_zero_and_nameless(self, monkeypatch):
        import canari.npm_enum as ne
        assert ne.dsh_enumerate(limit=0) == []
        market = json.dumps({"plugins": [{"name": ""}, {"name": "p", "author": ""}]}).encode()
        monkeypatch.setattr(ne, "_opener", lambda: Op([("cdn.dsh.so", market)]))
        out = ne.dsh_enumerate(limit=5)
        assert len(out) == 1 and "install_verdict" not in out[0]

    def test_with_security_paths(self, monkeypatch):
        import canari.npm_enum as ne
        market = json.dumps({"plugins": [{"name": "p", "author": "a",
                                          "versions": {"latest": "1.0"}}]}).encode()
        inst = json.dumps({"installTest": {"level": "L5", "verdict": "passed",
                                           "state": "passed"}}).encode()
        sec = json.dumps({"counts": {"critical": 1}, "filesScanned": 4,
                          "scannerVersion": "v"}).encode()
        monkeypatch.setattr(ne, "_opener", lambda: Op([
            ("cdn.dsh.so", market), ("data/install", inst), ("artifact", sec)]))
        import time as _t
        monkeypatch.setattr(_t, "sleep", lambda s: None)
        out = ne.dsh_enumerate(limit=5, with_security=True)
        assert out[0]["install_verdict"] == "passed"
        assert out[0]["security_critical"] == 1

    def test_with_security_errors_ignored(self, monkeypatch):
        import canari.npm_enum as ne
        market = json.dumps({"plugins": [{"name": "p", "author": "a"}]}).encode()
        monkeypatch.setattr(ne, "_opener", lambda: Op([
            ("cdn.dsh.so", market), ("data/install", OSError("x")), ("artifact", OSError("y"))]))
        import time as _t
        monkeypatch.setattr(_t, "sleep", lambda s: None)
        out = ne.dsh_enumerate(limit=5, with_security=True)
        assert "install_verdict" not in out[0]
