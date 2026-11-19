# -*- coding: utf-8 -*-
"""The probe is where the endpoint-monitor's claims come from.

It had 71% coverage and no test that drove it past the first response: the
classifier branches (auth / http_error / not_mcp / unsupported_version /
partial) and the second exchange (tools/list) were exercised only by whatever a
live server happened to return. That is too thin for the module that decides
whether an endpoint is "alive".

Every test here stubs _post, so nothing touches the network.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import canari.mcp_probe as probe  # noqa: E402


INIT_OK = {
    "jsonrpc": "2.0", "id": 1,
    "result": {"protocolVersion": "2025-06-18",
               "serverInfo": {"name": "s", "version": "1"},
               "capabilities": {}},
}
TOOLS_OK = {
    "jsonrpc": "2.0", "id": 2,
    "result": {"tools": [{"name": "b"}, {"name": "a"}, {"noname": True}]},
}


def _stub(monkeypatch, responses):
    """responses: list of (status, body, err) consumed in call order."""
    seq = list(responses)
    calls = []

    def fake_post(url, payload, timeout, headers=None):
        calls.append(payload.get("method"))
        return seq.pop(0)

    monkeypatch.setattr(probe, "_post", fake_post)
    return calls


def test_alive_endpoint_records_protocol_server_and_sorted_tools(monkeypatch):
    calls = _stub(monkeypatch, [
        (200, __import__("json").dumps(INIT_OK), None),
        (200, "", None),                                   # notification
        (200, __import__("json").dumps(TOOLS_OK), None),
    ])
    out = probe.probe_endpoint("https://x/mcp")
    assert out["outcome"] == "alive"
    assert out["reachable"] is True
    assert out["protocol_version"] == "2025-06-18"
    assert out["server_info"]["name"] == "s"
    assert out["tool_names"] == ["a", "b"], "tool names must be sorted and non-dicts skipped"
    assert out["tool_count"] == 2
    assert calls == ["initialize", "notifications/initialized", "tools/list"]


def test_http_401_is_auth_not_broken(monkeypatch):
    _stub(monkeypatch, [(401, "denied", None)])
    out = probe.probe_endpoint("https://x/mcp")
    assert out["outcome"] == "auth"
    assert out["reachable"] is False


def test_http_500_is_http_error(monkeypatch):
    _stub(monkeypatch, [(503, "down", None)])
    assert probe.probe_endpoint("https://x/mcp")["outcome"] == "http_error"


def test_transport_error_is_unreachable(monkeypatch):
    _stub(monkeypatch, [(None, None, "URLError: refused")])
    out = probe.probe_endpoint("https://x/mcp")
    assert out["outcome"] == "unreachable"
    assert "refused" in out["error"]


def test_html_body_is_not_mcp(monkeypatch):
    _stub(monkeypatch, [(200, "<html>hello</html>", None)])
    assert probe.probe_endpoint("https://x/mcp")["outcome"] == "not_mcp"


def test_unsupported_protocol_version_is_distinguished(monkeypatch):
    body = __import__("json").dumps({"jsonrpc": "2.0", "id": 1,
                                     "error": {"code": -32022, "message": "bad version"}})
    _stub(monkeypatch, [(200, body, None)])
    out = probe.probe_endpoint("https://x/mcp")
    assert out["outcome"] == "unsupported_version", (
        "a version rejection is not the same as a non-MCP server")


def test_other_jsonrpc_error_is_not_mcp(monkeypatch):
    body = __import__("json").dumps({"jsonrpc": "2.0", "id": 1,
                                     "error": {"code": -32601, "message": "nope"}})
    _stub(monkeypatch, [(200, body, None)])
    assert probe.probe_endpoint("https://x/mcp")["outcome"] == "not_mcp"


def test_tools_list_failure_is_partial_not_alive(monkeypatch):
    _stub(monkeypatch, [
        (200, __import__("json").dumps(INIT_OK), None),
        (200, "", None),
        (None, None, "timeout"),
    ])
    out = probe.probe_endpoint("https://x/mcp")
    assert out["outcome"] == "partial"
    assert out["reachable"] is True, "initialize succeeded, so it is reachable"


def test_initialize_sha256_is_over_the_raw_bytes(monkeypatch):
    body = __import__("json").dumps(INIT_OK)
    _stub(monkeypatch, [(200, body, None), (200, "", None), (200, __import__("json").dumps(TOOLS_OK), None)])
    out = probe.probe_endpoint("https://x/mcp")
    assert out["initialize_response_sha256"] == hashlib.sha256(body.encode()).hexdigest()


def test_sse_framed_response_is_parsed(monkeypatch):
    """A streamable-HTTP server may answer with SSE; that is alive, not not_mcp."""
    sse = "event: message\ndata: " + __import__("json").dumps(INIT_OK) + "\n\n"
    _stub(monkeypatch, [(200, sse, None), (200, "", None),
                        (200, __import__("json").dumps(TOOLS_OK), None)])
    out = probe.probe_endpoint("https://x/mcp")
    assert out["outcome"] == "alive"


def test_classify_http_covers_the_boundaries():
    assert probe._classify_http(401) == "auth"
    assert probe._classify_http(403) == "auth"
    assert probe._classify_http(402) == "auth"
    assert probe._classify_http(404) == "http_error"
    assert probe._classify_http(500) == "http_error"
    assert probe._classify_http(200) is None
    assert probe._classify_http(None) is None


# --------------------------------------------------------------- _post itself
#
# The transport half was the largest uncovered block (lines 36-54). It is worth
# covering because every classification above depends on it returning
# (status, body, err) correctly rather than raising.

class _Resp:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self, n):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_post_returns_status_and_body(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["method"] = req.get_method()
        seen["timeout"] = timeout
        return _Resp(200, b'{"ok":1}')

    monkeypatch.setattr(probe.urllib.request, "urlopen", fake_urlopen)
    status, body, err = probe._post("https://x/mcp", {"jsonrpc": "2.0"}, timeout=7)
    assert (status, body, err) == (200, '{"ok":1}', None)
    assert seen["method"] == "POST"
    assert seen["timeout"] == 7


def test_post_turns_http_error_into_a_status(monkeypatch):
    class FakeHTTPError(Exception):
        def __init__(self):
            self.code = 429

        def read(self, n):
            return b'{"detail":"slow down"}'

    # urllib.error.HTTPError is what _post catches; emulate it precisely
    import urllib.error
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests",
                                     {}, __import__("io").BytesIO(b'{"detail":"slow down"}'))
    monkeypatch.setattr(probe.urllib.request, "urlopen", fake_urlopen)
    status, body, err = probe._post("https://x/mcp", {}, timeout=5)
    assert status == 429
    assert body is not None and "slow down" in body
    assert err is None


def test_post_never_raises_on_transport_failure(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise OSError("network is unreachable")
    monkeypatch.setattr(probe.urllib.request, "urlopen", fake_urlopen)
    status, body, err = probe._post("https://x/mcp", {}, timeout=5)
    assert status is None and body is None
    assert err and "network is unreachable" in err


def test_post_sends_the_expected_headers(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["accept"] = req.get_header("Accept")
        seen["content-type"] = req.get_header("Content-type")
        seen["ua"] = req.get_header("User-agent")
        return _Resp(200, b"{}")

    monkeypatch.setattr(probe.urllib.request, "urlopen", fake_urlopen)
    probe._post("https://x/mcp", {}, timeout=5)
    assert "application/json" in seen["accept"]
    assert "text/event-stream" in seen["accept"]
    assert seen["content-type"] == "application/json"
    assert "canari-probe" in seen["ua"]
