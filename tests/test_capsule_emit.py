# -*- coding: utf-8 -*-
"""Probe and capsule-emission tests.

The regression these lock down: the first SSE parser only recognised a body
that *began* with `data:`, so every `event: message\\ndata: {...}` reply was
classified `not_mcp`. Six of 36 real endpoints were then published as
INCONSISTENT -- working MCP servers recorded as contradicting their own registry
declaration. A measurement tool that reports working as broken is worse than one
that reports nothing.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from canari import capsule as cap              # noqa: E402
from canari import capsule_emit as emit         # noqa: E402
from canari.mcp_probe import _parse_jsonrpc, probe_endpoint  # noqa: E402


SSE_BODY = (
    'event: message\n'
    'data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18",'
    '"capabilities":{"tools":{}},"serverInfo":{"name":"projectory",'
    '"version":"0.7.0"}}}\n'
)


class TestSseParsing:
    def test_sse_with_event_line_is_parsed(self):
        msg = _parse_jsonrpc(SSE_BODY)
        assert msg is not None, "an SSE reply must not be classified not_mcp"
        assert msg["result"]["protocolVersion"] == "2025-06-18"

    def test_sse_with_multiple_events_takes_first_jsonrpc(self):
        body = ('event: ping\ndata: \n\nevent: message\n'
                'data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n')
        msg = _parse_jsonrpc(body)
        assert msg["result"]["ok"] is True

    def test_bare_json_still_parsed(self):
        msg = _parse_jsonrpc('{"jsonrpc":"2.0","id":1,"result":{"a":1}}')
        assert msg["result"]["a"] == 1

    def test_html_is_not_jsonrpc(self):
        assert _parse_jsonrpc("<html><body>502</body></html>") is None

    def test_empty_and_none(self):
        assert _parse_jsonrpc("") is None
        assert _parse_jsonrpc(None) is None


class _FakeResp:
    def __init__(self, status, body):
        self.status = status
        self._b = body.encode("utf-8")

    def read(self, n=None):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@ pytest.fixture()
def fake_http(monkeypatch):
    """Route probe_endpoint's two POSTs to canned responses."""
    import canari.mcp_probe as mp

    def make(init_status, init_body, tools_body='{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"},{"name":"b"}]}}'):
        calls = {"n": 0}

        def _post(url, payload, timeout, headers=None):
            calls["n"] += 1
            if payload.get("method") == "initialize":
                return init_status, init_body, None
            if payload.get("method") == "tools/list":
                return 200, tools_body, None
            return 200, "", None

        monkeypatch.setattr(mp, "_post", _post)
        return calls

    return make


class TestProbeOutcomes:
    def test_alive_over_sse(self, fake_http):
        fake_http(200, SSE_BODY)
        r = probe_endpoint("https://x.example/mcp", timeout=5)
        assert r["outcome"] == "alive"
        assert r["protocol_version"] == "2025-06-18"
        assert r["tool_count"] == 2
        assert len(r["initialize_response_sha256"]) == 64

    def test_auth_is_not_a_finding(self, fake_http):
        fake_http(401, '{"error":"unauthorized"}')
        r = probe_endpoint("https://x.example/mcp", timeout=5)
        assert r["outcome"] == "auth"
        assert r["reachable"] is False

    def test_html_reply_is_not_mcp(self, fake_http):
        fake_http(200, "<html>hi</html>")
        assert probe_endpoint("https://x.example/mcp", timeout=5)["outcome"] == "not_mcp"

    def test_unsupported_version_is_its_own_outcome(self, fake_http):
        fake_http(200, '{"jsonrpc":"2.0","id":1,"error":{"code":-32022,'
                       '"message":"Unsupported protocol version"}}')
        assert probe_endpoint("https://x.example/mcp", timeout=5)["outcome"] \
            == "unsupported_version"


def _entry(url="https://x.example/mcp", transport="streamable-http"):
    return {"server": {"name": "x.example/mcp", "version": "1.0.0",
                       "remotes": [{"type": transport, "url": url}]},
            "_meta": {"io.modelcontextprotocol/registry/official":
                      {"status": "active"}}}


def _probe(url="https://x.example/mcp", outcome="alive", **kw):
    base = {"url": url, "checked_at": "2026-11-15T00:00:00Z", "outcome": outcome,
            "protocol_version": None, "server_info": None, "tool_count": None,
            "error": None, "initialize_response_sha256": "ab" * 32}
    base.update(kw)
    return base


class TestCapsuleStates:
    @pytest.mark.parametrize("outcome,state", [
        ("alive", "CONSISTENT"),
        ("not_mcp", "INCONSISTENT"),
        ("auth", "UNCHECKABLE"),
        ("unreachable", "UNCHECKABLE"),
        ("http_error", "UNCHECKABLE"),
        ("unsupported_version", "UNCHECKABLE"),
    ])
    def test_outcome_maps_to_state(self, outcome, state):
        doc = emit.build_parity_capsule(_entry(), _probe(outcome=outcome))
        assert doc["measurement_state"] == state

    def test_uncheckable_never_claims_a_finding(self):
        doc = emit.build_parity_capsule(_entry(), _probe(outcome="auth"))
        assert doc["differential"]["differs"] is None
        assert "not comparable" in doc["differential"]["reason"]
        assert any("could not be checked" in x for x in doc["limitations"])

    def test_inconsistent_names_the_field(self):
        doc = emit.build_parity_capsule(_entry(), _probe(outcome="not_mcp"))
        assert doc["differential"]["differs"] == ["transport"]

    def test_capsule_validates_and_has_stable_id(self):
        doc = emit.build_parity_capsule(_entry(), _probe())
        assert cap.validate_capsule(doc) == []
        assert doc["capsule_id"] == cap.capsule_id(doc)

    def test_null_source_allowed_when_nothing_was_read(self):
        doc = emit.build_parity_capsule(
            _entry(), _probe(outcome="unreachable", initialize_response_sha256=None))
        assert doc["sources"]["initialize_response"] is None
        assert cap.validate_capsule(doc) == []


class TestBatch:
    def test_batch_root_and_file_digest(self):
        docs = [emit.build_parity_capsule(_entry("https://a.example/mcp"),
                                          _probe("https://a.example/mcp")),
                emit.build_parity_capsule(_entry("https://b.example/mcp"),
                                          _probe("https://b.example/mcp", "auth"))]
        b = emit.build_batch(docs)
        ids = sorted(d["capsule_id"] for d in docs)
        assert b["merkle_root"] == cap.batch_root(ids)
        assert b["n_capsules"] == 2
        assert b["states"] == {"CONSISTENT": 1, "UNCHECKABLE": 1}
        assert len(b["capsules_file"]["sha256"]) == 64
