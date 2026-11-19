# -*- coding: utf-8 -*-
"""Offline coverage for the notary and the MCP server's error paths.

Both were below 71% after the 2026-11-19 deficiency audit, and both are places
where a crash or a wrong answer is user-visible: the notary signs someone
else's claim, and the MCP server is what a host actually talks to.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import canari.evidence_notary as notary  # noqa: E402
import canari.mcp_server as srv  # noqa: E402


# ------------------------------------------------------------ evidence_notary

def _index(**over):
    base = {"dataset": "mcp-registry", "run": "2026-11-19",
            "entries": 3, "states": {"ok": 3}, "checks": {"exists": 3},
            "sha256": "a" * 64, "checked_with": {"tool": "t/1"}}
    base.update(over)
    return base


def test_consistency_accepts_a_sound_summary():
    ok, detail = notary.check_index_consistency(_index())
    assert ok is True
    assert "3" in detail


def test_consistency_rejects_states_that_do_not_add_up():
    ok, detail = notary.check_index_consistency(_index(states={"ok": 1}))
    assert ok is False
    assert "states sum to 1" in detail


def test_consistency_rejects_checks_that_do_not_add_up():
    ok, detail = notary.check_index_consistency(_index(checks={"exists": 2}))
    assert ok is False
    assert "checks sum to 2" in detail


def test_consistency_rejects_a_missing_entry_count():
    ok, detail = notary.check_index_consistency({"states": {"ok": 1}})
    assert ok is False
    assert "entries" in detail


def test_notarising_refuses_without_a_producer_digest():
    with pytest.raises(ValueError) as e:
        notary.build_attestation(_index(sha256=None))
    assert "sha256" in str(e.value)


def test_notarising_refuses_a_digest_that_is_not_64_hex():
    with pytest.raises(ValueError) as e:
        notary.build_attestation(_index(sha256="abc"))
    assert "sha256" in str(e.value)


def test_notarising_refuses_without_a_run_date():
    with pytest.raises(ValueError) as e:
        notary.build_attestation(_index(run=""))
    assert "run date" in str(e.value)


def test_notarised_attestation_attributes_the_claim_to_the_producer():
    """Canari is the notary, not the author: the record must say whose data it is."""
    doc = notary.build_attestation(_index(), now=__import__("datetime").datetime(
        2026, 11, 19, tzinfo=__import__("datetime").timezone.utc))
    payload = doc.get("payload") if "payload" in doc else doc
    blob = json.dumps(payload)
    assert "a" * 64 in blob, "the producer's digest must be recorded"
    assert "notary" in blob.lower()


# --------------------------------------------------------------- mcp_server

def test_server_advertises_the_package_version():
    assert srv.SERVER_INFO["version"] == __import__("canari").__version__


def test_ping_and_list_are_answered():
    assert srv._handle({"jsonrpc": "2.0", "id": 1, "method": "ping"}, "x", None)["result"] == {}
    listed = srv._handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, "x", None)
    names = [t["name"] for t in listed["result"]["tools"]]
    assert names == ["gate_check", "verify_bundle", "store_summary"]


def test_initialized_notification_returns_nothing():
    assert srv._handle({"jsonrpc": "2.0", "method": "notifications/initialized"},
                       "x", None) is None


def test_unknown_method_is_an_error_not_a_crash():
    got = srv._handle({"jsonrpc": "2.0", "id": 9, "method": "does/not/exist"}, "x", None)
    assert got["id"] == 9
    assert "error" in got, "an unknown method must produce a JSON-RPC error"


def test_unknown_tool_is_a_jsonrpc_error(tmp_path):
    # an unknown tool is -32602 at the protocol level, not an isError payload
    got = srv._handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "nope", "arguments": {}}},
                      str(tmp_path), None)
    assert got["id"] == 3
    assert got["error"]["code"] == -32602
    assert "unknown tool" in got["error"]["message"]


def test_a_tool_that_raises_is_reported_as_isError(tmp_path, monkeypatch):
    """A tool crash must come back as isError, not kill the session."""
    def boom(args, store, key):
        raise RuntimeError("tool blew up")

    monkeypatch.setitem(srv.__dict__, "_tool_store_summary", boom)
    got = srv._handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                       "params": {"name": "store_summary", "arguments": {}}},
                      str(tmp_path), None)
    assert got["result"]["isError"] is True
    assert "tool blew up" in got["result"]["content"][0]["text"]


def test_verify_bundle_reports_an_unreadable_file(tmp_path):
    got = srv._tool_verify_bundle({"bundle_path": str(tmp_path / "missing.json")},
                                  str(tmp_path), None)
    assert got["ok"] is False
    assert "cannot read bundle" in got["error"]


def test_verify_bundle_reports_a_missing_key(tmp_path):
    p = tmp_path / "b.json"
    p.write_text("{}", encoding="utf-8")
    got = srv._tool_verify_bundle({"bundle_path": str(p)}, str(tmp_path), None)
    assert got["ok"] is False
    assert "no key_path" in got["error"]


def test_verify_bundle_reports_an_unreadable_key(tmp_path):
    p = tmp_path / "b.json"
    p.write_text("{}", encoding="utf-8")
    got = srv._tool_verify_bundle({"bundle_path": str(p),
                                   "key_path": str(tmp_path / "nokey.json")},
                                  str(tmp_path), None)
    assert got["ok"] is False
    assert "cannot read key" in got["error"]
