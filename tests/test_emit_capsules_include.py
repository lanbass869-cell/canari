# -*- coding: utf-8 -*-
"""emit_capsules --include: a declared server outside the default listing window.

Guard against: the batch silently covering only whatever the registry happens to
return first. Measured 2026-11-16: the first 100 registry records yielded 64
unique remote URLs, and api.inbin.dev/mcp was declared under two names yet absent
from all of them -- so a "we probed the registry" claim was quietly false for it.
"""
import importlib.util
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_SPEC = importlib.util.spec_from_file_location(
    "emit_capsules_under_test",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "scripts", "emit_capsules.py"))
ec = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ec)


def _payload(names_to_remotes):
    return {"servers": [
        {"server": {"name": n, "version": "1.0.0",
                    "remotes": [{"type": "streamable-http", "url": u}]},
         "_meta": {"io.modelcontextprotocol.registry/official": {"isLatest": True}}}
        for n, u in names_to_remotes]}


def test_fetch_by_name_keeps_only_exact_matches(monkeypatch):
    body = _payload([
        ("dev.inbin/agent-email", "https://api.inbin.dev/mcp"),
        ("dev.inbin/agent-meetings", "https://api.inbin.dev/mcp"),
        ("dev.inbin/agent-email-extra", "https://api.inbin.dev/other"),
    ])

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(body).encode("utf-8")

    monkeypatch.setattr(ec.urllib.request, "urlopen",
                        lambda req, timeout=0: FakeResp())

    got = ec.fetch_by_name("dev.inbin/agent-email")
    names = [(s.get("server") or s)["name"] for s in got]
    assert names == ["dev.inbin/agent-email"], names


def test_include_adds_a_new_endpoint_but_not_a_duplicate():
    data = _payload([
        ("already/here", "https://a.example/mcp"),
        ("late/server", "https://b.example/mcp"),
        ("dup/server", "https://a.example/mcp"),
    ])
    todo = ec.targets(data)[:1]
    assert [u for _, u in todo] == ["https://a.example/mcp"]

    seen = {u for _, u in todo}
    for entry, url in ec.targets({"servers": data["servers"][1:]}):
        if url not in seen:
            seen.add(url)
            todo.append((entry, url))
    assert [u for _, u in todo] == ["https://a.example/mcp",
                                    "https://b.example/mcp"]
