# -*- coding: utf-8 -*-
"""Cross-language verification.

The strongest available evidence that a proof format is real (and not a
private convention that only our own code can read) is a second, independent
implementation in another language accepting the same bytes. The Node verifier
is written against docs/spec/append-only-log.md using only node:crypto, and
these tests require it to agree with the Python one - including on forged
bundles, where agreement *and* rejection are both required.
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
NODE_VERIFIER = os.path.join(ROOT, "docs", "spec", "verify_offline.js")

from canari.logstore import open_log  # noqa: E402
from canari.verify_offline import verify_bundle  # noqa: E402

node = shutil.which("node")
needs_node = pytest.mark.skipif(node is None, reason="node not installed")


def run_node(path, *extra):
    return subprocess.run([node, NODE_VERIFIER, path, *extra],
                          capture_output=True, text=True)


def make_bundle(tmp_path):
    L = open_log(str(tmp_path / "log"), log_id="xlang")
    L.append_many([{"payload": {"i": i}} for i in range(9)])
    L.seal(timestamp="2026-01-01T00:00:00Z")
    L.append_many([{"payload": {"i": i}} for i in range(9, 17)])
    L.seal(timestamp="2026-01-02T00:00:00Z")
    b = L.export_bundle(12)
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(b), encoding="utf-8")
    return L, b, p


@needs_node
def test_node_accepts_python_bundle(tmp_path):
    L, b, p = make_bundle(tmp_path)
    assert verify_bundle(b)["ok"] is True
    r = run_node(str(p))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "RESULT: OK" in r.stdout


@needs_node
@pytest.mark.parametrize("mutate", [
    lambda b: b["tree_head"]["body"].__setitem__("size", b["tree_head"]["body"]["size"] + 1),
    lambda b: b["tree_head"]["signature"].__setitem__("sig", "00" * 64),
    lambda b: b["entry"].__setitem__("index", 0),
    lambda b: b["inclusion_proof"].clear(),
    lambda b: b["consistency"]["from_head"]["body"].__setitem__("root", "11" * 32),
])
def test_node_rejects_forgery(tmp_path, mutate):
    L, b, p = make_bundle(tmp_path)
    mutate(b)
    p.write_text(json.dumps(b), encoding="utf-8")
    assert verify_bundle(b)["ok"] is False
    r = run_node(str(p))
    assert r.returncode == 2, r.stdout + r.stderr
    assert "RESULT: FAILED" in r.stdout


@needs_node
def test_node_and_python_agree_on_pins(tmp_path):
    L, b, p = make_bundle(tmp_path)
    root = b["tree_head"]["body"]["root"]
    assert run_node(str(p), "--root", root).returncode == 0
    assert run_node(str(p), "--root", "ab" * 32).returncode == 2
    assert run_node(str(p), "--log-id", "xlang").returncode == 0
    assert run_node(str(p), "--log-id", "other").returncode == 2
    assert run_node(str(p), "--min-size", "99").returncode == 2


def test_node_verifier_does_not_import_canari():
    src = open(NODE_VERIFIER, encoding="utf-8").read()
    assert "canari/" not in src
    assert "require(\"child_process\")" not in src
