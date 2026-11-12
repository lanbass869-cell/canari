# -*- coding: utf-8 -*-
"""Installed-package behaviour of canari-mcp.

Listing a server in the MCP Registry means strangers `pip install canari-mcp`
and run it from a directory with no ledger checkout. If the server then answers
"no attestation for X" for every component it is useless - which is exactly
what `--store out` hard-coded default caused. These tests pin the resolution
order and prove the bundled snapshot actually answers gate_check.
"""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from canari import mcp_server
from canari.signing import read_signed_payload


def _run_stdio(cwd, payload_obj, env=None):
    """Talk to the real CLI over stdio from an unrelated cwd."""
    proc = subprocess.run(
        [sys.executable, "-m", "canari.mcp_server"],
        input=json.dumps(payload_obj) + "\n",
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=cwd, env=env, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    lines = [l for l in proc.stdout.splitlines() if l.strip()]
    assert lines, "no JSON-RPC response"
    return json.loads(lines[-1])


SNAPSHOT = os.path.join(HERE, "canari", "_snapshot")


class TestSnapshotIsShipped:
    def test_snapshot_directory_exists(self):
        assert os.path.isdir(os.path.join(SNAPSHOT, "attestations")), (
            "canari/_snapshot is missing - run scripts/build_snapshot.py")

    def test_snapshot_bundles_are_signed_statements(self):
        files = [f for f in os.listdir(os.path.join(SNAPSHOT, "attestations"))
                 if f.endswith(".bundle.json")]
        assert len(files) > 500, "snapshot unexpectedly small: %d" % len(files)
        with open(os.path.join(SNAPSHOT, "attestations", sorted(files)[0]),
                  encoding="utf-8") as f:
            bundle = json.load(f)
        payload, err = read_signed_payload(bundle)
        assert payload is not None, err
        assert payload.get("verdict")
        assert payload.get("subject", {}).get("name")

    def test_snapshot_has_public_key(self):
        assert os.path.isfile(os.path.join(SNAPSHOT, "public_key.json"))


class TestDefaultStoreResolution:
    def test_env_var_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CANARI_STORE", str(tmp_path))
        assert mcp_server.default_store() == str(tmp_path)

    def test_bundled_snapshot_used_when_no_checkout(self, tmp_path):
        """No ./out in cwd -> the packaged snapshot must be picked."""
        env = dict(os.environ)
        env.pop("CANARI_STORE", None)
        code = ("import sys; sys.path.insert(0, %r); "
                "from canari import mcp_server; "
                "print(mcp_server.default_store())" % HERE)
        r = subprocess.run([sys.executable, "-c", code], capture_output=True,
                           text=True, cwd=str(tmp_path), env=env, timeout=60)
        assert r.returncode == 0, r.stderr[-400:]
        resolved = r.stdout.strip().splitlines()[-1]
        assert resolved.endswith("_snapshot"), resolved
        assert os.path.isdir(os.path.join(resolved, "attestations"))


class TestGateCheckWorksOutOfTheBox:
    def test_store_summary_from_snapshot(self, tmp_path):
        env = dict(os.environ)
        env.pop("CANARI_STORE", None)
        res = _run_stdio(str(tmp_path), {"jsonrpc": "2.0", "id": 1,
                                         "method": "tools/call",
                                         "params": {"name": "store_summary",
                                                    "arguments": {}}},
                         env=env)
        assert res["result"]["isError"] is False
        body = json.loads(res["result"]["content"][0]["text"])
        assert body["components"] > 500, body

    def test_gate_check_answers_without_a_checkout(self, tmp_path):
        """Pick a real component from the snapshot and gate it."""
        import glob
        latest = None
        for fp in sorted(glob.glob(os.path.join(SNAPSHOT, "attestations", "*.bundle.json"))):
            with open(fp, encoding="utf-8") as f:
                p, _ = read_signed_payload(json.load(f))
            if not p:
                continue
            s = p.get("subject", {})
            if s.get("registry") in ("npm", "pypi") and s.get("name"):
                latest = (s["registry"], s["name"])
                break
        assert latest, "no npm/pypi component in snapshot"

        env = dict(os.environ)
        env.pop("CANARI_STORE", None)
        res = _run_stdio(str(tmp_path), {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "gate_check",
                       "arguments": {"registry": latest[0], "name": latest[1]}}}, env=env)
        assert res["result"]["isError"] is False, res
        body = json.loads(res["result"]["content"][0]["text"])
        assert body["found"] is True, body
        assert body["decision"] in ("ALLOW", "BLOCK", "REVIEW")
