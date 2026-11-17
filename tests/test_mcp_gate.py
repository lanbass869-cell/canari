# -*- coding: utf-8 -*-
"""Tests for canari-mcp-gate: launch-command component detection and the
stdio proxy's byte-exactness.

The proxy tests run a real child process. They exist because the failure mode
that matters is silent: a wrapper that rewrites or buffers stdio still "works"
for a one-line handshake and then corrupts a large tools/list response.
"""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari.mcp_gate import component_of

PY = sys.executable


class TestComponentOf:
    @pytest.mark.parametrize("argv,expected", [
        (["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
         ("npm", "@modelcontextprotocol/server-filesystem", None)),
        (["npx", "@scope/pkg@1.2.3"], ("npm", "@scope/pkg", "1.2.3")),
        (["bunx", "some-mcp"], ("npm", "some-mcp", None)),
        (["uvx", "mcp-server-fetch"], ("pypi", "mcp-server-fetch", None)),
        (["pipx", "mcp-server-git"], ("pypi", "mcp-server-git", None)),
        (["mcp-server-git", "--repository", "."], ("pypi", "mcp-server-git", None)),
    ])
    def test_recognised(self, argv, expected):
        assert component_of(argv) == expected

    @pytest.mark.parametrize("argv", [
        ["python", "-m", "some_pkg"],
        ["node", "server.js"],
        ["/usr/local/bin/custom-server", "--flag"],
        ["C:\\tools\\mcp.exe"],
        [],
    ])
    def test_unrecognised_returns_none(self, argv):
        """Local scripts and absolute paths have no registry identity; guessing
        one would be worse than returning None (which the gate treats as
        UNKNOWN and, by default, runs)."""
        assert component_of(argv) is None

    def test_exe_suffix_is_stripped(self):
        assert component_of(["npx.exe", "-y", "pkg"]) == ("npm", "pkg", None)


ECHO = (
    "import sys\n"
    "for line in sys.stdin.buffer:\n"
    "    sys.stdout.buffer.write(b'R:' + line)\n"
    "    sys.stdout.buffer.flush()\n"
)


def _run_gate(tmp_path, args, data=b""):
    child = tmp_path / "echo.py"
    child.write_text(ECHO, encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cmd = [PY, "-m", "canari.mcp_gate"] + list(args) + ["--", PY, str(child)]
    return subprocess.run(cmd, input=data, capture_output=True, timeout=120, env=env)


class TestProxy:
    def test_bytes_round_trip(self, tmp_path):
        payload = b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n'
        p = _run_gate(tmp_path, ["--store", str(tmp_path / "none")], payload)
        assert p.returncode == 0
        assert p.stdout == b"R:" + payload

    def test_large_payload_not_truncated(self, tmp_path):
        payload = b'{"x":"' + b"A" * 200000 + b'"}\n'
        p = _run_gate(tmp_path, ["--store", str(tmp_path / "none"), "--quiet"], payload)
        assert p.returncode == 0
        assert p.stdout == b"R:" + payload

    def test_stdout_carries_only_child_bytes(self, tmp_path):
        """Diagnostics must not land on stdout -- that would corrupt the stream."""
        p = _run_gate(tmp_path, ["--store", str(tmp_path / "none")], b"\n")
        assert p.stdout == b"R:\n"
        assert b"canari-mcp-gate" in p.stderr

    def test_block_does_not_start_child(self, tmp_path):
        store = tmp_path / "store"
        store.mkdir()
        marker = tmp_path / "ran.flag"
        launcher = tmp_path / "launcher.py"
        launcher.write_text(
            "open(r'%s','w').write('ran')\nprint('RAN')\n" % marker, encoding="utf-8")
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        p = subprocess.run(
            [PY, "-m", "canari.mcp_gate", "--store", str(store),
             "--on-unknown", "block", "--registry", "npm", "--name", "x",
             "--", PY, str(launcher)],
            input=b"", capture_output=True, timeout=120, env=env)
        assert p.returncode == 5
        assert p.stdout == b""
        assert not marker.exists()

    def test_missing_child_reports_127(self, tmp_path):
        p = _run_gate(tmp_path, ["--store", str(tmp_path / "none")], b"")
        # replace the resolved child with a name that cannot exist
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        p = subprocess.run([PY, "-m", "canari.mcp_gate", "--store", str(tmp_path / "none"),
                            "--quiet", "--", "definitely-not-a-real-exe-xyz"],
                           input=b"", capture_output=True, timeout=60, env=env)
        assert p.returncode == 127
