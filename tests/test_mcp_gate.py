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


# ----------------------------------------------------------------- in-process
# The tests above run the gate in a subprocess, which is the right way to prove the
# stdio proxy works -- but coverage cannot see inside a subprocess. These cover the
# same code paths in-process so the repository's coverage gate stays honest.

import io

import canari.mcp_gate as mg


class _FakePipe(io.BytesIO):
    """BytesIO with the few attributes Popen's pipes expose.

    close() is a no-op so the value written by the pump threads can still be read
    after _proxy's finally block closes the child's stdin.
    """
    def flush(self):
        pass

    def close(self):
        pass


class _FakeChild:
    def __init__(self, out_bytes=b"", code=0):
        self.stdin = _FakePipe()
        self.stdout = _FakePipe(out_bytes)
        self._code = code

    def wait(self):
        return self._code


class _FakeStdin:
    def __init__(self, data):
        self.buffer = _FakePipe(data)


class _FakeStdout:
    def __init__(self):
        self.buffer = _FakePipe()

    def write(self, s):
        return len(s)


class TestProxyInProcess:
    def test_copies_stdin_to_child_and_child_to_stdout(self, monkeypatch):
        child = _FakeChild(out_bytes=b"hi")
        monkeypatch.setattr(mg.subprocess, "Popen", lambda *a, **k: child)
        monkeypatch.setattr(mg.sys, "stdin", _FakeStdin(b"ping"))
        out = _FakeStdout()
        monkeypatch.setattr(mg.sys, "stdout", out)

        code = mg._proxy(["whatever"])
        assert code == 0
        assert child.stdin.getvalue() == b"ping"
        assert out.buffer.getvalue() == b"hi"

    def test_child_exit_code_propagates(self, monkeypatch):
        monkeypatch.setattr(mg.subprocess, "Popen", lambda *a, **k: _FakeChild(code=7))
        monkeypatch.setattr(mg.sys, "stdin", _FakeStdin(b""))
        monkeypatch.setattr(mg.sys, "stdout", _FakeStdout())
        assert mg._proxy(["whatever"]) == 7

    def test_missing_command_returns_127(self, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError()
        monkeypatch.setattr(mg.subprocess, "Popen", boom)
        monkeypatch.setattr(mg.sys, "stderr", io.StringIO())
        assert mg._proxy(["nope"]) == 127


class TestMainInProcess:
    def _setup(self, monkeypatch, decision=None, found=True):
        seen = {}

        def fake_check(store, registry, name, version=None, key_path=None, policy="default"):
            seen.update(store=store, registry=registry, name=name, version=version)
            return {"found": found, "decision": decision or "ALLOW",
                    "reasons": ["r1"], "policy": policy, "verdict": "pass",
                    "subject": "s", "generated_at": "", "bundle": None}

        monkeypatch.setattr(mg, "check_component", fake_check)
        monkeypatch.setattr(mg, "_proxy", lambda argv: seen.setdefault("ran", argv) and 0)
        monkeypatch.setattr(mg.sys, "stderr", io.StringIO())
        return seen

    def test_allow_runs_the_child(self, tmp_path, monkeypatch):
        seen = self._setup(monkeypatch)
        rc = mg.main(["--store", str(tmp_path), "--", "npx", "-y", "pkg"])
        assert rc == 0
        assert seen["ran"] == ["npx", "-y", "pkg"]
        assert seen["registry"] == "npm" and seen["name"] == "pkg"

    def test_block_never_runs_the_child(self, tmp_path, monkeypatch):
        seen = self._setup(monkeypatch, decision="BLOCK")
        rc = mg.main(["--store", str(tmp_path), "--", "npx", "pkg"])
        assert rc == 5
        assert "ran" not in seen

    def test_review_requires_the_flag(self, tmp_path, monkeypatch):
        seen = self._setup(monkeypatch, decision="REVIEW")
        assert mg.main(["--store", str(tmp_path), "--", "npx", "pkg"]) == 6
        assert "ran" not in seen
        assert mg.main(["--store", str(tmp_path), "--allow-review", "--", "npx", "pkg"]) == 0
        assert "ran" in seen

    def test_unknown_component_allowed_by_default(self, tmp_path, monkeypatch):
        seen = self._setup(monkeypatch, found=False)
        assert mg.main(["--store", str(tmp_path), "--registry", "npm", "--name", "x",
                        "--", "node", "s.js"]) == 0
        assert "ran" in seen

    def test_unknown_component_blocked_when_strict(self, tmp_path, monkeypatch):
        seen = self._setup(monkeypatch, found=False)
        assert mg.main(["--store", str(tmp_path), "--registry", "npm", "--name", "x",
                        "--on-unknown", "block", "--", "node", "s.js"]) == 5
        assert "ran" not in seen

    def test_unknown_component_review_when_asked(self, tmp_path, monkeypatch):
        seen = self._setup(monkeypatch, found=False)
        assert mg.main(["--store", str(tmp_path), "--registry", "npm", "--name", "x",
                        "--on-unknown", "review", "--", "node", "s.js"]) == 6
        assert "ran" not in seen

    def test_missing_store_warns_but_runs(self, tmp_path, monkeypatch):
        seen = self._setup(monkeypatch)
        missing = str(tmp_path / "nope")
        err = io.StringIO(); monkeypatch.setattr(mg.sys, "stderr", err)
        assert mg.main(["--store", missing, "--", "node", "s.js"]) == 0
        assert "store not found" in err.getvalue()
        assert "ran" in seen

    def test_no_command_is_a_usage_error(self):
        try:
            mg.main([])
        except SystemExit as e:
            assert e.code == 2
        else:
            raise AssertionError("expected SystemExit")
