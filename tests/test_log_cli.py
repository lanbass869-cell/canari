# -*- coding: utf-8 -*-
"""CLI tests for canari-log: the shell surface a consumer would actually use.

These run the real subprocess, because an in-process call would not catch
argument wiring, exit codes, or stdin handling - the parts that break first.
"""
import json
import os
import subprocess
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = [sys.executable, "-m", "canari.log_cli"]


def run(args, stdin=None, cwd=ROOT):
    return subprocess.run(CLI + args, input=stdin, capture_output=True,
                          text=True, cwd=cwd, encoding="utf-8")


def test_init_creates_key_and_empty_head(tmp_path):
    d = str(tmp_path / "log")
    r = run(["init", d, "--log-id", "cli-test", "--timestamp", "2026-01-01T00:00:00Z"])
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["head"]["body"]["size"] == 0
    assert out["public_key"]["log_id"] == "cli-test"
    assert os.path.exists(os.path.join(d, "public_key.json"))


def test_append_from_file_then_seal_then_bundle_then_verify(tmp_path):
    d = str(tmp_path / "log")
    assert run(["init", d]).returncode == 0
    src = tmp_path / "recs.json"
    src.write_text(json.dumps([{"a": 1}, {"a": 2}, {"a": 3}]), encoding="utf-8")
    r = run(["append", d, "--file", str(src)])
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["appended"] == 3
    r = run(["seal", d, "--timestamp", "2026-01-02T00:00:00Z"])
    assert r.returncode == 0
    head = json.loads(r.stdout)["head"]
    assert head["body"]["size"] == 3
    b = tmp_path / "b.json"
    r = run(["bundle", d, "1", "-o", str(b)])
    assert r.returncode == 0, r.stderr
    r = run(["verify", str(b)])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "RESULT: OK" in r.stdout
    r = run(["verify", str(b), "--root", "ab" * 32])
    assert r.returncode == 2
    assert "RESULT: FAILED" in r.stdout


def test_append_from_stdin(tmp_path):
    d = str(tmp_path / "log")
    run(["init", d])
    r = run(["append", d, "--stdin"], stdin=json.dumps({"payload": {"x": 1}}))
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["appended"] == 1


def test_append_rejects_empty_list(tmp_path):
    d = str(tmp_path / "log")
    run(["init", d])
    r = run(["append", d, "--stdin"], stdin="[]")
    assert r.returncode == 3


def test_audit_exit_codes(tmp_path):
    d = str(tmp_path / "log")
    run(["init", d])
    src = tmp_path / "r.json"
    src.write_text(json.dumps([{"a": 1}, {"a": 2}]), encoding="utf-8")
    run(["append", d, "--file", str(src)])
    run(["seal", d])
    r = run(["audit", d])
    assert r.returncode == 0, r.stdout
    assert json.loads(r.stdout)["ok"] is True

    p = os.path.join(d, "log.jsonl")
    lines = open(p, "rb").read().split(b"\n")
    lines[0] = lines[0].replace(b'"a":1', b'"a":9')
    open(p, "wb").write(b"\n".join(lines))
    r = run(["audit", d])
    assert r.returncode == 2
    assert json.loads(r.stdout)["ok"] is False


def test_head_without_heads_is_error(tmp_path):
    d = str(tmp_path / "log")
    os.makedirs(d)
    r = run(["head", d])
    assert r.returncode == 3


def test_seal_reports_no_new_entries(tmp_path):
    d = str(tmp_path / "log")
    run(["init", d])
    r = run(["seal", d])
    assert r.returncode == 0
    assert json.loads(r.stdout)["sealed"] is False


def test_verify_missing_file_is_usage_error(tmp_path):
    r = run(["verify", str(tmp_path / "nope.json")])
    assert r.returncode == 3

def test_audit_infers_a_non_default_log_id(tmp_path):
    """`audit DIR` must not report corruption just because the log was created
    with --log-id.

    Reproduced on the repo's own log before the fix: `canari-log audit docs/log`
    returned {"ok": false, errors: ["log_id mismatch: 'canari-snapshot-log' !=
    'canari-log'"]} and exit 2, on a completely intact log. A reader who had just
    cloned the repo would reasonably conclude the transparency log was corrupt.
    """
    d = str(tmp_path / "log")
    assert run(["init", d, "--log-id", "custom-id",
                "--timestamp", "2026-01-01T00:00:00Z"]).returncode == 0
    src = tmp_path / "recs.json"
    src.write_text(json.dumps([{"a": 1}, {"a": 2}]), encoding="utf-8")
    assert run(["append", d, "--file", str(src)]).returncode == 0
    assert run(["seal", d, "--timestamp", "2026-01-02T00:00:00Z"]).returncode == 0

    # no --log-id: infer it from the published head
    r = run(["audit", d])
    assert r.returncode == 0, (r.stdout, r.stderr)
    out = json.loads(r.stdout)
    assert out["ok"] is True, out
    assert out["size"] == 2

    # an explicitly wrong id must still fail closed
    r = run(["audit", d, "--log-id", "definitely-wrong"])
    assert r.returncode == 2
    out = json.loads(r.stdout)
    assert out["ok"] is False
    assert any("log_id mismatch" in e for e in out["errors"]), out["errors"]
