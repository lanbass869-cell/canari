# -*- coding: utf-8 -*-
"""canari-log end to end: init -> append -> seal -> audit -> bundle -> verify.

Coefficient: this module had 0% coverage before this file. It is a shipped CLI
with seven subcommands and no test ever executed a line of it, so "the gate is
green" said nothing about whether canari-log works at all.
"""
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari import log_cli


def _run(argv, stdin_text=None, monkeypatch=None):
    if stdin_text is not None and monkeypatch is not None:
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_text))
    return log_cli.main(argv)


def _new_log(tmp_path, monkeypatch):
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    assert _run(["init", str(tmp_path), "--log-id", "audit-log"], monkeypatch=monkeypatch) == 0
    doc = json.loads(out.getvalue())
    assert doc["public_key"]
    # init alone does not have to materialise the record file; append does.
    return doc


class TestLogCliLifecycle:
    def test_init_creates_log_and_prints_key(self, tmp_path, monkeypatch):
        _new_log(tmp_path, monkeypatch)

    def test_append_from_stdin_then_seal_then_audit(self, tmp_path, monkeypatch):
        _new_log(tmp_path, monkeypatch)
        monkeypatch.setattr(sys, "stdout", io.StringIO())
        rc = _run(["append", str(tmp_path), "--stdin"],
                  stdin_text='[{"a":1},{"b":2}]', monkeypatch=monkeypatch)
        assert rc == 0
        assert (tmp_path / "log.jsonl").exists()
        out = io.StringIO(); monkeypatch.setattr(sys, "stdout", out)
        assert _run(["seal", str(tmp_path)], monkeypatch=monkeypatch) == 0
        sealed = json.loads(out.getvalue())
        assert sealed["sealed"] is True
        out2 = io.StringIO(); monkeypatch.setattr(sys, "stdout", out2)
        assert _run(["audit", str(tmp_path)], monkeypatch=monkeypatch) == 0
        rep = json.loads(out2.getvalue())
        assert rep.get("ok") is True, rep

    def test_append_from_file_and_head(self, tmp_path, monkeypatch):
        _new_log(tmp_path, monkeypatch)
        rec = tmp_path / "rec.json"
        rec.write_text(json.dumps({"kind": "verdict", "timestamp": "t",
                                   "payload": {"v": 1}}), encoding="utf-8")
        monkeypatch.setattr(sys, "stdout", io.StringIO())
        assert _run(["append", str(tmp_path), "--file", str(rec)],
                    monkeypatch=monkeypatch) == 0
        out = io.StringIO(); monkeypatch.setattr(sys, "stdout", out)
        assert _run(["seal", str(tmp_path)], monkeypatch=monkeypatch) == 0
        out2 = io.StringIO(); monkeypatch.setattr(sys, "stdout", out2)
        assert _run(["head", str(tmp_path)], monkeypatch=monkeypatch) == 0
        head = json.loads(out2.getvalue())
        assert head["body"]["size"] >= 1

    def test_seal_without_new_entries_says_so(self, tmp_path, monkeypatch):
        _new_log(tmp_path, monkeypatch)
        out = io.StringIO(); monkeypatch.setattr(sys, "stdout", out)
        assert _run(["seal", str(tmp_path)], monkeypatch=monkeypatch) == 0
        assert json.loads(out.getvalue())["sealed"] is False

    def test_bundle_then_verify_offline(self, tmp_path, monkeypatch):
        _new_log(tmp_path, monkeypatch)
        monkeypatch.setattr(sys, "stdout", io.StringIO())
        _run(["append", str(tmp_path), "--stdin"], stdin_text='[{"a":1}]',
             monkeypatch=monkeypatch)
        _run(["seal", str(tmp_path)], monkeypatch=monkeypatch)
        bundle = tmp_path / "out" / "b.json"
        bundle.parent.mkdir()
        assert _run(["bundle", str(tmp_path), "0", "-o", str(bundle)],
                    monkeypatch=monkeypatch) == 0
        assert bundle.exists()
        out = io.StringIO(); monkeypatch.setattr(sys, "stdout", out)
        assert _run(["verify", str(bundle), "--json"], monkeypatch=monkeypatch) == 0
        assert json.loads(out.getvalue()).get("ok") is True

    def test_verify_fails_on_tampered_bundle(self, tmp_path, monkeypatch):
        _new_log(tmp_path, monkeypatch)
        monkeypatch.setattr(sys, "stdout", io.StringIO())
        _run(["append", str(tmp_path), "--stdin"], stdin_text='[{"a":1}]',
             monkeypatch=monkeypatch)
        _run(["seal", str(tmp_path)], monkeypatch=monkeypatch)
        bundle = tmp_path / "b.json"
        _run(["bundle", str(tmp_path), "0", "-o", str(bundle)], monkeypatch=monkeypatch)
        doc = json.loads(bundle.read_text(encoding="utf-8"))
        # Corrupt the entry the bundle claims is included; the proof can no
        # longer bind it to the signed root.
        doc["entry"] = {}
        bundle.write_text(json.dumps(doc), encoding="utf-8")
        assert _run(["verify", str(bundle), "--json"], monkeypatch=monkeypatch) == 2

    def test_audit_detects_truncated_log(self, tmp_path, monkeypatch):
        _new_log(tmp_path, monkeypatch)
        monkeypatch.setattr(sys, "stdout", io.StringIO())
        _run(["append", str(tmp_path), "--stdin"], stdin_text='[{"a":1},{"b":2}]',
             monkeypatch=monkeypatch)
        _run(["seal", str(tmp_path)], monkeypatch=monkeypatch)
        lines = (tmp_path / "log.jsonl").read_text(encoding="utf-8").splitlines()
        (tmp_path / "log.jsonl").write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        out = io.StringIO(); monkeypatch.setattr(sys, "stdout", out)
        rc = _run(["audit", str(tmp_path)], monkeypatch=monkeypatch)
        assert rc == 2
        assert json.loads(out.getvalue()).get("ok") is False


class TestReadRecords:
    def test_dict_becomes_one_record(self):
        class A:
            file = None
        import io as _io
        old = sys.stdin
        sys.stdin = _io.StringIO('{"x": 1}')
        try:
            recs = log_cli._read_records(A())
        finally:
            sys.stdin = old
        assert recs == [{"kind": "record", "payload": {"x": 1}}]

    def test_empty_input_is_an_error(self):
        class A:
            file = None
        import io as _io
        old = sys.stdin
        sys.stdin = _io.StringIO("[]")
        try:
            log_cli._read_records(A())
        except ValueError as e:
            assert "non-empty" in str(e)
        else:
            raise AssertionError("empty array must be rejected")
        finally:
            sys.stdin = old
