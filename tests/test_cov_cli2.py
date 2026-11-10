# -*- coding: utf-8 -*-
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_gate_cli_list_on_empty_store(tmp_path):
    from canari.gate_cli import main
    assert main(["--store", str(tmp_path), "--list"]) == 0


def test_gate_cli_requires_registry_and_name(tmp_path):
    from canari.gate_cli import main
    with pytest.raises(SystemExit) as e:
        main(["--store", str(tmp_path)])
    assert e.value.code == 2        # argparse usage error


def test_gate_cli_list_json_is_valid(tmp_path):
    from canari.gate_cli import main
    assert main(["--store", str(tmp_path), "--list", "--json"]) == 0


def test_drift_cli_returns_zero_on_empty_store(tmp_path, capsys):
    from canari.drift_cli import main
    rc = main(["--store", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.strip()


def test_drift_cli_write_creates_file(tmp_path):
    from canari.drift_cli import main
    outdir = tmp_path / "drift"
    assert main(["--store", str(tmp_path), "--write", str(outdir), "--json"]) == 0
    files = list(outdir.glob("drift-*.json"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text(encoding="utf-8"))
    assert "generated_at" in payload
