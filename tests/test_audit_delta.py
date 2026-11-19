# -*- coding: utf-8 -*-
"""Delta between two audit snapshots - the numbers the paper promises for 2026-12-15."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari.audit_delta import delta


def snap(as_of, rows):
    return {"as_of": as_of,
            "rows": [{"registry": r, "identifier": i, "version": v, "status": s}
                     for r, i, v, s in rows]}


class TestDelta:
    def test_counts_recovered_new_and_persistent(self):
        before = snap("2026-11-16", [
            ("npm", "a", "1.0.0", "package-gone"),
            ("npm", "b", "1.0.0", "version-absent"),
            ("pypi", "c", "1.0", "ok"),
        ])
        after = snap("2026-12-15", [
            ("npm", "a", "1.0.0", "package-gone"),     # persistent
            ("npm", "b", "1.0.0", "ok"),                # recovered
            ("pypi", "d", "2.0", "version-absent"),     # new
        ])
        d = delta(before, after)
        assert d["before_broken"] == 2 and d["after_broken"] == 2
        assert d["persistent"] == 1
        assert d["recovered"] == 1
        assert d["new"] == 1
        assert d["net"] == 0
        assert d["days_between"] == 29

    def test_inflow_per_week(self):
        before = snap("2026-12-01", [("npm", "a", "1", "package-gone")])
        after = snap("2026-12-15", [("npm", "a", "1", "package-gone"),
                                    ("npm", "b", "1", "package-gone"),
                                    ("npm", "c", "1", "package-gone")])
        d = delta(before, after)
        # 14 days = 2 weeks, 2 new references -> 1.0 per week
        assert d["new"] == 2
        assert abs(d["inflow_per_week"] - 1.0) < 1e-9

    def test_pep440_normalisation_makes_keys_match(self):
        before = snap("2026-11-16", [("pypi", "x", "0.2.0-rc.3", "version-absent")])
        after = snap("2026-11-19", [("pypi", "x", "0.2.0rc3", "version-absent")])
        d = delta(before, after)
        assert d["persistent"] == 1 and d["new"] == 0 and d["recovered"] == 0

    def test_missing_dates_give_no_inflow(self):
        before = {"as_of": "", "rows": []}
        after = snap("2026-12-15", [("npm", "a", "1", "package-gone")])
        d = delta(before, after)
        assert d["inflow_per_week"] is None


# ---------------------------------------------------------------------------
# The CLI half was never tested (coverage 56%, missing 79-97). It is the part
# the paper actually invokes on 2026-12-15, so it needs to work on real files:
#   python -m canari.audit_delta --before A.json --after B.json [--json]
# ---------------------------------------------------------------------------
import json  # noqa: E402

from canari import audit_delta  # noqa: E402


def _write(tmp_path, name, doc):
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def test_cli_human_output(tmp_path, capsys):
    before = _write(tmp_path, "a.json", snap("2026-11-16", [
        ("npm", "gone", "1.0.0", "package-gone"),
        ("npm", "stays", "1.0.0", "version-absent"),
    ]))
    after = _write(tmp_path, "b.json", snap("2026-12-15", [
        ("npm", "stays", "1.0.0", "version-absent"),
        ("npm", "fresh", "2.0.0", "package-gone"),
    ]))
    rc = audit_delta.main(["--before", before, "--after", after])
    out = capsys.readouterr().out
    assert rc == 0
    assert "2026-11-16 -> 2026-12-15" in out
    assert "29 days" in out
    assert "recovered 1   new 1   persistent 1" in out
    assert "inflow" in out


def test_cli_json_output_is_machine_readable(tmp_path, capsys):
    before = _write(tmp_path, "a.json", snap("2026-11-16", [
        ("npm", "x", "1.0.0", "package-gone"),
    ]))
    after = _write(tmp_path, "b.json", snap("2026-11-16", [
        ("npm", "x", "1.0.0", "package-gone"),
    ]))
    rc = audit_delta.main(["--before", before, "--after", after, "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["persistent"] == 1
    assert doc["recovered"] == 0
    assert doc["new"] == 0
    assert doc["days_between"] == 0
    # zero days must not divide by zero
    assert doc["inflow_per_week"] is None


def test_cli_rejects_a_missing_file(tmp_path):
    before = _write(tmp_path, "a.json", snap("2026-11-16", []))
    with __import__("pytest").raises(FileNotFoundError):
        audit_delta.main(["--before", before,
                          "--after", str(tmp_path / "does-not-exist.json")])


def test_unreadable_as_of_gives_no_inflow_rather_than_a_guess(tmp_path):
    before = _write(tmp_path, "a.json", {"as_of": "not-a-date",
                                         "rows": [{"registry": "npm",
                                                   "identifier": "x",
                                                   "version": "1",
                                                   "status": "package-gone"}]})
    after = _write(tmp_path, "b.json", snap("2026-12-15", []))
    doc = delta(json.load(open(before, encoding="utf-8")),
                json.load(open(after, encoding="utf-8")))
    assert doc["days_between"] is None
    assert doc["inflow_per_week"] is None


def test_version_normalisation_keeps_one_row_from_flapping(tmp_path):
    """The audit's own PEP 440 fix rewrites some version strings; a delta must
    not read the rewrite as a recovery plus a new breakage."""
    before = snap("2026-11-16", [("pypi", "pkg", "0.2.0-rc.3", "version-absent")])
    after = snap("2026-12-15", [("pypi", "pkg", "0.2.0rc3", "version-absent")])
    doc = delta(before, after)
    assert doc["recovered"] == 0
    assert doc["new"] == 0
    assert doc["persistent"] == 1
