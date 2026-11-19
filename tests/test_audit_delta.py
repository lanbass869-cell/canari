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
