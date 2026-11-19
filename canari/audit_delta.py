# -*- coding: utf-8 -*-
"""audit_delta.py - what changed between two registry-audit snapshots.

The weekly audit writes one JSON per run (docs/audit/package-existence/history/).
Comparing two of them answers the question the paper commits to:

  recovered   broken in the earlier snapshot, resolved in the later one
  new         resolved earlier, broken later
  persistent  broken in both
  inflow      new per week between the two snapshots

Keys are (registry, identifier, normalised version); normalising matters because
the audit's own PEP 440 fix changes how some PyPI version strings are written.

    python -m canari.audit_delta --before A.json --after B.json [--json]
"""
import argparse
import json
import sys


def _norm_version(version):
    try:
        from packaging.version import Version, InvalidVersion
        try:
            return str(Version(version))
        except InvalidVersion:
            return version
    except ImportError:
        return version


def _key(row):
    return (row.get("registry", ""), row.get("identifier", ""),
            _norm_version(row.get("version", "")))


def _broken(snapshot):
    return {_key(r) for r in (snapshot.get("rows") or [])
            if r.get("status") in ("package-gone", "version-absent")}


def _as_of(snapshot):
    from datetime import date
    raw = snapshot.get("as_of") or ""
    try:
        return date.fromisoformat(raw[:10])
    except ValueError:
        return None


def delta(before, after):
    a, b = _broken(before), _broken(after)
    recovered = sorted(a - b)
    new = sorted(b - a)
    persistent = sorted(a & b)
    days = None
    d1, d2 = _as_of(before), _as_of(after)
    if d1 and d2:
        days = (d2 - d1).days
    weeks = (days / 7.0) if days else None
    return {
        "before_as_of": before.get("as_of"),
        "after_as_of": after.get("as_of"),
        "before_broken": len(a),
        "after_broken": len(b),
        "persistent": len(persistent),
        "recovered": len(recovered),
        "new": len(new),
        "net": len(b) - len(a),
        "days_between": days,
        "inflow_per_week": (len(new) / weeks) if weeks else None,
        "recovered_list": [list(k) for k in recovered],
        "new_list": [list(k) for k in new],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="canari-audit-delta")
    ap.add_argument("--before", required=True)
    ap.add_argument("--after", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    with open(a.before, encoding="utf-8") as f:
        before = json.load(f)
    with open(a.after, encoding="utf-8") as f:
        after = json.load(f)
    d = delta(before, after)
    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=1))
    else:
        print("%s -> %s  (%s days)" % (d["before_as_of"], d["after_as_of"], d["days_between"]))
        print("broken %d -> %d  (net %+d)" % (d["before_broken"], d["after_broken"], d["net"]))
        print("recovered %d   new %d   persistent %d" % (d["recovered"], d["new"], d["persistent"]))
        if d["inflow_per_week"] is not None:
            print("inflow %.2f new broken references per week" % d["inflow_per_week"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
