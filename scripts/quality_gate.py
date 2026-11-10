# -*- coding: utf-8 -*-
"""quality_gate.py - the three quality thresholds as one command.

1. test suite green
2. line coverage >= 85%
3. mutation kill rate >= 90% (equivalent mutants excluded)

Exit code 0 only if all three pass; used by CI and by hand before a release.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def run(cmd):
    print("$ %s" % " ".join(cmd))
    return subprocess.call(cmd, cwd=HERE)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="quality-gate")
    ap.add_argument("--cov-min", type=float, default=85.0)
    ap.add_argument("--kill-min", type=float, default=90.0)
    ap.add_argument("--skip-mutation", action="store_true",
                    help="run tests+coverage only (CI matrix uses this for speed)")
    a = ap.parse_args(argv)

    failures = []

    rc = run([PY, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider",
              "--cov=canari", "--cov-branch",
              "--cov-fail-under=%s" % a.cov_min])
    if rc != 0:
        failures.append("tests/coverage (rc=%d, min %.0f%%)" % (rc, a.cov_min))

    if not a.skip_mutation:
        rc = run([PY, os.path.join("scripts", "mutation_sweep.py"),
                  "--min-kill", str(a.kill_min)])
        if rc != 0:
            failures.append("mutation kill rate (rc=%d, min %.0f%%)" % (rc, a.kill_min))

    print("\n" + "=" * 60)
    if failures:
        print("QUALITY GATE: FAIL -> %s" % "; ".join(failures))
        return 1
    print("QUALITY GATE: PASS (coverage >= %.0f%%, kill rate >= %.0f%%)"
          % (a.cov_min, a.kill_min if not a.skip_mutation else 0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
