# -*- coding: utf-8 -*-
"""quality_gate.py - the three quality thresholds as one command.

1. lint (ruff, the same rule set CI uses)
2. test suite green
3. line coverage >= 85%
4. paper numbers still match their artifacts
5. the one-page summary still states those same numbers
6. mutation kill rate >= 90% (equivalent mutants excluded)

This mirrors every gate in .github/workflows/ci.yml. Run it before pushing:
  python scripts/quality_gate.py

Running only `pytest tests` is not enough -- it skips the coverage gate and the
lint gate, which is how the repository once stayed red for nine commits.

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
    ap.add_argument("--skip-lint", action="store_true",
                    help="skip the ruff gate (only if ruff is not installed)")
    ap.add_argument("--skip-mutation", action="store_true",
                    help="run tests+coverage only (CI matrix uses this for speed)")
    a = ap.parse_args(argv)

    failures = []

    if not a.skip_lint:
        rc = run([PY, "-m", "ruff", "check", ".", "--select", "E9,F63,F7,F82"])
        if rc != 0:
            failures.append("lint (rc=%d)" % rc)

    rc = run([PY, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider",
              "--cov=canari", "--cov-branch",
              "--cov-fail-under=%s" % a.cov_min])
    if rc != 0:
        failures.append("tests/coverage (rc=%d, min %.0f%%)" % (rc, a.cov_min))

    # The paper's headline numbers must still match the JSON artifacts that produced
    # them. Three drifts were found by hand before this check existed (PEP 440 false
    # positives, the tombstone bucket split, and a 49 vs 49.5 download median).
    rc = run([PY, os.path.join("scripts", "check_paper_numbers.py")])
    if rc != 0:
        failures.append("paper numbers vs artifacts (rc=%d)" % rc)

    # Same rule for the one-page summary: it is the document most likely to be
    # handed to someone who will not check it, so every figure in it is pinned to
    # the artefact that produced it AND to the exact phrase it appears in.
    rc = run([PY, os.path.join("scripts", "check_doc_numbers.py")])
    if rc != 0:
        failures.append("summary numbers vs artifacts (rc=%d)" % rc)

    if not a.skip_mutation:
        rc = run([PY, os.path.join("scripts", "mutation_sweep.py"),
                  "--min-kill", str(a.kill_min)])
        if rc != 0:
            failures.append("mutation kill rate (rc=%d, min %.0f%%)" % (rc, a.kill_min))

    print("\n" + "=" * 60)
    if failures:
        print("QUALITY GATE: FAIL -> %s" % "; ".join(failures))
        return 1
    print("QUALITY GATE: PASS (lint, coverage >= %.0f%%, kill rate >= %.0f%%)"
          % (a.cov_min, a.kill_min if not a.skip_mutation else 0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
