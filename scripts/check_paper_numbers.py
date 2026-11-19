"""Cross-check every headline number in the paper against its artifact.

The project has twice shipped a number that disagreed with another artifact (the PEP 440
false positives, and the tombstone bucket split). This checks the paper's claims against
the JSON that produced them, so a future edit cannot silently drift.

    python scripts/check_paper_numbers.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXP = os.path.join(ROOT, "experiments", "package_existence_repro")
PAPER = os.path.join(ROOT, "docs", "paper", "main.tex")

checks = []


def check(label, claimed, actual, source):
    ok = claimed == actual
    checks.append((label, claimed, actual, ok, source))
    return ok


def main():
    repro = json.load(open(os.path.join(EXP, "result.json"), encoding="utf-8"))
    stale = json.load(open(os.path.join(EXP, "staleness.json"), encoding="utf-8"))
    dl = json.load(open(os.path.join(EXP, "downloads.json"), encoding="utf-8"))
    rec = json.load(open(os.path.join(EXP, "recovery.json"), encoding="utf-8"))
    reclass = json.load(open(os.path.join(EXP, "tombstone_reclass.json"), encoding="utf-8"))

    s = repro["summary"]
    total_n = s["package-gone"]["n"] + s["version-absent"]["n"]
    total_rep = s["package-gone"]["reproduced"] + s["version-absent"]["reproduced"]
    check("RQ1 sample size (n=40)", 40, total_n, "repro/result.json summary")
    check("RQ1 reproduced (39)", 39, total_rep, "repro/result.json summary")

    ages = stale["ages_days"]
    check("RQ2 median age (218)", 218, int(round(ages["median"])), "staleness.json ages_days.median")
    check("RQ2 max age (435)", 435, int(round(ages["max"])), "staleness.json ages_days.max")

    check("RQ3 packages with stats (140)", 140, dl["stats_obtained"], "downloads.json stats_obtained")
    check("RQ3 median downloads (49.5)", 49.5, float(dl["median_monthly"]), "downloads.json median_monthly")

    counts = reclass["status_counts"]
    check("corrected package-gone (219)", 219, counts.get("package-gone"),
          "tombstone_reclass.json status_counts")
    check("corrected version-absent (48)", 48, counts.get("version-absent"),
          "tombstone_reclass.json status_counts")

    check("three-day recheck still broken (267)", 267, rec["still_broken"], "recovery.json still_broken")
    check("three-day recheck recovered (7)", 7, rec["recovered"], "recovery.json recovered")

    # the paper must actually contain the numbers it claims
    tex = open(PAPER, encoding="utf-8").read()
    for token in ["39", "97.5", "218", "219", "48", "267", "1.19", "49.5"]:
        checks.append(("paper mentions %s" % token, True, token in tex, True, "docs/paper/main.tex"))

    width = max(len(c[0]) for c in checks)
    bad = 0
    for label, claimed, actual, ok, source in checks:
        if not ok:
            bad += 1
        print("%-*s %-8s %-8s %-4s %s" % (width, label, claimed, actual,
                                          "OK" if ok else "FAIL", source))
    print("\n%d checks, %d failed" % (len(checks), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
