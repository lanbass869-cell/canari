"""Cross-check every headline number in the paper against its artifact.

The project has twice shipped a number that disagreed with another artifact (the PEP 440
false positives, and the tombstone bucket split). This checks the paper's claims against
the JSON that produced them, so a future edit cannot silently drift.

    python scripts/check_paper_numbers.py
"""
import json
import os
import re
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

    # Presence is not consistency. 268 survived in the abstract and the conclusion while
    # the body said 267 because the check only asked "does the number appear somewhere".
    # So: (a) the paper must not contain any superseded value, and (b) every statement of
    # the same quantity must agree — one distinct value across the whole manuscript.
    tex = open(PAPER, encoding="utf-8").read()

    for stale_value, why in [("268", "274-7=267"), ("151", "pre-tombstone split"),
                             ("123", "pre-tombstone split")]:
        present = stale_value in tex
        checks.append(("paper has no stale %s (%s)" % (stale_value, why), False, present,
                       present is False, "docs/paper/main.tex"))

    # All phrasings that state the total unresolvable count, grouped by quantity.
    # Line breaks fall inside these phrases in the .tex source, so match across newlines.
    total_patterns = [
        r"at\s+most (\d+)\s*\(",
        r"\\textbf\{(\d+)\} unresolvable",
        r"(\d+) unresolved\s+references",
    ]
    seen_totals = sorted({m.group(1) for pat in total_patterns for m in re.finditer(pat, tex)})
    checks.append(("single unresolvable total across paper", ["267"], seen_totals,
                   seen_totals == ["267"], "docs/paper/main.tex (all statements)"))

    pep = re.search(r"so (\w+) of the 32 PyPI version-absent rows were not defects", tex)
    words = {"six": 6, "seven": 7}
    pep_n = words.get(pep.group(1)) if pep else None
    checks.append(("PEP 440 false positives stated as 7", 7, pep_n, pep_n == 7,
                   "docs/paper/main.tex verbatim"))
    checks.append(("274 - PEP440(7) == reported total", "267", str(src_rows := 274 - 7),
                   src_rows == 267, "audit report arithmetic"))

    checks.append(("267 == 219+48", 267, counts["package-gone"] + counts["version-absent"],
                   counts["package-gone"] + counts["version-absent"] == 267,
                   "tombstone_reclass.json status_counts"))

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
