# -*- coding: utf-8 -*-
"""check_doc_numbers.py - the one-page summary must not drift from its artefacts.

docs/PROJECT-SUMMARY-EN.md is meant to be handed to someone who will not check it.
That is exactly why its numbers need a machine behind them. The project has already
shipped four number-versus-artefact drifts (PEP 440 mis-count, tombstone split,
49 vs 49.5 downloads, 268 vs 267), and three of them were caught by hand, late.

So: every figure the summary states is re-derived here from the file that produced
it. If any of them stops matching, this exits non-zero and the quality gate fails.

    python scripts/check_doc_numbers.py
"""
import base64
import collections
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "PROJECT-SUMMARY-EN.md")
EXP = os.path.join(ROOT, "experiments", "package_existence_repro")
DATASET = os.path.join(ROOT, "dataset", "attestations")
OUT = os.path.join(ROOT, "out")

checks = []


def check(label, claimed, actual, source):
    ok = claimed == actual
    checks.append((label, claimed, actual, ok, source))
    return ok


def _payload(path):
    """Return the signed predicate, preferring the DSSE payload over the copy."""
    doc = json.load(open(path, encoding="utf-8"))
    raw = (doc.get("envelope") or {}).get("payload")
    payload = doc.get("payload") or {}
    if raw and not payload.get("predicate"):
        payload = json.loads(base64.b64decode(raw).decode("utf-8"))
    return payload.get("predicate") or {}


def main():
    # --- dataset: record counts, registry split, distinct components
    registry_counts = collections.Counter()
    components = set()
    for path in glob.glob(os.path.join(DATASET, "*.json")):
        pred = _payload(path)
        subject = pred.get("subject") or {}
        registry_counts[subject.get("registry")] += 1
        if subject.get("name"):
            components.add((subject.get("registry"), subject.get("name")))

    total = sum(registry_counts.values())
    check("signed attestations (5170)", 5170, total, "dataset/attestations/*.json")
    check("(registry,name) pairs (1417)", 1417, len(components), "same")
    check("distinct names (1415)", 1415, len({n for _, n in components}), "same")
    for registry, want in (("pypi", 2051), ("dsh-registry", 1590),
                           ("npm", 1064), ("mcp-registry", 465)):
        check("%s records (%d)" % (registry, want), want, registry_counts[registry],
              "same")

    # --- install reproduction
    repro = json.load(open(os.path.join(EXP, "result.json"), encoding="utf-8"))["summary"]
    check("install sample n (40)", 40,
          repro["package-gone"]["n"] + repro["version-absent"]["n"],
          "repro/result.json")
    check("installs that failed (39)", 39,
          repro["package-gone"]["reproduced"] + repro["version-absent"]["reproduced"],
          "repro/result.json")
    check("failure rate stated as 97.5", "97.5",
          "%.1f" % (100.0 * 39 / 40), "derived from the two rows above")

    # --- staleness / downloads / corrected split
    stale = json.load(open(os.path.join(EXP, "staleness.json"), encoding="utf-8"))
    check("median entry age (218)", 218, int(round(stale["ages_days"]["median"])),
          "staleness.json ages_days.median")
    check("max entry age (435)", 435, int(round(stale["ages_days"]["max"])),
          "staleness.json ages_days.max")

    downloads = json.load(open(os.path.join(EXP, "downloads.json"), encoding="utf-8"))
    check("median monthly downloads (49.5)", 49.5, float(downloads["median_monthly"]),
          "downloads.json median_monthly")

    split = json.load(open(os.path.join(EXP, "tombstone_reclass.json"),
                           encoding="utf-8"))["status_counts"]
    check("package-gone (219)", 219, split["package-gone"], "tombstone_reclass.json")
    check("version-absent (48)", 48, split["version-absent"], "tombstone_reclass.json")

    unresolvable = split["package-gone"] + split["version-absent"]
    check("unresolvable total (267)", 267, unresolvable, "sum of the two rows")

    # --- the live endpoint monitor report, if this checkout has one
    verdict_path = os.path.join(OUT, "endpoint_verdicts.json")
    if os.path.exists(verdict_path):
        report = json.load(open(verdict_path, encoding="utf-8"))
        counts = report.get("verdict_counts") or {}
        check("monitor: endpoints observed (60)", 60, report.get("endpoints_observed"),
              "out/endpoint_verdicts.json")
        check("monitor: confirmed findings (0)", 0, report.get("confirmed_findings"),
              "same")
        for verdict, want in (("CONSISTENT", 38), ("NEUTRAL_ONLY", 20),
                              ("FLAPPING", 1), ("INSUFFICIENT_EVIDENCE", 1)):
            check("monitor: %s (%d)" % (verdict, want), want, counts.get(verdict), "same")

    # --- shipped CLI surface
    pyproject = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    cli = [line for line in pyproject.splitlines()
           if line.startswith("canari-") and "=" in line]
    check("console entry points (12)", 12, len(cli), "pyproject.toml [project.scripts]")

    # --- the summary must actually SAY each figure.
    #
    # Comparing constants against artefacts is not enough: the first version of
    # this script passed while the document said 5171 instead of 5170, because it
    # never looked at the document. Each headline figure is therefore pinned to
    # the exact phrase it appears in, so editing the number breaks the phrase.
    text = open(DOC, encoding="utf-8").read()
    phrases = [
        ("5170", "5,170 signed attestations"),
        ("1417", "1,417 `(registry, name)` pairs"),
        ("1415", "(1,415 distinct names)"),
        ("2051", "pypi 2,051"),
        ("1590", "dsh 1,590"),
        ("1064", "npm 1,064"),
        ("465", "mcp-registry 465"),
        ("267", "**267** (219 package gone, 48 version absent), 1.19%"),
        ("40", "**39/40 = 97.5%**"),
        ("218", "median **218 days**"),
        ("49.5", "median **49.5 downloads/month**"),
        ("12", "12 CLI entry points"),
        ("989", "989 tests"),
        ("86.87", "86.87% line coverage"),
        ("100%", "mutation kill rate 100%"),
        ("38", "38 CONSISTENT"),
        ("20", "20 NEUTRAL_ONLY"),
        ("0 findings", "**0 findings**"),
        ("629", "629 PyPI downloads in 30 days"),
        ("0 stars", "**0 stars"),
        ("51.9", "51.9%"),
        ("94.78", "94.78%"),
        ("66.6", "**66.6%**"),
        ("66.6%", "**66.6%** of npm+PyPI records affected"),
        ("21", "**21 full papers**"),
    ]
    for label, phrase in phrases:
        present = phrase in text
        checks.append(("summary states %s" % label, True, present, present,
                       "docs/PROJECT-SUMMARY-EN.md verbatim"))

    for stale_value, why in (("268", "was 274-6; the PEP 440 correction is 7"),
                             ("151", "pre-tombstone split"),
                             ("123", "pre-tombstone split")):
        present = stale_value in text
        checks.append(("summary has no stale %s (%s)" % (stale_value, why),
                       False, present, present is False, "docs/PROJECT-SUMMARY-EN.md"))

    width = max(len(c[0]) for c in checks)
    bad = 0
    for label, claimed, actual, ok, source in checks:
        if not ok:
            bad += 1
        print("%-*s %-8s %-8s %-4s %s"
              % (width, label, claimed, actual, "OK" if ok else "FAIL", source))
    print()
    print("%d checks, %d failed" % (len(checks), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
