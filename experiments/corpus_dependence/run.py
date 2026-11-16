# -*- coding: utf-8 -*-
"""Corpus dependence of name-similarity (typosquat) verdicts.

Reproduce:  python run.py        (deterministic; seed fixed)
Inputs:     names.txt            (620 names beginning with "mcp-server-", from the
                                  public PyPI simple index, captured 2026-11-16)
Outputs:    results.json

Why this exists
---------------
A name-similarity verdict answers "is this package close to some other package?"
-- a question about a *set*, not about one package. Two consequences follow, and
both are measured here:

  1. The number of close pairs grows quadratically with corpus size, so the
     fraction of names that get flagged grows with it (the curve below).
  2. A fixed target can therefore change verdict purely because the corpus it
     was compared against changed, with no change to the target itself
     (the flip experiment below). This is the reproducibility defect: the same
     bytes are "clean" or "a likely typosquat" depending on how much of the
     registry the scanner happened to load.
"""
import io
import json
import os
import random
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from canari.typosquat import _damerau_levenshtein  # noqa: E402

SEED = 20261116
NAMES = os.path.join(HERE, "names.txt")


def load_pool():
    with io.open(NAMES, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip()]


def fold(s):
    return s.casefold().replace("-", "")


def _threshold(mx, dmax):
    return dmax if dmax is not None else (1 if mx < 8 else 2)


def flagged_set(names, dmax=None):
    """Names having at least one neighbour within the threshold."""
    folded = [fold(n) for n in names]
    out = set()
    for i in range(len(folded)):
        for j in range(i + 1, len(folded)):
            d = _threshold(max(len(folded[i]), len(folded[j]), 1), dmax)
            if abs(len(folded[i]) - len(folded[j])) > d:
                continue
            if _damerau_levenshtein(folded[i], folded[j]) <= d:
                out.add(names[i])
                out.add(names[j])
    return out


def pairs_count(names, dmax=None):
    folded = [fold(n) for n in names]
    count = 0
    for i in range(len(folded)):
        for j in range(i + 1, len(folded)):
            d = _threshold(max(len(folded[i]), len(folded[j]), 1), dmax)
            if abs(len(folded[i]) - len(folded[j])) > d:
                continue
            if _damerau_levenshtein(folded[i], folded[j]) <= d:
                count += 1
    return count


def main():
    pool = load_pool()
    res = {"pool_size": len(pool), "seed": SEED}

    # 1) flip experiment: 60 fixed targets, small corpus vs full corpus
    rng = random.Random(SEED)
    targets = sorted(rng.sample(pool, 60))
    small = flagged_set(targets)
    full = flagged_set(pool)
    in_small = {t for t in targets if t in small}
    in_full = {t for t in targets if t in full}
    only_full = in_full - in_small
    only_small = in_small - in_full
    res["flip"] = {
        "n_targets": len(targets),
        "flagged_in_small_corpus": len(in_small),
        "flagged_in_full_corpus": len(in_full),
        "both": len(in_small & in_full),
        "clean_only_in_small": len(only_small),
        "typosquat_only_in_full": len(only_full),
        "neither": len(set(targets) - in_small - in_full),
        "flip_rate_of_all_targets": round(
            (len(only_small) + len(only_full)) / len(targets), 4),
        "examples_flagged_only_in_full": sorted(only_full)[:5],
    }

    # 2) corpus-size curve (5 samples per size)
    curve = []
    for n in (50, 100, 200, 300, 400, 500, 620):
        fracs, prs = [], []
        for t in range(5):
            if n < len(pool):
                sub = sorted(random.Random(SEED + 1000 * n + t).sample(pool, n))
            else:
                sub = list(pool)
            fracs.append(len(flagged_set(sub)) / n)
            prs.append(pairs_count(sub))
        curve.append({
            "n": n,
            "flagged_fraction_mean": round(statistics.mean(fracs), 4),
            "flagged_fraction_sd": round(statistics.pstdev(fracs), 4),
            "pairs_mean": round(statistics.mean(prs), 1),
            "pairs_per_n_squared": round(statistics.mean(prs) / (n * n), 5),
        })
    res["corpus_size_curve"] = curve

    # 3) threshold sensitivity at full corpus
    res["threshold_sensitivity"] = [
        {"max_distance": d,
         "flagged": len(flagged_set(pool, dmax=d)),
         "flagged_fraction": round(len(flagged_set(pool, dmax=d)) / len(pool), 4),
         "pairs": pairs_count(pool, dmax=d)}
        for d in (1, 2, 3)
    ]

    path = os.path.join(HERE, "results.json")
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(res, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
