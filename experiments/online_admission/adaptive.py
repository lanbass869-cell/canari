"""Adaptive corruption: what happens when the attacker corrupts the root you
already trusted?

The static experiment (sim.py) asked "how many false admissions at threshold t".
This one asks the question adaptivity actually raises: admissions are
IRREVERSIBLE, so an adversary that corrupts a root *after* the algorithm has used
it retroactively invalidates items that were already admitted.

Two rules, same stream:
  A  per-item: >=2 distinct roots
  B  per-item: >=2 distinct roots AND >=2 distinct root FAMILIES

Root families stand in for the 4 ecosystems Canari actually reads (npm, PyPI, MCP
Registry, dsh). Family-diverse evidence is the cheap operational proxy for
"corruption-distinct": two witnesses in the same family can share one upstream.
"""
import json
import os
import random
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
FAMILIES = 4


def draw_root(rng, k, zipf_s):
    """Continuous weight -> popular roots are reused a lot (zipf_s=0 uniform)."""
    if zipf_s == 0:
        return rng.randrange(k)
    w = [1.0 / ((i + 1) ** zipf_s) for i in range(k)]
    return rng.choices(range(k), weights=w, k=1)[0]


def build(k=200, n=4000, zipf_s=1.2, seed=5):
    rng = random.Random(seed)
    roots = [(draw_root(rng, k, zipf_s), draw_root(rng, k, zipf_s)) for _ in range(n)]
    # de-duplicate a pair that drew the same root twice (retry once)
    fixed = []
    for a, b in roots:
        if a == b:
            b = (b + 1) % k
        fixed.append((a, b))
    return fixed


def family(r, k=200):
    return r * FAMILIES // k


def evaluate(pairs, rule):
    admitted = []
    for i, (a, b) in enumerate(pairs):
        if len({a, b}) < 2:
            continue
        if rule == "B" and family(a) == family(b):
            continue
        admitted.append((i, a, b))
    return admitted


def invalidate(admitted, corrupt_root):
    """An admitted item survives only if it still has >=2 independent witnesses."""
    dead = sum(1 for _i, a, b in admitted if corrupt_root in (a, b))
    return dead, (dead / len(admitted)) if admitted else 0.0


if __name__ == "__main__":
    out = {}
    for label, zs in (("uniform root usage", 0), ("skewed root usage (zipf 1.2)", 1.2)):
        pairs = build(zipf_s=zs)
        row = {}
        for rule in ("A", "B"):
            adm = evaluate(pairs, rule)
            usage = Counter()
            for _i, a, b in adm:
                usage[a] += 1
                usage[b] += 1
            top = usage.most_common(1)[0] if usage else (None, 0)
            dead, rate = invalidate(adm, top[0])
            row[rule] = {
                "admitted": len(adm),
                "most_relied_upon_root": top[0],
                "items_using_it": top[1],
                "retroactively_invalid_after_corrupting_that_root": dead,
                "retroactive_invalidation_rate": round(rate, 4),
            }
        out[label] = row
    with open(os.path.join(HERE, "adaptive_result.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print(json.dumps(out, indent=1))
