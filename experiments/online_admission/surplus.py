"""Surplus witnesses vs the corrupted root: does the cheaper defence work?

Proposition 1's corollary says a component citing r+s roots survives s corrupted
roots. This tests it on the same skewed stream that produced the 44.9% disaster,
and prices the defence in extra evidence requests rather than lost admissions.

Each component draws t roots (t = r + s). If the draw collapses to fewer than
ceil(r/... ) distinct roots it is recorded as insufficient evidence - the stream
cannot supply the surplus - which is the real constraint in this ecosystem.
"""
import json
import os
import random
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
R = 2          # threshold: this many independent witnesses are required
K = 200
N = 4000
ZIPF = 1.2


def draw(rng, weights):
    return rng.choices(range(K), weights=weights, k=1)[0]


def run(t, seed=5):
    rng = random.Random(seed)
    w = [1.0 / ((i + 1) ** ZIPF) for i in range(K)]
    admitted, insufficient = [], 0
    use = Counter()
    for _ in range(N):
        roots = set()
        for _try in range(3 * t):               # bounded attempts to get t distinct
            roots.add(draw(rng, w))
            if len(roots) >= t:
                break
        if len(roots) < t:
            insufficient += 1
        if len(roots) < R:
            continue
        roots = tuple(sorted(roots))
        admitted.append(roots)
        for x in roots:
            use[x] += 1
    top = use.most_common(1)[0][0] if use else None
    # corrupt exactly one root: a component survives iff it still has >= R witnesses
    invalid = sum(1 for roots in admitted if top in roots and len(roots) - 1 < R)
    return {
        "witnesses_per_component": t,
        "surplus_s": t - R,
        "admitted": len(admitted),
        "insufficient_evidence": insufficient,
        "extra_requests_per_component": t - R,
        "total_extra_requests": len(admitted) * (t - R),
        "invalidated_by_one_corrupted_root": invalid,
        "damage_rate": round(invalid / len(admitted), 4) if admitted else 0.0,
    }


if __name__ == "__main__":
    rows = [run(t) for t in (2, 3, 4)]
    out = {"threshold_r": R, "roots_k": K, "items_n": N, "root_usage": "zipf 1.2",
           "rows": rows,
           "note": ("surplus is bought with requests, not with admissions; the "
                    "insufficient column is how often the environment cannot "
                    "supply that many distinct roots at all")}
    with open(os.path.join(HERE, "surplus_result.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print(json.dumps(out, indent=1))
