"""What does buying down single-root damage cost?

The adaptive experiment showed one corrupted root can retroactively invalidate
44.9% of a per-item policy's admissions when root usage is skewed. This measures
the obvious defence: cap how much of the admitted set may depend on any one root.

For a cap q, after admitting an item the per-root dependence count may not exceed
q * (admitted so far + 1). Sweep q and report what it costs in admissions.

The cap works by construction - the measurement is the PRICE, not the effect.
"""
import json
import os
import random
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))


def build(k=200, n=4000, zipf_s=1.2, seed=5):
    rng = random.Random(seed)
    w = [1.0 / ((i + 1) ** zipf_s) for i in range(k)]
    out = []
    for _ in range(n):
        a = rng.choices(range(k), weights=w, k=1)[0]
        b = rng.choices(range(k), weights=w, k=1)[0]
        if a == b:
            b = (b + 1) % k
        out.append((a, b))
    return out


def run(pairs, q):
    """q=None means no cap."""
    use = Counter()
    admitted = []
    for idx, (a, b) in enumerate(pairs):
        if q is not None:
            total = len(admitted) + 1
            cap = max(1, int(q * total))
            if use[a] + 1 > cap or use[b] + 1 > cap:
                continue
        use[a] += 1
        use[b] += 1
        admitted.append((idx, a, b))
    top = use.most_common(1)[0] if use else (None, 0)
    dead = sum(1 for _i, a, b in admitted if top[0] in (a, b))
    return {"cap": q, "admitted": len(admitted),
            "most_used_root": top[0], "items_on_it": top[1],
            "invalidated": dead,
            "damage_rate": round(dead / len(admitted), 4) if admitted else 0.0}


if __name__ == "__main__":
    pairs = build()
    base = run(pairs, None)
    rows = [base]
    for q in (0.3, 0.2, 0.1, 0.05):
        r = run(pairs, q)
        r["admission_cost_vs_nocap"] = round(1 - r["admitted"] / base["admitted"], 4)
        rows.append(r)
    out = {"n_items": len(pairs), "roots": 200, "rule": "2 distinct roots",
           "rows": rows,
           "note": ("the cap bounds damage by construction; the number that matters "
                    "is how many admissions it costs to reach a given bound")}
    with open(os.path.join(HERE, "policy_result.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print(json.dumps(out, indent=1))
