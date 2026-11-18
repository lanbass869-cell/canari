"""Online admission with a corruption budget: what breaks, and by how much.

Model (see docs/theory/online-admission.md):
  - a stream of (component, witness_root) pairs arrives one at a time;
  - an item is admissible iff it has evidence from >= r DISTINCT roots;
  - up to c roots are corrupted and will vouch for anything;
  - the algorithm has bounded memory and must decide online, per item.

Three rules are compared:
  exact  - per-item set of roots (unbounded memory, the oracle)
  count  - per-item counter of records (the obvious cheap thing)
  bloom  - one Bloom filter over (item, root) with a per-item counter of new keys
"""
import json
import os
import random
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))


class Exact:
    name = "exact"

    def __init__(self, r=2):
        self.r = r
        self.seen = defaultdict(set)

    def offer(self, item, root):
        self.seen[item].add(root)
        return len(self.seen[item]) >= self.r

    def memory_bytes(self):
        return sum(len(s) * 8 for s in self.seen.values()) + 32 * len(self.seen)


class Count:
    """The naive rule: count records, not distinct roots."""
    name = "count"

    def __init__(self, r=2):
        self.r = r
        self.n = defaultdict(int)

    def offer(self, item, root):
        self.n[item] += 1
        return self.n[item] >= self.r

    def memory_bytes(self):
        return 4 * len(self.n) + 32 * len(self.n)


class Bloom:
    """Bounded memory. A key is inserted at most once; the per-item counter only
    advances when the filter says 'new', so a repeat from the same root does not
    advance it (except on false positives; those cause false REJECTS)."""
    name = "bloom"

    def __init__(self, r=2, bits_per_key=10, expected_keys=20000):
        self.r = r
        self.m = max(1024, bits_per_key * expected_keys)
        self.k = 4
        self.bits = bytearray(self.m // 8 + 1)
        self.count = defaultdict(int)

    def _hashes(self, key):
        import hashlib
        h1 = int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big")
        h2 = int.from_bytes(hashlib.sha256(("#" + key).encode()).digest()[:8], "big")
        return [((h1 + i * h2) % self.m) for i in range(self.k)]

    def offer(self, item, root):
        key = str(item) + "\x00" + str(root)
        hs = self._hashes(key)
        is_new = not all(self.bits[h // 8] >> (h % 8) & 1 for h in hs)
        if is_new:
            for h in hs:
                self.bits[h // 8] |= 1 << (h % 8)
            self.count[item] += 1
        return self.count[item] >= self.r

    def memory_bytes(self):
        return len(self.bits) + 4 * len(self.count) + 32 * len(self.count)


def make_stream(seed=7, n_items=2000, n_roots=200, genuine_roots=2,
                forged_per_item=0, corrupted_roots=0, fraction_attacked=0.5):
    """Each item gets `genuine_roots` real witnesses; with probability
    `fraction_attacked` a corrupted root also adds `forged_per_item` records for
    that item (the same root repeated - the cheap attack)."""
    rng = random.Random(seed)
    corrupted = set(rng.sample(range(n_roots), corrupted_roots)) if corrupted_roots else set()
    clean = [i for i in range(n_roots) if i not in corrupted]
    stream = []
    for item in range(n_items):
        roots = rng.sample(clean, genuine_roots)
        recs = [(item, r) for r in roots]
        if corrupted and forged_per_item and rng.random() < fraction_attacked:
            bad = rng.choice(sorted(corrupted))
            recs += [(item, bad)] * forged_per_item
        rng.shuffle(recs)
        stream.extend(recs)
    return stream, corrupted


def evaluate(cls, stream, r=2):
    algo = cls(r=r)
    decisions = {}
    for item, root in stream:
        decisions[item] = algo.offer(item, root)
    return algo, decisions


def score(decisions, truth, r=2):
    """truth[item] = set of roots that spoke for it. Admissible iff |truth| >= r."""
    adm = [i for i, d in decisions.items() if d]
    bad = [i for i in adm if len(truth.get(i, ())) < r]
    return {"admitted": len(adm), "false_admits": len(bad),
            "false_admit_rate": (len(bad) / len(adm)) if adm else 0.0}


if __name__ == "__main__":
    """The finding is not "one rule beats another" - it is that the threshold has
    to cover the corruption budget, and nobody knows the budget.

    Benign items carry 2 or 3 independent witnesses. An attacked item carries ONE
    independent witness plus one corrupted root (which is a distinct root, so a
    distinct-root counter counts it).

    t = 2  counts the corrupted root as evidence -> every attacked item admitted
    t = 3  rejects every attacked item, and also rejects benign items with only 2
    """
    n = 4000
    rng = random.Random(11)
    corrupted = {999}
    stream, attacked = [], set()
    for item in range(n):
        is_attacked = rng.random() < 0.25
        if is_attacked:
            # The attacker SUBSTITUTES for a missing witness: one honest root,
            # plus a corrupted root pretending to be a second authority.
            genuine = 1
            attacked.add(item)
        else:
            genuine = 2 if rng.random() < 0.6 else 3
        recs = [(item, rng.randrange(100, 998)) for _ in range(genuine)]
        if is_attacked:
            recs.append((item, 999))
        rng.shuffle(recs)
        stream.extend(recs)

    exact, _dec = evaluate(Exact, stream, r=2)      # r=2, ignores the budget
    rows = []
    for t in (2, 3, 4):
        algo = Exact(r=t)
        dec = {}
        for item, root in stream:
            dec[item] = algo.offer(item, root)
        adm = {i for i, d in dec.items() if d}
        fa = len(adm & attacked)
        # false rejects: attacked items rejected is CORRECT; benign rejected is not
        benign = set(range(n)) - attacked
        fr = len(benign - adm)
        rows.append({
            "threshold": t,
            "admitted": len(adm),
            "false_admits": fa,
            "false_admit_rate": round(fa / max(1, len(attacked)), 4),
            "false_rejects": fr,
            "false_reject_rate": round(fr / max(1, len(benign)), 4),
            "memory_kb": round(algo.memory_bytes() / 1024, 1),
        })

    out = {"n_items": n, "attacked": len(attacked), "corrupted_roots": 1,
           "benign_roots": "2 (60%) or 3 (40%)", "rows": rows,
           "note": ("A corrupted root is still a distinct root, so a distinct-root "
                    "counter cannot tell it apart from an honest one. The correct "
                    "threshold is r + c; c is unknown and must be estimated online.")}
    with open(os.path.join(HERE, "result.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print(json.dumps(out, indent=1))
