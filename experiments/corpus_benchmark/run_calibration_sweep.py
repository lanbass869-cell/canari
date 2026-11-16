# -*- coding: utf-8 -*-
"""How much would a self-calibrated threshold cost in recall? (labelled benchmark)

For each corpus size n, compute the exact neighbour profile E[nb@d] = 2*pairs(d)/n,
then pick the largest d whose expected false-neighbour count stays under TARGET.
Report precision / recall / FP at that operating point, next to the fixed d=2 rule.
"""
import json, io, os, random, sys, time

B = os.environ.get("CANARI_TYPO_BENCH",
                     r"E:\Temp\tbdig\bench\agent-skill-typosquat-bench")
sys.path.insert(0, os.path.join(B, "src"))
from detector import Detector, skeleton, _lev  # noqa: E402

D = os.path.join(B, "data"); OUT = os.path.dirname(os.path.abspath(__file__))
protected = json.load(io.open(os.path.join(D, "protected.json"), encoding="utf-8"))
legit = json.load(io.open(os.path.join(D, "legit_names.json"), encoding="utf-8"))
rows = [json.loads(l) for l in io.open(os.path.join(D, "dataset.jsonl"), encoding="utf-8") if l.strip()]
prot_set = set(protected); cands = {r["candidate"] for r in rows}
distractors_clean = [x["name"] for x in legit if x["name"] not in prot_set and x["name"] not in cands]

def profile(corpus, max_d=3):
    sk = [skeleton(n) for n in corpus]
    c = {d: 0 for d in range(1, max_d + 1)}
    for i in range(len(sk)):
        for j in range(i + 1, len(sk)):
            dist = _lev(sk[i], sk[j], max_d + 1)
            for d in c:
                if dist <= d: c[d] += 1
    return {d: 2.0 * c[d] / len(corpus) for d in c}

def d_eff(prof, target, max_d=3):
    best = 0
    for d in range(1, max_d + 1):
        if prof[d] <= target: best = d
    return best

def evaluate(corpus, t):
    det = Detector(corpus, edit_threshold=t)
    tp = fp = fn = 0
    for r in rows:
        hit = det.flag(r["candidate"])[0]
        if r["label"] == "typosquat":
            tp += 1 if hit else 0; fn += 0 if hit else 1
        else:
            fp += 1 if hit else 0
    p = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * rec / (p + rec) if p + rec else 0.0
    return {"precision": round(p, 4), "recall": round(rec, 4), "f1": round(f1, 4), "fp": fp}

out = {"benchmark": "Kemalyavas/agent-skill-typosquat-bench", "rows": len(rows), "points": []}
print("n      prof@1  prof@2  prof@3 | fixed d2 P/R/FP   | T=0.05 d  P/R/FP      | T=0.10 d  P/R/FP      | T=0.25 d  P/R/FP")
for n in (200, 400, 800, 1200, 1617):
    rng = random.Random(20261116 + n); k = n - len(protected)
    extra = (distractors_clean if k >= len(distractors_clean) else rng.sample(distractors_clean, k)) if k else []
    corpus = list(protected) + extra
    prof = profile(corpus)
    fixed = evaluate(corpus, 2)
    row = {"n": n, "profile": {str(d): round(v, 4) for d, v in prof.items()}, "fixed_d2": fixed, "calibrated": {}}
    parts = []
    for target in (0.05, 0.10, 0.25):
        d = d_eff(prof, target)
        r = evaluate(corpus, d)
        row["calibrated"][str(target)] = dict(d_eff=d, **r)
        parts.append("T=%.2f d=%d P=%.3f R=%.3f FP=%-3d" % (target, d, r["precision"], r["recall"], r["fp"]))
    out["points"].append(row)
    print("n=%-5d %.3f   %.3f   %.3f | d2 P=%.3f R=%.3f FP=%-3d | %s | %s | %s"
          % (n, prof[1], prof[2], prof[3], fixed["precision"], fixed["recall"], fixed["fp"], *parts))
    sys.stdout.flush()
io.open(os.path.join(OUT, "calibration.json"), "w", encoding="utf-8").write(json.dumps(out, ensure_ascii=False, indent=1))
print("wrote calibration.json")
