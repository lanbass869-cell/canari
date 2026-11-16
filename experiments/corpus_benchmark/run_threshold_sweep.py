# -*- coding: utf-8 -*-
"""Corpus-size dependence measured on a THIRD-PARTY labelled benchmark.

Input: Kemalyavas/agent-skill-typosquat-bench (CC BY 4.0 dataset, MIT code).
Manipulation: keep detector and candidate set fixed; grow the comparison corpus
by adding *real* registry names that are not protected. Any change in
precision/recall is therefore attributable to corpus size alone.
"""
import json, io, os, random, statistics, sys

B = os.environ.get("CANARI_TYPO_BENCH",
                     r"E:\Temp\tbdig\bench\agent-skill-typosquat-bench")
sys.path.insert(0, os.path.join(B, "src"))
from detector import Detector  # noqa: E402

D = os.path.join(B, "data")
OUT = os.path.dirname(os.path.abspath(__file__))
os.makedirs(OUT, exist_ok=True)

protected = json.load(io.open(os.path.join(D, "protected.json"), encoding="utf-8"))
legit = json.load(io.open(os.path.join(D, "legit_names.json"), encoding="utf-8"))
rows = [json.loads(l) for l in io.open(os.path.join(D, "dataset.jsonl"), encoding="utf-8") if l.strip()]

prot_set = set(protected)
distractors = [x["name"] for x in legit if x["name"] not in prot_set]
cand_set = {r["candidate"] for r in rows}
distractors_clean = [n for n in distractors if n not in cand_set]

print("protected=%d distractors=%d (clean=%d) candidates=%d"
      % (len(protected), len(distractors), len(distractors_clean), len(rows)))

def evaluate(corpus, t):
    det = Detector(corpus, edit_threshold=t)
    tp = fp = fn = tn = hard_fp = 0
    flagged_neg = set()
    for r in rows:
        hit = det.flag(r["candidate"])[0]
        if r["label"] == "typosquat":
            tp += 1 if hit else 0
            fn += 0 if hit else 1
        else:
            if hit:
                fp += 1; flagged_neg.add(r["candidate"])
                hard_fp += 1 if r.get("hard_negative") else 0
            else:
                tn += 1
    p = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * rec / (p + rec) if p + rec else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(p, 4), "recall": round(rec, 4), "f1": round(f1, 4),
            "hard_neg_fp": hard_fp, "flagged_negatives": sorted(flagged_neg)}

SIZES = [200, 400, 800, 1200, 1617]
TRIALS = 3
result = {"benchmark": "Kemalyavas/agent-skill-typosquat-bench", "rows": len(rows),
          "protected_base": len(protected), "curve": []}

for t in (1, 2):
    base = evaluate(protected, t)
    base_neg = set(base["flagged_negatives"])
    for n in SIZES:
        k = n - len(protected)
        reps = []
        trials = TRIALS if k < len(distractors_clean) else 1
        for trial in range(trials):
            rng = random.Random(20261116 + 1000 * n + trial)
            extra = (distractors_clean if k >= len(distractors_clean) else rng.sample(distractors_clean, k)) if k > 0 else []
            r = evaluate(list(protected) + extra, t)
            r["new_fps_vs_base"] = len(set(r["flagged_negatives"]) - base_neg)
            reps.append(r)
        agg = {"threshold": t, "n": n, "trials": len(reps),
               "precision_mean": round(statistics.mean(x["precision"] for x in reps), 4),
               "precision_min": min(x["precision"] for x in reps),
               "recall_mean": round(statistics.mean(x["recall"] for x in reps), 4),
               "f1_mean": round(statistics.mean(x["f1"] for x in reps), 4),
               "fp_mean": round(statistics.mean(x["fp"] for x in reps), 1),
               "hard_neg_fp_mean": round(statistics.mean(x["hard_neg_fp"] for x in reps), 1),
               "new_fps_vs_base_mean": round(statistics.mean(x["new_fps_vs_base"] for x in reps), 1)}
        result["curve"].append(agg)
        print("t=%d n=%-5d P=%.3f(min %.3f) R=%.3f F1=%.3f FP=%.1f hardFP=%.1f newFP=%.1f"
              % (t, n, agg["precision_mean"], agg["precision_min"], agg["recall_mean"],
                 agg["f1_mean"], agg["fp_mean"], agg["hard_neg_fp_mean"], agg["new_fps_vs_base_mean"]))
        sys.stdout.flush()

io.open(os.path.join(OUT, "results.json"), "w", encoding="utf-8").write(json.dumps(result, ensure_ascii=False, indent=1))
print("wrote results.json")
