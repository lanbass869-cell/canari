# -*- coding: utf-8 -*-
"""Margin gate applied ON TOP of the shipped detector.

base   = the benchmark's own Detector (skeleton/affix/exact rules + edit<=2)
gated  = base AND (the best match is strictly closer than the next closest)

The point is not to replace their detector but to ask whether a cheap "is this
match distinctive, or just the densest one in a crowd?" test reduces the
corpus-size sensitivity measured in README.md.
"""
import json, io, os, random, sys

B = os.environ.get("CANARI_TYPO_BENCH", r"E:\Temp\tbdig\bench\agent-skill-typosquat-bench")
sys.path.insert(0, os.path.join(B, "src"))
from detector import Detector, skeleton, _lev  # noqa: E402

D = os.path.join(B, "data")
protected = json.load(io.open(os.path.join(D, "protected.json"), encoding="utf-8"))
legit = json.load(io.open(os.path.join(D, "legit_names.json"), encoding="utf-8"))
rows = [json.loads(l) for l in io.open(os.path.join(D, "dataset.jsonl"), encoding="utf-8") if l.strip()]
prot_set = set(protected); cands = {r["candidate"] for r in rows}
distractors_clean = [x["name"] for x in legit if x["name"] not in prot_set and x["name"] not in cands]

def distinct(sk_c, corpus_sk, cap=4):
    """True if the closest corpus name is strictly closer than the next one."""
    d1 = d2 = cap + 1
    for s in corpus_sk:
        if s == sk_c:
            continue
        d = _lev(sk_c, s, cap)
        if d < d1:
            d2, d1 = d1, d
        elif d < d2:
            d2 = d
    return (d2 - d1) >= 1

def evaluate(corpus, tau=2, gate=False):
    det = Detector(corpus, edit_threshold=tau)
    csk = [skeleton(y) for y in corpus]
    tp = fp = fn = 0
    for r in rows:
        hit = det.flag(r["candidate"])[0]
        if hit and gate:
            hit = distinct(skeleton(r["candidate"]), csk)
        if r["label"] == "typosquat":
            tp += 1 if hit else 0; fn += 0 if hit else 1
        else:
            fp += 1 if hit else 0
    p = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * rec / (p + rec) if p + rec else 0.0
    return round(p, 3), round(rec, 3), round(f1, 3), fp

print("base = benchmark Detector (edit<=2);  gated = base AND distinctive match")
print(" n     | base    P/R/F1/FP          | +margin gate P/R/F1/FP")
for n in (200, 400, 800, 1200, 1617):
    rng = random.Random(20261116 + n); k = n - len(protected)
    extra = (distractors_clean if k >= len(distractors_clean) else rng.sample(distractors_clean, k)) if k else []
    corpus = list(protected) + extra
    a = evaluate(corpus, 2, gate=False)
    b = evaluate(corpus, 2, gate=True)
    print("n=%-5d| P=%.3f R=%.3f F1=%.3f FP=%-4d| P=%.3f R=%.3f F1=%.3f FP=%-4d"
          % (n, a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]))
    sys.stdout.flush()
