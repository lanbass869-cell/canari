# -*- coding: utf-8 -*-
"""Does any name normalization restore the gap between attacks and accidents?

The trade-off note (THEORY.md) says precision-stability + recall-stability needs
a threshold tau* with p(tau*) = 0 while almost all attacks sit at or below tau*.
For plain edit distance this fails because p(tau) > 0 for every tau >= 1.

So test candidate normalizations on a labelled benchmark and ask, for each:
does it reduce the null collision rate without destroying attack recall?

Arms:
  raw        their detector as shipped
  brand_gate their detector, but only compare names that share a non-generic
             token (brand), so two unrelated `*/mcp-server` do not collide
"""
import json, io, os, random, re, sys

B = os.environ.get("CANARI_TYPO_BENCH", r"E:\Temp\tbdig\bench\agent-skill-typosquat-bench")
sys.path.insert(0, os.path.join(B, "src"))
from detector import Detector, skeleton, _lev, PREFIXES, SUFFIXES  # noqa: E402

D = os.path.join(B, "data")
OUT = r"E:\Temp\tbdig\corpus_bench"
protected = json.load(io.open(os.path.join(D, "protected.json"), encoding="utf-8"))
legit = json.load(io.open(os.path.join(D, "legit_names.json"), encoding="utf-8"))
rows = [json.loads(l) for l in io.open(os.path.join(D, "dataset.jsonl"), encoding="utf-8") if l.strip()]
prot_set = set(protected); cands = {r["candidate"] for r in rows}
distractors_clean = [x["name"] for x in legit if x["name"] not in prot_set and x["name"] not in cands]

GENERIC = {
    "mcp", "mcps", "server", "servers", "model", "models", "context", "protocol",
    "skill", "skills", "plugin", "plugins", "agent", "agents", "ai", "tool", "tools",
    "api", "apis", "sdk", "cli", "js", "ts", "node", "python", "py", "official",
    "real", "the", "secure", "core", "lib", "kit", "bot", "app", "service", "services",
}

def tokens(name):
    return [t for t in re.split(r"[^A-Za-z0-9]+", name.casefold()) if t]

def brand(name):
    return {t for t in tokens(name) if t not in GENERIC}

def brand_overlap(a, b):
    ba, bb = brand(a), brand(b)
    if ba and bb:
        return bool(ba & bb)
    return True  # if a side has no brand token, do not gate it away

def evaluate(corpus, t, gate):
    det = Detector(corpus, edit_threshold=t)
    tp = fp = fn = 0
    for r in rows:
        hit = det.flag(r["candidate"])[0]
        if hit and gate:
            # re-check against the corpus with the brand gate applied
            hit = False
            cs = skeleton(r["candidate"])
            for y in corpus:
                if not brand_overlap(r["candidate"], y):
                    continue
                if _lev(cs, skeleton(y), t + 1) <= t:
                    hit = True
                    break
        if r["label"] == "typosquat":
            tp += 1 if hit else 0; fn += 0 if hit else 1
        else:
            fp += 1 if hit else 0
    p = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * rec / (p + rec) if p + rec else 0.0
    return round(p, 4), round(rec, 4), round(f1, 4), fp

print("threshold=2, corpus grows with real distractors")
print(" n     | shipped  P/R/F1/FP        | +brand gate  P/R/F1/FP")
for n in (200, 400, 800, 1200, 1617):
    rng = random.Random(20261116 + n)
    k = n - len(protected)
    extra = (distractors_clean if k >= len(distractors_clean) else rng.sample(distractors_clean, k)) if k else []
    corpus = list(protected) + extra
    a = evaluate(corpus, 2, gate=False)
    b = evaluate(corpus, 2, gate=True)
    print("n=%-5d| P=%.3f R=%.3f F1=%.3f FP=%-4d| P=%.3f R=%.3f F1=%.3f FP=%-4d"
          % (n, a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]))
    sys.stdout.flush()
