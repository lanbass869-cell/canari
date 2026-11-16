# When the Corpus Decides

## Why name-similarity verdicts are not reproducible without their comparison set

> **中文摘要**　本文报告一个在两类数据上独立复现的现象：名称相似度类供应链检测（typosquatting / 依赖混淆）给出的结论，是**比较语料**的属性，而不是被检包的属性。同一份包、同一份代码、同一个阈值，只因扫描时载入的语料规模不同，判定就会翻转。我们在自建的 620 个 `mcp-server-*` 命名空间上测到 **21.7% 的包会翻转**（13/60，且反向翻转恒为 0，说明效应是单调的）；在第三方标注基准（Kemalyavas/agent-skill-typosquat-bench）上，把语料从 200 个受保护名扩到 1,617 个，**精确率 0.985 → 0.940、误报 18 → 74，而召回恒定 0.964**。第 5 节给出一个并集界论证，说明这不是实现缺陷：在 `p(τ) > 0` 对所有可用阈值成立时，精确率与召回率**不可能同时**随语料规模保持稳定，除非存在一个"真攻击严格比任何偶然碰撞更近"的空隙。第 6 节测试了三种自然想到的逃离方案（品牌门控、边际门控、阈值自校准），全部只能以 10.6–37 个百分点的召回损失换取精确率。结论是这个问题不能靠改名规范化解决，只能靠协议：**每条结论必须承诺它自己的比较语料**。我们已把该承诺实现进自己的产物格式。

## Abstract

Tools that flag a package as a "typosquat" of another package are answering a
question about a **set**, not about one package: *is this name close to some other
name in the corpus I loaded?* The corpus is almost never stated. We show that this
omission is not cosmetic — the verdict is a function of the corpus, so two
implementations of the same algorithm can publish different numbers for the same
packages, and both be correct.

We report three results.

1. **A measurement on a real namespace.** Over 620 names beginning `mcp-server-`
   from the public PyPI index, holding the rule fixed and growing only the
   comparison corpus from 60 to 620 names, **13 of 60 sampled packages change
   verdict** (21.7%), and **zero change in the reverse direction** — adding names
   can only add neighbours, so the effect is monotone. The number of close pairs
   grows as `Θ(n²)`, and the fraction of names flagged rises from 11.2% to 33.7%.

2. **A measurement on a third-party labelled benchmark.** On
   `Kemalyavas/agent-skill-typosquat-bench` (1,200 typosquats, 800 legit including
   200 hard negatives), holding the detector and the candidate set fixed and
   growing only the corpus from 200 to 1,617 real registry names, **precision
   falls 0.985 → 0.940 and false positives rise 18 → 74 while recall stays
   exactly 0.964**. Recall is constant by construction, so the published
   precision is a property of "200 protected names", not of the detector.

3. **A statement of what this is an instance of, and why the obvious escapes
   fail.** We give a union-bound argument showing that a fixed threshold cannot
   hold its false-discovery proportion as the corpus grows, that any
   false-discovery budget forces the threshold to shrink, and that precision- and
   recall-stability coexist **iff** a gap exists — some threshold below which
   accidental collisions have probability zero while almost all real attacks
   remain. We then test three candidate normalizations (brand gating, margin
   gating, threshold calibration); each buys precision by spending 10.6–37 points
   of recall. The escape is a protocol decision, not an algorithm: a verdict must
   commit to its comparison corpus. We implement that commitment.

## 1. Introduction

Package registries are large enough that similar-looking names occur by accident.
A registry with `n` names and any fixed edit-distance threshold contains on the
order of `n²·p` accidental near-pairs, where `p` is the probability that two
randomly chosen names are within the threshold. Detectors built on this signal —
SpellBound's lexical similarity plus popularity `[1]`, `andrew/typosquatting`'s
generators `[2]`, the skeleton-and-edit-distance baseline studied here `[3]` — are
widely deployed inside supply-chain scanners for npm, PyPI and, more recently, MCP
servers and agent skills.

The question we ask is not "how accurate is such a detector" but **"what is the
detector's accuracy a property of"**. Our answer, from two independent datasets, is
that it is a property of the comparison corpus: the set of names the detector
happened to load when it ran.

The practical consequence is uncomfortable. A scanner that indexes more of a
registry — an unambiguously better scanner — will report more typosquatting,
without any package changing. Two teams running identical code can publish
different precision and recall on the same packages, and neither number is wrong.

### Contributions

- `§3` A monotone, quantified measurement of verdict flipping on a real namespace,
  with the `Θ(n²)` scaling of accidental pairs.
- `§4` The same effect measured on a third-party labelled benchmark, where
  precision and recall are both observable, so the effect can be attributed to
  false positives specifically.
- `§5` A lemma, corollary and proposition that state exactly which two quantities
  cannot be held simultaneously, and the **gap condition** under which they can.
- `§6` Three candidate escapes, each measured and each shown to be a point on the
  same trade-off curve rather than a way off it.
- `§7` The consequence for artifact design — a corpus commitment — implemented in
  our own attestation format.

## 2. Setting and definitions

Names are strings over an alphabet `Σ`; let `S ⊂ Σ*`. A **comparison corpus** is a
finite set `C ⊂ S` with `|C| = n`. A **distance** `d(x,y)` is any edit distance. A
**threshold rule** is `τ ≥ 0`. A candidate `c` is flagged

```
flag(c, C, τ) = 1  iff  ∃ y ∈ C, y ≠ c : d(c, y) ≤ τ
```

We model clean registry names as drawn from a distribution `π` over `S` and define
the **null collision probability**

```
p(τ) = P_{c,y ~ π, c ≠ y}[ d(c, y) ≤ τ ]
```

Note `p(τ)` depends on the registry's name distribution and on the distance — not
on the detector, and not on `n`.

Two quantities will be distinguished throughout:

- `E[nb@τ] = 2·pairs(τ)/n`, the **expected number of corpus neighbours per name**,
  which is directly estimable from a corpus and is what our experiments report;
- `p(τ)`, the per-pair null probability, which is a property of the population and
  must be estimated separately. The two are related by
  `E[nb@τ] = (n-1)·p(τ)` in expectation, so the estimator `2·pairs(τ)/n` targets
  the former.

## 3. Measurement 1 — a real namespace flips its verdicts

**Data.** 620 names beginning `mcp-server-`, extracted from the public PyPI simple
index on 2026-11-16. Rule: Damerau–Levenshtein over casefolded names with hyphens
removed, similar at distance ≤ 1 below 8 characters and ≤ 2 otherwise — the rule
our own scanner shipped.

**Flip experiment.** 60 targets drawn with `seed=20261116`. Corpus A is the 60
targets themselves; corpus B is all 620.

| outcome | count |
|---|---|
| flagged in both corpora | 8 |
| flagged only with the full corpus | **13** |
| flagged only with the small corpus | **0** |
| flagged in neither | 39 |
| **flip rate over the 60 targets** | **21.7 %** |

The zero in the third row is the load-bearing detail: adding names can only add
neighbours, so the defect is **monotone**. More coverage mechanically means more
accusations.

**Scaling.** Five random samples per corpus size:

| n | flagged fraction (mean ± sd) | close pairs | pairs / n² |
|---|---|---|---|
| 50 | 0.112 ± 0.020 | 4.4 | 0.00176 |
| 100 | 0.176 ± 0.048 | 18.4 | 0.00184 |
| 200 | 0.224 ± 0.033 | 83.8 | 0.00210 |
| 300 | 0.239 ± 0.025 | 150.4 | 0.00167 |
| 400 | 0.291 ± 0.015 | 241.0 | 0.00151 |
| 500 | 0.305 ± 0.009 | 375.2 | 0.00150 |
| 620 | 0.337 ± 0.000 | 573 | 0.00149 |

`pairs/n²` stays in `[0.0015, 0.0021]` across a 12× range of `n`, which is the
signature of `Θ(n²)`.

**Threshold sensitivity** at `n = 620`: distance 1/2/3 flags 64 / 209 / 336 names
(10.3% / 33.7% / 54.2%). Moving the threshold by one character triples the
accusation rate.

## 4. Measurement 2 — the same effect on a labelled benchmark

Measurement 1 cannot distinguish "flagged a real typosquat" from "flagged an
accident", because it has no labels. We therefore repeat it on
`Kemalyavas/agent-skill-typosquat-bench` `[3]`: 2,000 labelled candidates (1,200
typosquats across 10 generation strategies, 800 legit including 200 hard negatives
that sit within edit distance 2 of a protected name), over 200 protected names,
with a shipped skeleton + edit-distance detector.

**Manipulation.** The detector and the candidate set are held fixed. Only the
corpus grows, by appending **real** registry names from the benchmark's own
`legit_names.json` (excluding any name equal to a candidate, so nothing is flagged
as a typosquat of itself). Nothing about the detector changes, so any movement is
attributable to corpus size alone.

| corpus n | precision | recall | F1 | false positives |
|---|---|---|---|---|
| 200 (benchmark default) | 0.985 | 0.964 | 0.974 | 18 |
| 400 | 0.973 | 0.964 | 0.969 | 32 |
| 800 | 0.958 | 0.964 | 0.961 | 51 |
| 1,200 | 0.950 | 0.964 | 0.957 | 61 |
| 1,617 | **0.940** | 0.964 | 0.952 | **74** |

At edit ≤ 1 the same shape, one order of magnitude smaller: precision 1.000 → 0.987,
false positives 0 → 14.

**Recall is constant because it must be.** Every positive's true target remains in
the corpus, so only false positives can move. This is exactly what makes the
experiment clean: it isolates the corpus effect on the *false-positive* side, which
is where the mechanism acts.

**Neighbour density.** `E[nb@d] = 2·pairs(d)/n` for the same corpora:

| n | E[nb@1] | E[nb@2] | E[nb@3] |
|---|---|---|---|
| 200 | 0.020 | 0.050 | 0.240 |
| 400 | 0.020 | 0.095 | 0.375 |
| 800 | 0.007 | 0.105 | 0.657 |
| 1,200 | 0.020 | 0.163 | 0.982 |
| 1,617 | 0.027 | 0.249 | 1.389 |

At fixed `d`, the expected neighbour count grows roughly linearly in `n`.

## 5. Why this is structural

### 5.1 Lemma

For a candidate `c` and a corpus `C` of size `n` drawn independently from `π`,

```
E[ #{ y ∈ C : d(c,y) ≤ τ } ] = (n − 1) · p(τ)
```

*Proof.* Linearity of expectation over the `n − 1` corpus members. ∎

Two consequences. The expected number of accidental edges in a corpus of `n` names
is `Θ(n²)·p(τ)` — the birthday shape measured in §3. And for an all-clean corpus,
`P(flag) ≤ (n−1)p(τ)` by the union bound, with approximate equality under
independence, so `P(flag) → 1` as `n → ∞` for any fixed `τ` with `p(τ) > 0`.

### 5.2 Corollary

If the candidates are clean, the false discovery proportion is 1 whenever anything
is flagged. For a mixture, the expected FDP is bounded below by the clean flag
count over total flags, hence

```
FDP(n) → 1 as n → ∞   unless   n · p(τ) → 0
```

Since `p(τ)` does not depend on `n`, the only way to keep `n·p(τ)` bounded is to let
`τ` shrink as the corpus grows.

### 5.3 Proposition

Let `τ(n)` be any corpus-size-dependent threshold, `α ∈ (0,1)` a false-discovery
budget, and `A` the distance distribution between a real typosquat and its genuine
target.

**(i)** If `FDP(n) ≤ α` for all `n`, then `n·p(τ(n)) ≤ α`, hence `p(τ(n)) → 0`, hence
the distances `τ(n)` admits must eventually carry no null mass.

**(ii)** Recall at that operating point is bounded by `P_A[d ≤ τ(n)]`, which is
non-increasing in `n` once `τ` begins to shrink.

**(iii) Gap condition.** Precision-stability and recall-stability hold
simultaneously iff there is a threshold `τ*` with

```
p(τ*) = 0                     no accidental collision at or below τ*
P_A[d ≤ τ*] ≥ 1 − ε           almost every real attack at or below τ*
```

that is, real attacks are **strictly closer than any accidental collision, at every
registry scale**.

*Proof.* If such `τ*` exists, a constant threshold `τ*` gives precision 1 and recall
`≥ 1 − ε` for all `n`. Conversely, if no such `τ*` exists, every `τ` with
`P_A[d ≤ τ] ≥ 1 − ε` has `p(τ) > 0`, so by (i) either the budget is violated at some
`n`, or `τ` must shrink below the mass of `A`. ∎

### 5.4 What the proposition says about edit-distance comparison

For edit distance over a real registry, `p(τ) > 0` for every usable `τ ≥ 1`: there
are always some unrelated names within a small edit distance, and their number grows
with the catalogue. The gap condition therefore fails, and the trade-off is **forced
rather than an implementation flaw**.

The measurements of §3 and §4 are precisely the two horns: hold `τ` and false
positives grow; hold the false-positive budget and recall falls.

## 6. Three attempted escapes

If the gap fails, perhaps a better name normalization creates one. We tested three
on the same benchmark, same candidates, corpus grown 200 → 1,617.

| strategy | precision | recall | false positives |
|---|---|---|---|
| shipped rule (edit ≤ 2) | 0.985 → 0.940 | **0.964 → 0.964** | 18 → 74 |
| brand gate (compare only names sharing a non-generic token) | 0.994 → 0.977 | 0.667 → 0.667 | 5 → 19 |
| margin gate (best match strictly closer than the next) | 0.980 → 0.937 | 0.599 → 0.596 | 15 → 48 |
| threshold calibration (`E[nb@2] ≤ 0.05`) | 0.985 → 0.987 | 0.964 → 0.858 | 18 → 14 |

Read as points on one curve rather than as competing designs.

- The **brand gate** refuses to compare names that share only generic tokens
  (`mcp`, `server`, `skill`, …). It removes most attacks that rename or extend the
  brand — combosquat and affix strategies — so recall is 0.667 before the corpus
  even grows.
- The **margin gate** requires a distinctive winner. Attacks whose target is one of
  several equally close names — which is what a real registry looks like — are lost.
  Recall 0.599 at every size.
- **Threshold calibration** keeps the shipped rule and shrinks the radius. The
  smallest loss of the three, 10.6 points, but still a loss.

None achieves the gap condition: each is precise *and* blind. Every strategy buys
stability by making the detector stop looking, not by separating attacks from
accidents. That is what §5.3 predicts once `p(τ) > 0` for every usable `τ`: no
re-weighting of the same distance signal can make accidents disappear.

## 7. Consequence for artifact design

The escape is not a normalization but a **protocol decision**: a verdict must commit
to the comparison corpus, so that the number is reproducible by construction and its
coverage limits are explicit.

We implement this in `canari/typosquat.py`. Every similarity verdict carries

```json
"comparison_corpus": {
  "registry": "pypi",
  "kind": "name-set",
  "size": 620,
  "digest": "sha256:…",
  "canonicalization": "sha256(utf-8, casefolded names sorted asc, LF-joined, trailing LF)",
  "as_of": "2026-11-16T05:31:35Z"
}
```

plus a one-line `corpus:<registry>:sha256:…:n=<size>` entry in the attestation's
`evidence_refs`. The canonicalization is stated inside the record rather than
documented beside it, so a reader can re-derive the digest without trusting prose.
Two attestations that disagree on a typosquat verdict can then be distinguished by
whether they compared against the same corpus, instead of looking like a
contradiction.

Three practical rules follow.

1. A reported precision/recall pair for a name-similarity detector must name the
   corpus size it was measured at. Otherwise it is not reproducible.
2. If a detector's corpus is a *sample* of the registry, its false-positive count is
   a function of the sample size, not of the packages.
3. Where the gap condition fails — the normal case — the design must choose
   explicitly: fixed threshold and growing false positives, or calibrated threshold
   and falling recall. There is no third option at a fixed corpus model.

## 8. Threats to validity

- **One namespace, one benchmark.** §3 uses a single prefix family; §4 uses a single
  labelled dataset and a single detector family (skeleton + bounded edit distance).
  The mechanism in §5 does not depend on either, but the exact numbers do.
- **Recall is only observable because of a design choice.** The benchmark keeps each
  positive's true target in the corpus. A benchmark that sampled both sides would
  conflate "target absent" with "detector missed", which is a different effect.
- **`p(τ)` is estimated, not known.** Our experiments report `E[nb@d]`, the expected
  neighbour count, which is the quantity bounded by the lemma. It is a plug-in
  estimator and is not an estimate of `p(τ)` itself.
- **The proposition is a union-bound argument.** It is tight enough to be actionable
  — it says the threshold must shrink, and why — but not tight enough to give an
  exact rate.
- **No claim of deep novelty.** Record linkage has long known that the number of
  possible links grows quickly with database size `[4]`, and blocking methods are
  evaluated on exactly that trade-off `[5]`. What this note adds is which two
  quantities cannot be held simultaneously for *this* task, and the gap condition
  under which they can.

## 9. Related work

Lexical typosquat detection over package registries is established: SpellBound
combines lexical similarity with popularity weighting and reports a 0.5% false
positive rate `[1]`; a public curated corpus of 167 real typosquat pairs with
transformation labels exists `[6]`; a public labelled benchmark for MCP and
agent-skill names, with hard negatives and a transparent baseline, is what §4 uses
`[3]`. On the statistical side, blocking and record linkage have long studied the
cost of comparing more pairs `[4][5]`, and multiple-testing control has been applied
to record linkage accuracy `[7]`. We did not find prior work that states the
corpus-size dependence of a *package-name* verdict as a reproducibility property, or
that measures it against a labelled benchmark.

## 10. Reproduction

All artifacts are in `experiments/` of https://github.com/lanbass869-cell/canari.

| artifact | what it reproduces |
|---|---|
| `corpus_dependence/run.py` | §3, deterministic (`seed=20261116`), reads a committed 620-name list |
| `corpus_benchmark/run_threshold_sweep.py` | §4 main table |
| `corpus_benchmark/run_calibration_sweep.py` | §4 neighbour density + §6 calibration row |
| `corpus_benchmark/run_brand_gate.py` | §6 brand gate row |
| `corpus_benchmark/run_margin_gate.py` | §6 margin gate row |

The benchmark dataset is not vendored — it is CC BY 4.0 and must be fetched from
its own repository; the scripts read a local clone via `CANARI_TYPO_BENCH`.

## References

1. Taylor et al. *SpellBound: Defending Against Package Typosquatting.*
   arXiv:2003.03471, 2020.
2. `andrew/typosquatting` — typosquat generators by transformation category.
3. `Kemalyavas/agent-skill-typosquat-bench` — labelled MCP/agent-skill name-confusion
   benchmark and baseline detector, 2026.
4. *Probabilistic Record Linkage and Deduplication after Indexing, Blocking, and
   Filtering.* arXiv:1603.07816, 2016.
5. *A Comparison of Blocking Methods for Record Linkage.* arXiv:1407.3191, 2014.
6. `ecosyste-ms/typosquatting-dataset` — curated typosquat name pairs with
   classification and source attribution, CC0.
7. *Assessing the accuracy of individual link with varying block sizes and cut-off
   values using MaCSim.* arXiv:2003.05686, 2020.
