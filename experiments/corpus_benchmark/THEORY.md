# Why a name-similarity threshold cannot be both stable and accurate

A short formal note on what the two tables in `README.md` are instances of.

## 1. Setup

Let names be strings over an alphabet, `S ⊂ Σ*`, and let `d(x, y)` be any edit
distance. A **corpus** is a finite set `C ⊂ S` of size `n`. A **threshold rule**
is a function `τ ≥ 0`. A candidate `c` is flagged by

```
flag(c, C, τ) = 1  ⟺  ∃ y ∈ C, y ≠ c : d(c, y) ≤ τ
```

Names in a registry are not adversarial by default, so model a "clean" name as
drawn from a distribution `π` over `S`. Define the **null collision
probability**

```
p(τ) = P_{c,y ~ π, c ≠ y} [ d(c, y) ≤ τ ]
```

`p(τ)` is a property of the registry's name distribution and the distance, not of
any detector.

## 2. Lemma — accidental collisions grow with the corpus

For a candidate `c` and corpus `C` of size `n` drawn from `π` independently of `c`,

```
E[ #{ y ∈ C : d(c,y) ≤ τ } ]  =  (n − 1) · p(τ)
```

*Proof.* Linearity of expectation over the `n − 1` corpus members. ∎

Two immediate consequences:

- the expected number of **accidental edges** in a corpus of `n` names is
  `Θ(n²) · p(τ)` — the birthday-problem shape, which is what the
  `pairs / n²` column in `experiments/corpus_dependence` measures;
- for an all-clean corpus, `P(flag) ≤ (n−1)p(τ)` by the union bound, and under
  approximate independence `P(flag) ≈ 1 − (1 − p(τ))^{n−1}`, which tends to 1 as
  `n → ∞` for any fixed `τ` with `p(τ) > 0`.

## 3. Corollary — a fixed threshold cannot hold its false discovery proportion

If all candidates are clean, the **false discovery proportion** is 1 whenever
anything is flagged. For a mixture of clean and attacked names, the expected FDP
is bounded below by the clean flag count divided by total flags, so

```
FDP(n) → 1   as n → ∞   unless  n · p(τ) → 0
```

Since `p(τ)` does not depend on `n`, the only way to keep `n · p(τ)` bounded is to
let `τ` itself shrink as `n` grows.

## 4. Proposition — the trade-off, and the exact condition for escaping it

Let `τ(n)` be any corpus-size-dependent threshold, let `α ∈ (0,1)` be a
false-discovery budget, and let `A` be the distribution of distances between a
real typosquat and its genuine target. Then:

**(i)** If `FDP(n) ≤ α` for all `n`, then `n · p(τ(n)) ≤ α`, hence
`p(τ(n)) → 0`, hence the set of distances `τ(n)` permits must eventually carry no
null mass.

**(ii)** Recall at that operating point is bounded by `P_A[d ≤ τ(n)]`, which is
non-increasing in `n` once `τ` starts shrinking.

**(iii) Gap condition.** Precision-stability *and* recall-stability can hold
simultaneously if and only if there is a threshold `τ*` with

```
p(τ*) = 0        (no accidental collision at or below τ*)
P_A[d ≤ τ*] ≥ 1 − ε   (almost every real attack is at or below τ*)
```

i.e. real attacks are *strictly closer* than any accidental collision, at every
registry scale.

*Proof.* (i) and (ii) follow from Lemma 1 and the definition of FDP. For (iii):
if such `τ*` exists, use a constant threshold `τ*` — no accidental flags at any
`n`, so precision is 1 and recall is `≥ 1 − ε` regardless of `n`. Conversely, if
no such `τ*` exists, then every `τ` with `P_A[d ≤ τ] ≥ 1 − ε` has `p(τ) > 0`, so
by (i) either the budget `α` is violated at some `n` or `τ` must shrink below the
mass of `A`. ∎

## 5. What this explains

For edit-distance name comparison over a real registry, `p(τ) > 0` for every
`τ ≥ 1`: there are always *some* unrelated names within a small edit distance,
and the count grows with the catalogue. So the gap condition of (iii) fails, and
the trade-off is forced, not an implementation flaw.

The measurements in `README.md` are exactly (i) and (ii):

- holding `τ = 2`: precision 0.985 → 0.940 and false positives 18 → 74 across
  `n = 200 → 1,617`, with recall unchanged (0.964) because every positive's true
  target stays in the corpus;
- shrinking `τ` to keep the false-positive budget: precision recovers to
  ≈ 0.99, recall falls 0.964 → 0.858.

The 10.6-point recall loss is in the same range as the mass of positives whose
closest protected name sits at distance exactly 2 (14.3 % of the benchmark's
1,200 positives); the two are not identical because the detector also has
skeleton-exact and affix paths that catch some of those cases without distance.

## 6. What this does *not* say

- It does not say threshold detectors are useless. It says their reported
  precision is only meaningful together with the corpus it was measured on.
- `p(τ)` is registry-specific and must be estimated, not assumed. The
  `E[nb@d] = 2·pairs(d)/n` statistic used in `README.md` is a plug-in estimator
  for the **expected neighbour count**, which is the quantity Lemma 1 bounds —
  not an estimate of `p(τ)` itself.
- The proposition is a union-bound argument. It is tight enough to be actionable
  (it tells you the threshold must shrink, and why), not tight enough to give an
  exact rate.
- No claim of deep novelty: practitioners of record linkage have long known that
  "the number of possible links grows rapidly in the size of the databases"
  (arXiv:1603.07816). What this note adds is the statement of *which* two
  quantities cannot be held simultaneously for this task, and the gap condition
  under which they can.

## 7. Practical rules that follow

1. A reported precision/recall pair for a name-similarity detector must name the
   corpus size it was measured at — otherwise it is not reproducible.
2. If a detector's corpus is a *sample* of the registry, its false-positive count
   is a function of the sample size, not of the packages.
3. Two detectors with the same code can publish different precision, both
   correctly. Comparing them requires the same corpus.
4. Where the gap condition fails (which is the normal case), choose explicitly:
   fixed threshold and accept growing false positives, or a calibrated threshold
   and accept falling recall. There is no third option at fixed corpus model.
