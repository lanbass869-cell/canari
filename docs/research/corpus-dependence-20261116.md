# Corpus size decides a typosquat detector's precision

Third-party benchmark: [`Kemalyavas/agent-skill-typosquat-bench`](https://github.com/Kemalyavas/agent-skill-typosquat-bench)
(CC BY 4.0 dataset, MIT code) — 2,000 labelled candidates (1,200 typosquats /
800 legit, 200 of them hard negatives) over 200 protected MCP/npm names.

**Manipulation.** The detector and the candidate set are fixed. Only the
*comparison corpus* grows: real registry names (distractors, also from the
benchmark's own `legit_names.json`) are appended to the 200 protected names.
Nothing about the detector changes, so any movement in precision is attributable
to corpus size alone.

## Result — fixed threshold: precision decays, recall does not move

Edit distance ≤ 2, exactly the benchmark's own loosest operating point:

| corpus n | precision (mean) | recall | F1 | false positives (mean) | trials |
|---|---|---|---|---|---|
| **200** | **0.985** | 0.964 | 0.974 | **18** | 3 |
| 400 | 0.973 | 0.964 | 0.969 | 32 | 3 |
| 800 | 0.958 | 0.964 | 0.961 | 51 | 3 |
| 1200 | 0.950 | 0.964 | 0.957 | 61 | 3 |
| **1617** | **0.940** | 0.964 | 0.952 | **74** | 1 |

> All figures are means over the trials listed; `results_threshold_sweep.json`
> is the machine output this table is generated from. (Earlier revisions of this
> file quoted a per-trial minimum for precision alongside a different
> false-positive figure at n=400/800/1200; the table above is now consistent with
> the JSON.)

Edit distance ≤ 1 behaves the same way, one order of magnitude smaller:
precision 1.000 → 0.987, false positives 0 → 14.

Recall is constant *by construction*: every positive's true target is still in
the corpus. So the benchmark's headline precision is a property of "200 protected
names", not of the detector.

## Result — the threshold has to shrink, and recall pays for it

Expected number of corpus neighbours per name, `E[nb@d] = 2·pairs(d)/n`, grows
roughly linearly with n at fixed d:

| n | E[nb@1] | E[nb@2] | E[nb@3] |
|---|---|---|---|
| 200 | 0.020 | 0.050 | 0.240 |
| 400 | 0.020 | 0.095 | 0.375 |
| 800 | 0.007 | 0.105 | 0.657 |
| 1200 | 0.020 | 0.163 | 0.982 |
| 1617 | 0.027 | 0.249 | 1.389 |

So a **self-calibrated** rule — take the largest d with `E[nb@d] ≤ 0.05` — drops
from d=2 to d=1 once the corpus passes ~400 names:

| n | d_eff | precision | recall | FP |
|---|---|---|---|---|
| 200 | 2 | 0.985 | 0.964 | 18 |
| 400 | 1 | 0.999 | **0.858** | 1 |
| 800 | 1 | 0.991 | **0.858** | 9 |
| 1200 | 1 | 0.989 | **0.858** | 11 |
| 1617 | 1 | 0.987 | **0.858** | 14 |

Calibration buys the precision back and charges it to recall: **~10.6 points of
recall** to keep the false-positive count roughly flat.

## The point

For this family of detectors there is no threshold setting that keeps both
precision and recall stable as the corpus grows:

- hold the threshold → false positives grow with the corpus
- hold the false-positive budget → recall falls with the corpus

A reported number like "precision 1.000, recall 0.858" is therefore incomplete
without the corpus it was measured on. Two teams can run identical code on
identical packages and publish different precision, both correctly.

## Reproduce

```
git clone https://github.com/Kemalyavas/agent-skill-typosquat-bench  <path>
set CANARI_TYPO_BENCH=<path>
python run_threshold_sweep.py     # writes results_threshold_sweep.json
python run_calibration_sweep.py   # writes results_calibration.json
```

Distractors whose name equals a candidate are excluded, so no candidate is
"flagged as a typosquat of itself". Randomness is seeded (20261116 + n), and the
n = 1617 point uses the full distractor pool.

## Limitations

- One benchmark, one detector family (skeleton + bounded edit distance). The
  mechanism is general, the exact numbers are not.
- Recall is only measurable because this benchmark keeps each positive's true
  target in the corpus; a benchmark that sampled both sides would conflate the
  two effects.
- The calibration rule (`E[nb@d] ≤ 0.05`) is one choice among many; it is shown
  to make the trade-off visible, not claimed to be optimal.
