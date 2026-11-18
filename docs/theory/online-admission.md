# Online admission under a corruption budget

Status: problem statement + a measured cost structure. **No theorem yet.** This
file exists so that the gap is written down precisely enough to attack, instead of
being described in conversation.

## The model

A stream `σ = (a_1, ρ_1), (a_2, ρ_2), ...` arrives one pair at a time, where `a_i`
is a component and `ρ_i ∈ {1..k}` is the *root* (independent authority) that
vouches for it.

- Up to `c` of the `k` roots are corrupted: they vouch for anything, any number of
  times, for any component.
- A component is **admissible** iff it has evidence from at least `r`
  *independent* (uncorrupted) roots.
- The algorithm must decide, online, per component: it sees the stream once, has
  memory `M ≪ T`, and cannot retract an admission.
- Goal: competitive ratio against the offline optimum that knows which roots are
  corrupted, or equivalently the regret from false admissions.

## What the measurement shows (2026-11-18)

`experiments/online_admission/sim.py`, 4,000 components, one corrupted root, 25% of
components attacked. An attacker **substitutes** for a missing witness: one honest
root plus the corrupted root pretending to be a second authority. Benign components
have 2 (60%) or 3 (40%) honest witnesses.

| threshold | false admits (of 1,039 attacked) | false rejects (of 2,961 benign) |
|---|---|---|
| 2 | **1,039 (100%)** | 1 (0.03%) |
| 3 | 0 | **1,760 (59.4%)** |
| 4 | 0 | 2,961 (100%) |

Reading of the table: **a corrupted root is still a distinct root.** A distinct-root
counter cannot tell it apart from an honest one, so at threshold `r` every
substitution attack is admitted. Raising the threshold to `r + c` blocks all of
them - and also rejects every benign component that only has `r` witnesses.

The correct threshold is `r + c`. `c` is not published, changes over time, and is
exactly what a corruption-budget estimator would have to produce. That is the open
interface.

## What is and is not established

**Established (measured, reproducible):** the trade-off above, on an explicit
stream, with the generator committed. Any claim about "distinct witnesses" that
ignores the corruption budget is refuted by the threshold-2 row.

**Not established:** a lower bound. Nothing here shows that no algorithm with
memory `M` achieves a better ratio than a fixed threshold - that is the theorem
that would make this a paper rather than an observation. The obstruction to proving
it is that the attacker in this simulation is non-adaptive; an adaptive attacker who
chooses *which* root to corrupt after seeing the algorithm's behaviour may force a
strictly worse ratio, and that reduction is not done.

**Known prior art to respect:** arXiv:2610.10597 (anytime-valid corruption budgets,
leaderboard claims, no memory bound), arXiv:2610.01007 (streaming set cover
space-approximation, no evidence structure), arXiv:2608.15810 (anytime-valid
admission for compressed serving state, single-model). See
`E:\RUANJIAN\workdocs\canari\research2\A-algorithm-gaps.md`.

## The next honest step

Prove or refute: *for adaptive adversaries, any algorithm with `o(k)` memory has
competitive ratio `Ω(k)` against the offline optimum.* A refutation would be a
sketch-based algorithm with a better bound; either outcome is publishable, and both
require the adaptive adversary that the current simulation does not model.

## What adaptivity actually costs (2026-11-18)

`experiments/online_admission/adaptive.py`. Admissions are irreversible, so the
adversary does not have to forge anything: it can corrupt a root *after* the
algorithm has relied on it. Measured damage is therefore **retroactive
invalidation**, not just false admission.

4,000 components, 200 roots, r = 2. Two rules, same streams:

- **A** - at least 2 distinct roots (the per-item rule)
- **B** - at least 2 distinct roots **and** at least 2 distinct root *families*
  (the four ecosystems Canari actually reads)

| root usage | rule | admitted | invalidated when the single most-used root is corrupted |
|---|---|---|---|
| uniform | A | 4,000 | 59 (1.47%) |
| uniform | B | 3,018 | 46 (1.52%) |
| **skewed (zipf 1.2)** | **A** | 4,000 | **1,796 (44.9%)** |
| **skewed (zipf 1.2)** | **B** | 1,042 | **306 (29.4%)** |

Two things follow.

1. **The vulnerability is a property of the usage distribution, not of the rule.**
   Under uniform usage both rules lose ~1.5%; under skew one corrupted root takes
   out 45% of everything admitted. Popular roots are single points of failure and
   no per-item check can see that.
2. **Per-item distinctness is local; the damage function is global.** Adding the
   family constraint cuts absolute damage from 1,796 to 306 (83% less) - and also
   cuts admissions from 4,000 to 1,042. That trade is the whole argument for an
   explicit *corruption-distinct class* accounting, which is the gap the A-line
   survey identified.

Honest boundary: this is still a measurement, not a bound. It shows that any
analysis restricted to per-item witness counts cannot capture the failure mode; it
does not yet say what the optimal global policy costs.

## What protection costs (2026-11-18)

`experiments/online_admission/diversity_policy.py`. The obvious defence against
the previous section is a per-root dependence cap: after admitting an item, no
single root may account for more than `q` of the admitted set.

| cap q | admitted | damage if the top root is corrupted | admissions given up |
|---|---|---|---|
| none | 4,000 | 44.9% | - |
| 0.30 | 3,138 | 30.0% | 21.6% |
| 0.20 | 2,471 | 20.0% | 38.2% |
| 0.10 | 1,605 | 10.0% | **59.9%** |
| 0.05 | 735 | 4.9% | 81.6% |

The damage column tracks the cap by construction - that is not a discovery. The
number that matters is the last column: **cutting single-root damage from 45% to
10% costs 60% of admissions.** The cost grows faster than the protection.

This is why "just require diverse witnesses" is not an answer: at the diversity
levels that actually bound damage, a fixed quota throws away most of the useful
admissions. Allocating a *shared* budget across components - rather than a
per-root quota - is the open problem, and it is the same corruption-budget
estimation problem the first section identified, now with a measured price tag.

## Proposition 1 (elementary, but it settles an argument)

**Statement.** Let a policy admit `m >= 1` components, each citing at most `r`
distinct roots out of a universe of `k`. Admissions are irreversible. Then there
is a root whose corruption retroactively invalidates at least `ceil(r*m/k)` of the
`m` admissions.

**Proof.** Each admitted component contributes at most `r` root citations, so the
total number of citations is at most `r*m`. These are spread over `k` roots.
By the pigeonhole principle (equivalently, averaging: the mean is at most
`r*m/k`), some root is cited by at least `ceil(r*m/k)` of the admitted components.
Corrupting that one root invalidates exactly those. QED.

**Corollary.** No policy - whatever its memory, whatever its online strategy - can
hold single-root damage below a `r/k` fraction of admissions while admitting a
constant fraction of the stream. The bound is a property of `r` and `k`, not of the
algorithm.

### What this does and does not settle

**Settles:** the "just require more witnesses per component" instinct cannot work
by itself. Raising `r` *raises* the guaranteed damage floor (`r/k`), because the
same roots are cited more often. The only lever that lowers the floor is increasing
`k` - more *independent sources in the population* - which is exactly the
corruption-distinct class accounting the survey identified as missing.

**Does not settle:** the observed 44.9% in the adaptive experiment is far above
this floor (with `r=2, k=200` the floor is 1%). The gap comes from *skew*: the
adversary corrupts the most-cited root, not the average one. Proposition 1 bounds
the average case; the worst case under skew is what a real bound would need to
characterise, and that is not done.

**Deliberately not claimed:** this is pigeonhole. It is written down because it
rules out a whole family of proposed defences, not because it is deep.
