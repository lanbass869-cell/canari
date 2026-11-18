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

> **Correction, same day.** The first version of this section said "at most r
> citations", which makes the bound FALSE: a component citing fewer roots breaks
> the average. The correct hypothesis is **exactly r**, and it also forces a
> second correction - a component citing more than r roots is *immune* to a single
> corrupted root, which is the useful part. Both fixed below.

**Statement.** Suppose a policy admits `m` components, and every admitted
component cites **exactly** `r` distinct roots from a universe of `k`. Then some
root is cited by at least `ceil(r*m/k)` of them, and corrupting that one root
invalidates all of those (each drops to `r-1` witnesses).

**Proof.** Total citations are exactly `r*m`, spread over `k` roots. By
pigeonhole, some root carries at least `ceil(r*m/k)` citations. A component citing
exactly `r` roots falls below the threshold when one of them is corrupted, so every
such component is invalidated. QED.

**Corollary 1.** No policy - whatever its memory or online strategy - can hold
single-root damage below an `r/k` fraction of admissions, *within the population of
components that cite exactly `r` roots*.

**Corollary 2 (the useful one).** A component citing `r+s` roots survives `s`
simultaneous corruptions. So the defence against a `c`-root adversary is **surplus**
`c` witnesses per component, not a higher threshold and not a per-root quota: surplus
costs evidence, and it costs no admissions.

### What this does and does not settle

**Settles:** "just require more witnesses" is wrong in the direction people assume.
Raising `r` raises the damage floor `r/k` for components that sit exactly at the
threshold; what protects them is being *above* it.

**Explains the measurement:** in `adaptive.py` every admitted component cited
exactly `r=2` roots, so the floor applied and the skew pushed the observed damage
(44.9%) far above the uniform-case 1%.

**Does not settle:** the worst case under skew, and the cost of surplus when
evidence is scarce (each extra witness is a request that may not exist). Those are
the open questions.

**Deliberately not claimed:** this is pigeonhole. It is written down because it
rules out a family of proposed defences, not because it is deep.

## The operational payoff: surplus beats quotas (2026-11-18)

`experiments/online_admission/surplus.py`, same skewed stream (zipf 1.2, 200 roots,
4,000 components, threshold `r=2`). Each component cites `r+s` roots; then the
adversary corrupts the single most-cited root.

| witnesses per component | admitted | invalidated by one corrupted root | damage | extra requests |
|---|---|---|---|---|
| 2 (s=0) | 3,999 | 1,835 | **45.9%** | 0 |
| 3 (**s=1**) | 4,000 | **1** | **0.03%** | 4,000 |
| 4 (s=2) | 4,000 | 0 | 0.00% | 8,000 |

Compare with the quota policy from the previous section, which needed a cap of
`q=0.10` - giving up **59.9% of admissions** - to reach 10% damage:

| defence | damage | admission cost | evidence cost |
|---|---|---|---|
| per-root quota q=0.10 | 10% | **-59.9%** | 0 |
| **surplus s=1** | **0.03%** | **0** | +1 request per component |

**Surplus dominates the quota**: an order of magnitude more protection, no lost
admissions, and the price is paid in evidence rather than in access.

### The honest caveat, and where the real cost hides

In this stream the universe is dense (200 roots), so failing to find a third
distinct root happened for 1 component in 4,000. That is *not* the real world. Our
own measurement says npm MCP packages publish a repository 94.0% of the time and
PyPI 40.0% - so for a large share of real components **the third witness may not
exist**. The open question is therefore not "is surplus better" (it is) but:

> Given a component's actual evidence supply, what surplus is attainable, and how
> should a fixed evidence budget be allocated across components to minimise total
> expected damage?

That is a concrete, measurable optimisation problem with a published cost model,
and it is the natural next step for this line.
