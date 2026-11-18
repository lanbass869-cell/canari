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
