# Literature ledger - is the online-admission gap real?

Goal: decide, on evidence, whether "online admission with a corruption budget,
bounded memory, irreversible decisions" is a real gap or a known problem in
disguise. Method: read full text (arXiv HTML, not abstract), record what each
paper *solves* and where its model differs from ours.

Status: 14 abstracts + **10 full texts read** (2026-11-18). Target is 20 full texts
across four adjacent fields; this file grows until that is done.

## Read in full (text extracted from arXiv HTML, key sections read)

### 1. arXiv:2610.01007 - Settling the Pass Complexity of Streaming Set Cover
**Field:** streaming algorithms / space lower bounds.
**Solves:** the optimal three-way tradeoff between space, passes and approximation
for streaming set cover, with a communication-complexity lower bound: beating a
`(log n)/2` approximation requires `Omega(m)` bits, which gives `Omega(m/p)` space
for `p` passes.

**Model vs ours:** sets arriving in a stream, goal is a minimum cover at the end,
unlimited memory of the *final* answer. Ours is: witnesses arriving, per-component
irreversible decision at arrival time, adversary corrupts roots, memory bound.

**Occupies our slot?** No - different decision object. **But** it settles that the
"online set cover" framing is taken, and it supplies the lower-bound technique
(pointer chasing -> communication complexity) that a bound for our problem would
have to use.

### 2. arXiv:2610.10597 - Certified Corruption Budgets: Anytime-Valid Leaderboard Claims
**Field:** robust statistics / sequential testing under adaptive corruption.
**Solves:** an anytime-valid corruption tolerance `B_t` published with every
pairwise claim, with **matching upper and lower bounds**: faking a margin `delta`
requires forging a `2*delta` fraction of records (or flipping `delta`), and the
tolerance nearly reaches that fraction. Attacker may insert forged records, flip
records, and sees every published certificate.

**Model vs ours:** their decision object is a **ranking claim**; ours is an
**irreversible admission**. Their adversary model (adaptive, sees published
state) is the same one that produced our 44.9% measurement.

**Occupies our slot?** **Partially.** It owns "adaptive attacker vs published
certificates". It does not own "admission with irreversible decisions and a memory
bound". Any write-up must distinguish from it explicitly.

### 3. arXiv:2609.34376 - Before Agents Act: Assurance-Aware Semantic Scheduling
**Field:** evidence acquisition / operational research.
**Solves:** joint **witness selection and scheduling** under quorum, diversity,
freshness, deadline and resource constraints; integer-program formulation; proves
the Assurance Scheduling Problem (ASP-DEC) **NP-hard**; gives cuts with finite
termination and conditional global optimality; ships a catalogue of assurance
operations and an explicit **Open Problems** appendix.

**Model vs ours:** offline/plan-time selection with a cost objective, not an
online stream with bounded memory and irreversible commits.

**Occupies our slot?** **Largely.** This is the paper I was about to propose as
"the open problem" (evidence budget allocation across components). It is not open:
it is formulated, proved NP-hard, and solved by IP with optimality conditions.
Anyone claiming that gap is wrong.

## Read as abstracts only (not yet full text)

| id | title | why it matters |
|---|---|---|
| 2609.34245 | Certified Multi-Source Integrity for Structured Agent Actions | the single-shot offline certifier this line would extend |
| 2608.15810 | Anytime-Valid Admission for Compressed Serving State | closest use of "admission" + anytime-valid, different object (model serving) |
| 2606.11632 | Sovereign Assurance Boundary: Certificate-Bound Admission | certificate-bound runtime admission for agentic infra |

## Interim verdict (2026-11-18, after 3 full texts)

Two of the three candidate "gaps" I proposed in earlier turns are already occupied:

| candidate gap | status |
|---|---|
| evidence budget allocation across components | **occupied** by 2609.34376 (NP-hard + IP + optimality) |
| adaptive adversary vs published certificates | **occupied** by 2610.10597 (matching upper/lower bounds) |
| online + irreversible + bounded memory + competitive ratio | **not yet found** - must survive the remaining 17 reads |

The third is narrow. Its only remaining claim would be: *irreversibility plus a
memory bound changes the problem the first two papers solve*. That has not been
established, and the burden of proof is now on that claim.

## Next reads (planned, not yet done)

1. Byzantine quorum systems (Malkhi & Reiter) + *maximum availability* (IPL 2002) -
   to pin down exactly what masking quorums do and do not give.
2. Streaming lower bounds: Assadi's semi-streaming set cover (1404.6763) and the
   multi-pass tradeoff (1703.01847) - to see whether "irreversible decision"
   admits the same reduction.
3. Online budgeted allocation / online packing survey - to check the
   "budget across items" structure.
4. Resilient covering / interdiction / critical-node - to check the
   "corrupt c sources" structure.
5. Each field's newest survey, for its stated open problems.

### 4. arXiv:2610.41136 - The Competitive Ratio of Online Budgeted Allocation is Strictly Smaller than 1-1/e
**Field:** online algorithms.
**Solves:** refutes the decade-old conjecture that the randomized competitive ratio
of online budgeted allocation is `1-1/e`, proving an upper bound of
`1-1/e-epsilon` (epsilon ~ 1e-4). Context in the paper: deterministic bound `1/2`,
best known randomized `0.5016` (HZZ24).

**Model vs ours:** items arrive online, each consumes budget from a set of
budget-constrained agents; goal is revenue vs offline optimum. No corruption, no
irreversibility, no memory bound.

**Occupies our slot?** **It occupies the "budget across arriving items + competitive
ratio" framing completely, and it is being actively tightened in 2026.** Any claim
of the form "allocate a budget across a stream with a competitive ratio" has to
position against this line, and the bounds there are already near-tight.

### 5. arXiv:cs/9908011 - The Load and Availability of Byzantine Quorum Systems
**Field:** distributed systems / quorum theory (1999).
**Solves:** defines **load** as the access probability of the busiest server, and
proves **lower bounds on the load and on availability of b-masking quorum systems**,
plus constructions achieving optimal load; introduces composition and boosting
techniques.

**Model vs ours:** static quorum system over n servers with crash/Byzantine
probabilities; load is measured over access patterns.

**Occupies our slot?** **It covers the skew observation.** Our "one corrupted root
takes out 44.9% of admissions" is, in their language, a load of 0.449 concentrated
on one root, and **lower bounds on masking-quorum load already exist**. The
insight that "popular roots are single points of failure" is quorum load theory.

## Sharpened interim verdict (2026-11-18, after 5 full texts)

| candidate gap I proposed | status |
|---|---|
| evidence budget allocation across components | **occupied** - 2609.34376 (NP-hard, IP, optimality) |
| adaptive adversary vs published certificates | **occupied** - 2610.10597 (matching up/low bounds) |
| skew makes one root a single point of failure | **occupied** - cs/9908011 (load of masking quorums, with lower bounds) |
| budget across a stream with a competitive ratio | **occupied and actively tightened** - 2610.41136 (2026-10-30) |
| online + irreversible + bounded memory, as its own problem | **not found yet**, but every ingredient is now occupied |

The last row is the only thing left, and after five reads it looks more like a
*composition* of known results than a new problem. The honest default is now:

> **Assume there is no gap until the remaining 15 reads produce one.**

### 6. arXiv:1703.01847 - Tight Space-Approximation Tradeoff for Streaming Set Cover
**Solves:** resolves the tradeoff: any `alpha`-approximation needs
`Omega~(m n^{1/alpha})` space, **even with polylog passes and even on random
arrival order**; maximum coverage needs `Omega~(m/eps^2)`.
**Occupies:** the whole "streaming + space bound + approximation" space for
covering problems. Random arrival does not buy anything - relevant because it
rules out "our stream is not adversarial" as an escape.

### 7. arXiv:1404.6763 - Semi-Streaming Set Cover
**Solves:** `O(sqrt(n))`-approximation in semi-streaming, plus a negative result
for `(1-eps)`-cover certificates: cannot guarantee `E[|Im(chi)|] = o(OPT/eps)`.
**Occupies:** the positive side of the same tradeoff.

### 8. arXiv:2610.07759 - Stateless Recovery and Byzantine Quorum Safety
**Solves:** exact accounting of the slack between the classical intersection bound
`2q-n` and actual Byzantine/recovering identities; tightness construction.
**Occupies:** the fine structure of quorum safety accounting - the same slack
identity our "surplus" argument rests on.

### 9. arXiv:0803.2842 - Admission Control to Minimize Rejections and Online Set Cover with Repetitions
**Solves:** preemptive online admission with the objective of minimizing rejected
requests; `O(log^2(mn))`-competitive randomized algorithm; reduction between
admission control and online set cover with repetitions.

**Crucial sentence for us:** the paper notes that **allowing preemption is
essential for avoiding trivial lower bounds**. That is the opposite of our
setting - we assumed admissions are irreversible. So irreversibility is not a fresh
twist; it is precisely the condition that makes this family of problems collapse
to trivial bounds.

### 10. arXiv:1704.08835 - Relaxing the Irrevocability Requirement for Online Graph Algorithms
**Solves:** studies online models where acceptance is delayed but **irrevocable**
(Late Accept / Late Reject), for Independent Set, Matching, Vertex Cover, MST, and
shows the competitive ratio changes by model (Matching: 2 -> 3/2).
**Occupies:** "irreversible online decisions with a competitive ratio" as a
modelling dimension. It is established vocabulary, not a new axis.

## Verdict after 10 full texts

| candidate gap | status |
|---|---|
| evidence budget allocation | occupied (2609.34376) |
| adaptive adversary vs published certificates | occupied (2610.10597) |
| skew / single point of failure | occupied (cs/9908011 quorum load) |
| stream + budget + competitive ratio | occupied, actively tightened (2610.41136) |
| streaming covering with space bounds | fully settled (1703.01847, 1404.6763) |
| irreversible online decisions | an established model dimension (1704.08835), and preemption is what makes the admission version tractable (0803.2842) |
| **anything left** | one question: does *irreversibility plus a memory bound* together produce a genuinely different, tractable problem - or just a trivially hard one? |

That last question now reads like a warning rather than an opening: 0803.2842 says
preemption is needed to avoid trivial lower bounds, which suggests our setting is
hard for a boring reason, not an interesting one.

Honest default stands: **assume no gap** until the remaining 10 reads produce
evidence otherwise.
