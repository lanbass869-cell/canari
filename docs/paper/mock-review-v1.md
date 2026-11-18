# Mock review — package-existence draft v1

Self-review, adversarial. Five attacks a reviewer would actually make, what the draft
currently answers, and what it does not yet.

## A1 "This is a bug report at scale, not research."  ← the strongest attack

**Reviewer:** The observation is that a registry does not re-validate. That is an
operations defect. Where is the generalisable insight?

**Draft answers:** §1 frames the entry as an *instruction* and §6 states the mechanism
(publish-time validation without lifecycle re-validation).

**Not yet answered:** a general statement of the *class*. The paper would be stronger
with one sentence like: "any registry that validates at publish time only will accumulate
stale instructions at the rate upstream churn produces them; the MCP Registry is an
instance, and its 1.19% is a lower bound because the registry validates at all."

**Action:** add to §6 the general form + why MCP is a *favourable* case (it does validate
at publish), which makes the measured 1.19% a lower bound rather than a worst case.

## A2 "n = 40, one snapshot, three days."

**Draft answers:** Wilson CI is reported; the three-day re-check is added; threats §7.

**Not yet answered:** no second full audit. Promised, not delivered. A reviewer will accept
this only if the promise is concrete (scheduled date + what will be reported).

**Action:** state the exact date and what the second audit will report (count, drift,
recovery count).

## A3 "Downloads are package-level; the harm claim is inflated."

**Draft answers:** §5 states it plainly, and the claim is phrased per package.

**Remaining risk:** the abstract's "47 exceed 100/month" may still read as impact. Keep
the hedge adjacent to the number (it is), and avoid ever writing "users affected".

## A4 "Where is the baseline? Is 1.19% high?"

**Draft answers:** none. This is a genuine hole: without a comparison, "1.19%" is a
number, not a finding.

**Options:**
1. compute the same metric for a registry that *does* re-validate, if one exists;
2. compute the *inflow* rate (new broken references per week) from two audits, and report
   the steady-state stock = inflow × residence time (Little's law);
3. report the number as a **lower bound** (see A1) and stop claiming it is high.

**Action:** do (3) now, (2) at the second audit. Do not claim "high" anywhere in the draft.

## A5 "You found a bug in your own measurement mid-study. Why trust the rest?"

**Draft answers:** §2 corrects it openly, and §3 reports the case as evidence for the
correction rather than against the finding. §7 lists residual normalisation risk.

**Action:** none beyond keeping the correction visible. This is the paper's best
credibility signal, not its worst.

---

## Verdict before revision

**Not submittable yet.** Two blocking items:
1. A1/A4: the general framing + "lower bound, not a high number" statement (doable today).
2. A2: a concrete second-audit commitment with a date.

Everything else is wording that is already in place.
