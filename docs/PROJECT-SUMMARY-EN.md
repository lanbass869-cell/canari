# Canari — one page

**A verdict ledger for AI agent components.** Weekly scans of npm, PyPI, the official
MCP Registry and dsh.so produce a *signed, offline-verifiable verdict* per component,
with the full supersession history kept, plus an install-time gate other programs can
call.

Not a scanner (no home-grown detection engine). Not a platform (no accounts, no
community). Not an LLM product. Not a cloud service.

All figures below were re-derived from artefacts on 2026-11-19; every one is
reproducible with the command named next to it.

---

## The problem

Agent components are consumed through registries that validate a package **once, at
publish time**, and never again. When the upstream package disappears, the registry
keeps advertising an install command that no longer works, and nothing in the
ecosystem notices.

Measured on the official MCP Registry, snapshot 2026-11-16 (654 pages, 65,340 latest
records, 22,526 distinct npm/PyPI references):

| Finding | Value | How |
|---|---|---|
| References that do not resolve | **267** (219 package gone, 48 version absent), 1.19% | `canari-registry-audit` |
| Real install attempts that fail | **39/40 = 97.5%** (Wilson 95% CI 87.1–99.6) | equal-spaced sample, both classes |
| Age of the affected entries | median **218 days**, max 435, 83.3% > 90 days | registry's own `publishedAt` |
| Usage of the affected packages | median **49.5 downloads/month**, 47 above 100 | npm/PyPI download APIs |

The registry was careful at publish time. This is what staleness looks like *when the
publisher is careful*.

## What is built

| Layer | What it does |
|---|---|
| **Write** | scans four ecosystems; downloads artefacts and hashes them for the deep tier |
| **Store** | DSSE/Ed25519 envelope over a real in-toto Statement v1, chained by `supersedes` |
| **Read** | offline verifier, install gate with a policy engine, drift report, identity clustering |
| **Publish** | append-only signed log (RFC 9162 Merkle, inclusion + consistency proofs), anchored to Bitcoin via OpenTimestamps, browser verifier with no install and no upload |

**Current state**: 5,170 signed attestations over 1,417 `(registry, name)` pairs
(1,415 distinct names) — pypi 2,051 / dsh 1,590 / npm 1,064 / mcp-registry 465 —
12 CLI entry points, 989 tests, 86.87% line coverage, mutation kill rate 100% over 52
mutants.

```
canari-verify --chain dataset/attestations   # 5170 bundles, 1335 chains, all valid
python scripts/quality_gate.py               # lint -> tests+coverage -> number provenance -> mutation
```

## Three design constraints the audits forced

1. **Only the signed payload is true.** A bundle carried two copies of its payload; the
   convenience copy was not covered by the DSSE signature, and every consumer read that
   one. Bug found and closed 2026-11-11.
2. **Unknown must never render as pass.** The verdict was once `"pass" if sha else "fail"`,
   so any record whose artefact downloaded was marked passing even when the checks inside
   it reported `unsupported`. Re-deriving from each signed record's own checks found
   **66.6%** of npm+PyPI records affected. Disclosed in
   `docs/DISCLOSURE-false-pass-20261118.md`; the signed records were **not** rewritten,
   because a log that edits its own history is worthless.
3. **History is never deleted.** Corrections supersede; the old record stays.

## What went wrong, and got published anyway

- Four number-versus-artefact drifts, three found by hand and one only after the checker
  was rewritten to demand *one* value per quantity rather than "appears somewhere".
- A sampling artefact: the first census claimed 84% of MCP registry names were bound to a
  domain that serves the endpoint. Full pagination gave **94.78%** for reverse-DNS
  namespaces — the sample happened to be the first 800 names alphabetically, which were
  all `a*`. Correction banner written back into the experiment directory.
- A theory line that was closed by reading **21 full papers** and concluding there is no
  theoretical gap. The work is engineering applied to a real problem, not a new theory,
  and `docs/theory/why-no-gap.md` says so.

## Current work: endpoint decay judged from a streak

A single probe answers "what did this endpoint do at that moment", not "is this entry
dead". The registry's own census found that **27 of 52 hosts that failed at least once
answered again later (51.9%)** — which is why
[registry#1692](https://github.com/modelcontextprotocol/registry/issues/1692) asks for
*n consecutive failures separated in time*.

That request had no implementation. This one implements it:

- 2 confirmations by default, at least 6 hours apart — a burst of probes counts once;
- a success ends the run; neutral outcomes (401/403, 5xx, unsupported protocol) are
  recorded but never accumulate;
- two failure classes stay separate: *answered but not MCP* is a wrong declaration,
  *answered nothing* is availability;
- a record with both a success and a failure, with too few confirmations, is **FLAPPING**
  rather than rounded to broken.

First live run (60 endpoints): 38 CONSISTENT, 20 NEUTRAL_ONLY, 1 FLAPPING,
1 INSUFFICIENT, **0 findings** — a naive single-probe monitor would have reported two
of them as dead.

## Upstream

Three pull requests against the official registry, two with green CI:

- **#1868** — npm tombstone: an unpublished unscoped package answers `200` with an empty
  `versions` map, so the validator told publishers "publish this version" for a package
  that cannot be republished.
- **#1869** — the HTTP key fetcher returned `("", nil)` for a `200` with a zero-length
  body, skipping the retry and surfacing later as "no valid MCP public key found". This
  was the root cause of a CI failure on an unrelated PR.
- **#1861** — optional `serverCard` field, backed by a full census of card adoption.

## Honest limits

- **0 stars, 0 reviews, 629 PyPI downloads in 30 days.** No external validation yet.
- The endpoint monitor has **one day of data**; no rate from it can be quoted.
- The staleness paper has no theoretical contribution. It is a reproducible measurement
  plus a cheap remediation suggestion.
- "2 confirmations, 6 hours" are derived, not calibrated against observed flapping.

---

Repository: <https://github.com/lanbass869-cell/canari> ·
Full history: [docs/PROJECT-STORY-20261119.md](PROJECT-STORY-20261119.md)
