# Technical moat: deep survey and plan (2026-11-15)

Status: research complete. Every claim below was checked against a primary
source (IETF draft text, spec source file, or paper abstract) during this
session; links are given inline. Where something could not be verified it is
marked as unverified rather than asserted.

**Correction to earlier work in this repo.** `docs/research-moat-20261115-v2.md`
says "IETF SCITT has a framework but no AI profile". That is no longer true and
was probably never precisely true: the SCITT draft index now contains at least
six AI-specific profiles. The claim must not be repeated.

---

## 0. Headline

The four technical gaps I proposed to attack are **all already taken**:

| Proposed gap | Actual status | Primary evidence |
|---|---|---|
| Content identity / anti-rename | Researched at scale + standardised | arXiv 2606.29785 (2026-06), SWHID v1.6 |
| Verifiable completeness | IETF draft with completeness chains and spot checks | draft-jangra-scitt-digest-evidence-00, 2026-10-08 |
| Verdict conflict adjudication | Two IETF drafts: "verdict arithmetic", and a formal underdetermination profile | draft-hillier-scitt-arp-06, draft-nestorov-scitt-p10-underdetermination-00 |
| Drift attribution | IETF draft with "source-data version binding"; plus a reference implementation of reproducible diff | draft-hillier-scitt-arp-06; HISTOR `histor/diffing.py` |

So the honest answer to "is there a technical moat here" is: **not in mechanism
invention**. The mechanisms are being standardised by people with more standing
than this project.

What is left is one **structural** gap, and it is not a mechanism problem.

---

## 1. The one real structural gap: MCP has no channel for a third-party claim

Read `schema/2025-11-25/schema.ts` from `modelcontextprotocol/modelcontextprotocol`.
Grep counts for the whole schema:

```
ToolAnnotations      4
readOnlyHint         3
destructiveHint      1
provenance           0
verdict              0
signature            0
```

`ToolAnnotations` is exactly five fields, every one a **hint declared by the
server about itself**:

- `title`
- `readOnlyHint` (default false)
- `destructiveHint` (default true)
- `idempotentHint` (default false)
- `openWorldHint` (default true)

There is no field anywhere in the protocol for "an independent party checked
this and here is their signed conclusion", and no field that lets a client ask
for one. Everything a client learns about a tool's safety is either
self-declared by the party being judged, or out of band.

This is not covered by adjacent work:

| Work | Why it does not fill this |
|---|---|
| VEX | Scoped to `vulnerability x product`; four statuses; CVE-centric. MCP tool poisoning has no CVE. `impact_statement` is explicitly "not intended to be machine readable" |
| CycloneDX 1.7 `declarations` | BOM-level. `claim.predicate` is a **free-form string**; `counterEvidence` exists but there is no adjudication rule |
| SCITT profiles | SCITT-level transport and receipts; none of them defines a field on the MCP wire |
| MCP registry issues #82 / #1404 | Registry-side storage, not a protocol field a client can rely on at call time |

The consequence: a client cannot, at the moment it decides to call a tool,
obtain a verifiable third-party statement about that tool **over the MCP
protocol**. It has to hard-code a vendor.

That gap is structural, not algorithmic. Filling it requires a spec change at
the MCP layer, which is a political/standardisation task with a reference
implementation attached — not something one can brute-force with clever code.

---

## 2. Full survey of what is already built

### 2.1 Transparency logs for AI components

| Project | What it actually has | What it explicitly does not |
|---|---|---|
| `alexar76/histor` | RFC 9162 Merkle (passes our 144 vectors: 72/72 inclusion, 72/72 consistency); c2sp checkpoint + signed-note + cosignature/v1; `c2sp.org/tlog-tiles` tiled log validated against `golang.org/x/mod/sumdb/tlog` on 70k leaves; is itself a c2sp witness; cross-checks with CrawlCheck and ScraperWatch | Per its own spec §9: publisher signatures, witness selection, time semantics, and **"Completeness. A server the log did not dial is not in the log."** |
| PulseFeed (`pulsefeed.dev/mcp/drift`) | Ed25519-signed daily manifests, OpenTimestamps anchoring to Bitcoin, seven Zenodo DOIs for frozen copies | No Merkle log, no consistency proofs; per-day anchors only |
| mcpcost / ProtocolProbe | Daily evidence exports, publisher-published sha256 in an index, CC BY 4.0 | Unsigned; no history commitment |
| Canari (this repo) | RFC 9162 + c2sp checkpoint + OTS + three verifiers | Same completeness non-goal as HISTOR |

### 2.2 SCITT drafts relevant to this project

Index query: `datatracker.ietf.org/api/v1/doc/document/?name__contains=scitt`
returned 60 documents; these matter:

| Draft | Rev | What it adds | Date evidence |
|---|---|---|---|
| `draft-jangra-scitt-digest-evidence` | 00 | Digest-only evidence log over RFC 9162 + **completeness chains** + selective disclosure + **spot checks on "a sample nobody could choose"**; "published as running code with test vectors" | Text dated 8 October 2026, expires 2027-04-11 |
| `draft-hillier-scitt-arp` | 06 | Attestation Reconciliation Protocol: **"verdict arithmetic that the deployment's policy resolves"**, and **"source-data version binding that makes a change in a historical verdict attributable to a change in policy or to a change in the underlying published corpus"** | rev 06 (mature draft) |
| `draft-nestorov-scitt-p10-underdetermination` | 00 | Formal third-party-verifiable binding for `NotDemonstrated(reason=underdetermined)`: two witness worlds consistent with the same closed evidence set that disagree | September 2026; code at `github.com/VolMax-Studio/p10-underdetermination-profile` |
| `draft-emirdag-scitt-ai-agent-execution` | 01 | AI Agent Execution Profile of SCITT | — |
| `draft-dawkins-scitt-ai-article50` | 00 | EU AI Act Article 50 transparency receipts | — |
| `draft-bailey-scitt-agent-session-receipt` | 00 | Causal provenance receipts for agent sessions | — |
| `draft-templeman-scitt-measurement-capsule` | 01 | Declared-versus-observed measurement capsules | — |
| `draft-fassbender-scitt-time-anchor` | 08 | Bitcoin-anchored temporal proofs | — |
| `draft-mih-scitt-checkpointed-local-log` | 02 | Checkpointed Local Log | — |

### 2.3 Verdict vocabulary

OpenVEX spec (`github.com/openvex/spec`, `OPENVEX-SPEC.md`), read directly:

- Four statuses: `not_affected`, `affected`, `fixed`, `under_investigation`
- `justification` is a fixed label set; `impact_statement` is free text and the
  spec says it "is not intended to be machine readable so its use is highly
  discouraged for automated systems"
- Scope is per-vulnerability per-product. There is no "this package is safe
  overall" statement, and no conflict resolution between two producers.

### 2.4 Content identity

- **SWHID v1.6** (last modified 2021-04-30): core identifiers `swh:1:cnt:` /
  `dir:` / `rev:` / `rel:` / `snp:`. Content-addressed, so the same bytes in two
  repositories share an identifier.
- **Go checksum database**: identity is the module path; the database binds
  path+version to a hash. There is no cross-path identity — `replace` is a build
  directive, not a claim that two paths are the same code.
- **arXiv 2606.29785** "Uncovering Similar but Different Packages in PyPI"
  (2026-06-29): studies replication over one third of PyPI (200k packages);
  finds 1,361 replicated packages of the top 3K, 256 previously unknown
  replicated vulnerable packages, and 186 of 3,883 known malicious packages
  (4.79%) replicating popular ones.

Conclusion: replica detection is a **solved research problem with published
numbers**. Re-implementing it would be repeating published work, and no
deployment of it is verifiable after the fact.

---

## 3. What that means for "technical moat"

Three layers, and this project is only in the first:

| Layer | Definition | Where Canari is |
|---|---|---|
| L1 implement a public spec | RFC 9162, c2sp, OpenVEX, CycloneDX | done, no moat |
| L2 implement a draft before others do | the SCITT drafts above | possible, weak and temporary |
| L3 own a structural position others must route through | a protocol field, a wire format, a default | **the only durable one, and it is open** |

The L3 candidate is §1: **a third-party-verifiable claim channel on the MCP
wire**. Whoever gets that into the spec, with a reference implementation that
existing clients can adopt, holds a position that later entrants must
interoperate with. That is the only technical position here that compounds.

Everything else we build is either (a) public standard, (b) someone else's
published draft, or (c) operational quality.

---

## 4. Plan

### Stage 0 — falsify the premise first (1 to 2 days)

Before writing any spec text, check whether the gap is real:

1. Read the MCP spec repository for any in-flight proposal about provenance,
   trust, or verdicts on the wire (issues, PRs, discussions). If someone is
   already drafting it, the plan changes from "propose" to "join".
2. Ask the maintainers in the appropriate issue whether a `_meta` extension for
   a third-party verdict is acceptable in principle, or whether they would
   reject it. One comment, no product pitch.
3. Check `schema.ts` for `_meta` extension precedents (e.g.
   `io.modelcontextprotocol.registry/*`) and confirm the extension mechanism
   applies to `tools/list` results.

**Falsification criteria.** Stop this line if any of:
- a draft already exists for tool provenance on the wire
- maintainers state the registry/gateway layer is the intended home and the wire
  is deliberately closed
- `_meta` turns out not to be carried on `tools/list` items

Cost: zero money; 1 to 2 days.

### Stage 1 — reference implementation, no spec PR yet (1 week)

Build the thing that makes a proposal credible: a working client-side check.

- Produce `_meta` payloads carrying a Canari bundle pointer plus the verdict
  digest, for a handful of real servers
- A client-side verifier that, given a `tools/list` response, checks the
  attached bundle offline (reuse `canari/verify_offline.py` and the browser page
  already built)
- A demo: two MCP servers, one with a passing verdict, one failing, and a client
  that refuses to call the failing one based only on the attached evidence

**Acceptance.** A stranger can run the demo and see the refusal happen without
trusting our service.

**Falsification.** If attaching `_meta` breaks any real client, the approach is
wrong and should be dropped rather than patched.

### Stage 2 — implement one SCITT draft rather than invent one (2 to 3 weeks)

Pick exactly one, and pick the one with the most normative text and running
code available: `draft-jangra-scitt-digest-evidence` (completeness chains +
spot checks) because it directly answers the question our own spec admits we
cannot answer, and because it is a small, well-bounded construction.

Deliverable: our log gains `chain_tag` / `chain_seq` / `chain_prev` support and
can answer "is this set complete" with a signed chain statement, conforming to
the draft's construction. Then publish cross-implementation vectors so an
independent implementation can check us.

Do **not** invent a replacement format. If the draft is wrong, write an
implementation note and file it with the draft authors.

### Stage 3 — time and data (months, no shortcuts)

Only two things compound here, and neither can be bought:
- days of unbroken history in the log
- number of independent witnesses that have co-signed the origin

Targets that would make this defensible: 365 consecutive days, and at least 3
independent witnesses from different operators.

---

## 5. Explicit non-goals (things not to build)

- **Replica / clone detection.** arXiv 2606.29785 has the numbers and the
  method. Cite it; do not re-implement it.
- **A verdict vocabulary.** OpenVEX already defines one for vulnerabilities; if
  a vocabulary is needed for tool-level claims, it should be proposed as a
  profile, not a new format.
- **A log format.** c2sp already has checkpoint, note, cosignature and tiles.
- **A completeness theory.** draft-jangra has the construction.

Re-implementing any of the above is the exact failure mode this project has
already been through once, when it invented its own tree-head format and had to
throw it away to become interoperable.

---

## 6. Risks

| Risk | Consequence | Mitigation |
|---|---|---|
| Maintainers reject `_meta` provenance | Stage 1 has no destination | Stage 0 exists to find this out in 2 days, not 2 months |
| A big vendor ships this first | Position lost | Acceptable: then implement their format and supply the audit layer |
| Drafts change under us | Rework | Implement one draft, keep vectors, track revisions |
| Nobody ever witnesses | Log stays self-anchored | Already stated as a limit in our own spec; do not paper over it |

---

## 7. What changed in my own position

Earlier in this session I told the user that four specific technical gaps were
open, and that anti-rename detection was the most promising. That was wrong on
both counts, and the correction matters more than the original claim:

- completeness: drafted in October 2026
- adjudication: two drafts
- drift attribution: a draft, plus a reference implementation in a competitor
- anti-rename: a peer-reviewed-scale measurement study with published numbers

The remaining gap is not an algorithm. It is a missing field in a protocol.
