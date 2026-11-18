# The registry publishes installs that fail

**Draft v1 — 2026-11-19. Numbers carry their snapshot date and denominator.**
Target: FSE 2027 IVR (4 pages + 1 page references), 2027-02-12 AoE.

---

## Abstract

Agent component registries tell a client *what to install*. We measured whether that
instruction still works. On the MCP Registry's 2026-11-16 snapshot (654 pages, 65,340
latest records, 22,526 distinct npm/PyPI references), 274 references named a package or
version that could not be resolved. We then ran the actual install command for 40 of
them: **39 failed (97.5%, Wilson 95% CI 87.1–99.6%)**. The entries advertising those
references are not fresh mistakes — their median age is **218 days** (p90 283, max 435),
and 83% are older than 90 days. The packages are not abandoned either: of the 140 whose
download statistics were obtainable, the median is **49 downloads/month** and **47 exceed
100/month**. A registry that validates only at publish time therefore keeps advertising
unusable installs, for months, for packages people are actively using.

## 1. The claim

> A registry entry is an instruction. This paper measures how often that instruction
> fails, how long it has been failing, and whether anyone was using it.

Three numbers, three measurements, one sentence:

| RQ | Measurement | Result |
|---|---|---|
| RQ1 Does the install work? | run the real `npm install` / `pip download` for a 40-item sample | **39/40 fail (97.5%, CI 87.1–99.6)** |
| RQ2 How long has it been dead? | entry age from the registry's own `publishedAt` | **median 218 d**, 83% > 90 d, max 435 d |
| RQ3 Does anyone use it? | monthly downloads for each distinct package | **median 49/mo**, 47 packages ≥ 100/mo |

## 2. Background and data

The MCP Registry publishes, per server, a `packages[]` array whose entries name a
`registryType`, an `identifier` and a `version`. A client that follows an entry simply
runs the corresponding install.

Our corpus is the full `GET /v0/servers?version=latest` pagination on **2026-11-16**:
654 pages, 65,340 latest records, de-duplicated to **22,526 distinct
(registry, identifier, version) references** across 22,384 servers.

Each reference was resolved against the publisher's own registry (npm `versions` map,
PyPI `releases` map with at least one file). 274 references did not resolve: 151 where
the package returns HTTP 404, 123 where the package exists but the version does not.

**Correction (2026-11-19).** Re-running the install exposed a defect in our own check:
PyPI keys `releases` by PEP 440 normal form, and we compared the raw registry string.
Seven of the 32 PyPI version-absent rows are normalisation-sensitive; six are confirmed
installable under the normalised key. **The corrected figure is at most 268 (1.19%), not
274 (1.22%).** The 151 package-gone rows are unaffected.

## 3. RQ1 — does the install work?

Sampling: 20 rows from each failure class, taken at equal spacing over the sorted list
(not hand-picked). Commands:

```
npm install <name>@<ver> --dry-run --ignore-scripts --no-audit --no-fund
python -m pip download <name>==<ver> --no-deps -d <tmp>
```

| class | n | reproduced | rate | 95% Wilson CI |
|---|---|---|---|---|
| package-gone | 20 | **20** | 100% | 83.9–100% |
| version-absent | 20 | **19** | 95% | 76.4–99.1% |
| **all** | 40 | **39** | **97.5%** | **87.1–99.6%** |

Both failure modes are covered, and they fail with *different* error classes: npm `404`
and `ETARGET notarget`, pip `No matching distribution`. The one that did not fail is the
PEP 440 case discussed in §2 — i.e. it is evidence for the correction, not against the
finding.

## 4. RQ2 — how long has it been dead?

Joining the 274 references back to the registry snapshot yields **311 entries** (a
reference can appear under more than one server). Reading each entry's own
`_meta["io.modelcontextprotocol.registry/official"].publishedAt`:

| age | value |
|---|---|
| min / p25 | 2.0 d / 127.8 d |
| **median** | **218.3 d** |
| p75 / p90 | 266.4 d / 282.7 d |
| max | 435.4 d |
| > 30 d | 301 / 311 (96.8%) |
| > 90 d | 259 / 311 (83.3%) |

Split by class: package-gone median 244.6 d; version-absent median 192.4 d.

**Reading note.** `publishedAt` is when the registry published the entry, which cannot
precede the upstream disappearance. So entry age is an **upper bound** on the break
duration, not the duration itself. The claim is: *the registry kept a dead reference for
at least a median of seven months*, not *the install has been broken for seven months*.

## 5. RQ3 — does anyone use it?

Monthly downloads for the 271 distinct packages (npm `api.npmjs.org`, PyPI `pypistats`),
throttled after 429s:

| registry | packages with stats | median/mo | max/mo | ≥100/mo |
|---|---|---|---|---|
| npm | 69 | 60 | 3,638 | 25 |
| PyPI | 71 | 41 | 20,925 | 22 |
| **all** | **140** | **49** | **20,925** | **47** |

A further 48 packages 404 on the download API, which is itself consistent with "gone".

**Reading note.** Downloads are per *package*, not per *version*. The 20,925 downloads of
`nanobanana-mcp-server` are overwhelmingly other versions. The claim is therefore: *the
package is in active use, and the exact version the registry advertises cannot be
installed* — not *20,000 users are affected*.

## 6. Why this happens

The registry validates a version **at publish and edit time**. It does not re-check
afterwards. Upstream unpublishes, renames, yanks or abandons a version; the registry
entry keeps its text. Nothing in the entry's lifecycle forces a re-check, and nothing in
the client's install path distinguishes "the publisher withdrew this" from "the registry
is stale".

The cheap fix does not require deleting anything: re-run the existing validation on a
schedule and record the outcome in `_meta` (e.g. `lastVerifiedAt`,
`verificationStatus ∈ {ok, package-missing, version-missing}`), leaving the entry's
history intact. Deletion is a separate decision, because revocation across distributions
(npm removed, an OCI copy still live) is not the registry's call alone.

## 7. Threats to validity

- **Sample size.** RQ1 uses 40 references out of 274. The CI is reported; the point
  estimate should not be read as an exact population rate.
- **Upper bound on age.** §4.
- **Package-level downloads.** §5.
- **Snapshot drift.** The registry grows; 274 (2026-11-16) became 275 (2026-11-17) on the
  same definition. Every figure here is tied to its snapshot.
- **Normalisation.** One measurement defect was found and corrected during the study; the
  remaining rows were re-derived with the normalised comparison. A residual risk of the
  same class in npm version strings exists and was not exhaustively ruled out.

## 8. Related work

Package-registry health has been studied for npm and PyPI (dependency confusion, typosquatting,
unpublished-package reuse). Those lines measure *malice* or *availability of a name*; this
paper measures **whether the registry's own instruction still resolves**, which is a
different failure: nothing is malicious, the entry is simply stale.

## 9. Conclusion

A registry that validates once and never again will accumulate instructions that no
longer work. In the MCP Registry's 2026-11-16 snapshot that accumulation is already
measurable: 274 references, 39/40 of a sample failing when actually executed, a median
entry age of seven months, and 47 affected packages still receiving 100+ downloads a
month. The fix is cheap and does not require deleting history.
