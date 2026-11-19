# Audit: 274 registry entries reference a package version that cannot be installed

Snapshot **2026-11-16**. This is the first of a recurring audit: the **current** figure is
regenerated every Monday at `docs/audit/package-existence/` (see `latest.json`). The next
run, on 2026-11-17, measured **275 of 22,657** because the registry had grown; the number
and its snapshot date must always be quoted together.

Source: `GET /v0/servers?version=latest`, full pagination —
654 pages, 65,340 latest records.

## What was checked

Every `packages[]` entry with `registryType` npm or pypi, de-duplicated to
`(registry, identifier, version)`: **22,526 distinct references** across 22,384 servers.
Each was resolved against its publisher's own registry:

- npm: `GET https://registry.npmjs.org/<identifier>` → is `<version>` a key of `versions`?
- PyPI: `GET https://pypi.org/pypi/<identifier>/json` → is `<version>` a key of `releases` with at least one file?

One HTTP request per reference, no download, no install. 84 references failed on the
first pass for network reasons and were retried individually until **0 were unknown**.

## Result

> **Superseded split.** The 151 / 123 split below is the *first-pass* classification. A later re-check found two defects in our own classifier: PyPI PEP 440 normalisation (7 rows) and npm tombstones (68 rows). The corrected split is **219 package-gone / 48 version-absent**; see the two correction sections at the end. The table is kept as published.

| outcome | references | share |
|---|---|---|
| version resolves | 22,247 | 98.78% |
| **package no longer exists (HTTP 404)** | **151** | 0.67% |
| **package exists, that version is not published** | **123** | 0.55% |
| **total that cannot be installed** | **274** | **1.22%** |

272 distinct server entries are affected. By registry: npm 198, PyPI 76.

Full list: [`data/package-existence-20261117.csv`](data/package-existence-20261117.csv)
(274 rows: registry, identifier, version, status, affected registry entries) and
[`data/package-existence-20261117.json`](data/package-existence-20261117.json)
(same data plus the denominators and the exclusions below).

## Correction (2026-11-19): PEP 440 normalisation

Re-running the real install for a 40-item sample exposed a defect in this audit.
PyPI keys `releases` by **PEP 440 normal form**, but the audit compared the registry's
raw version string. So an entry declaring `0.2.0-rc.3` (pip normalises it to `0.2.0rc3`)
was counted as "version not published" even though it installs fine.

Checking all 32 PyPI `version-absent` rows:

| item | count |
|---|---|
| raw version != PEP 440 normal form | **7** |
| confirmed installable under the normal form | **6** (verified: the normalised key exists and has files) |
| unverified (network error at check time) | 1 |

**So the published total of 274 is an overcount by at least 6: the corrected figure is
at most 268 (1.19%), not 274 (1.22%).** The audit code now compares the normalised form
before reporting a version absent (`canari/registry_audit.py`, tests in
`tests/test_pep440_normalisation.py`).

The `package-gone` category (151 rows) is unaffected: those are HTTP 404 on the package
itself, where no version spelling helps.

## Second correction (2026-11-19): npm tombstones

Re-checking the 274 rows a second time found a second defect in our own classifier. An
**unpublished unscoped npm package keeps a tombstone**: `GET /<name>` still answers `200`,
with `versions: {}` and a `time.unpublished` object. The audit read that `200` as "package
exists", so those rows were filed as *version* absent.

Verified live on 2026-11-19:

| package | HEAD | GET | versions | time.unpublished |
|---|---|---|---|---|
| `ace-context-mcp` | 200 | 200 | 0 | `{time: 2026-08-05T17:24:17.672Z, versions: [0.1.0, 0.1.1]}` |
| `stillshipping-mcp` | 200 | 200 | 0 | `{time: 2026-10-29T01:59:04.927Z, versions: [0.1.0, 0.1.1]}` |
| `mcp-server-fetch` (control) | 200 | 200 | 1 | none |

Re-classifying all 274 rows with tombstone detection:

| bucket | published | corrected |
|---|---|---|
| package gone | 151 | **219** |
| version absent | 123 | **48** |
| rows that changed bucket | - | 75 |

**The total is unchanged; the split is not.** Combined with the PEP 440 correction the
unresolvable set is 267, of which 219 are wholesale removal and only 48 are version drift.
That matters for the remedy: a drifted version can be republished, a removed package name
cannot.

## What this is not

- **This is not a report of a publish-time validation failure.** The registry does check
  the exact listed version at publish and edit time. Every one of these 274 entries passed
  that check; the upstream package or version disappeared afterwards. That is precisely the
  class of problem a periodic re-check would catch, which is what #93 asked for.
- **This is not a security report.** A removed package is usually an unpublish, a rename, a
  yank or an abandoned project. It says nothing about whether it was malicious.
- **The 5 entries that use `version: "latest"` are excluded from the 274.** `validateVersion`
  rejects `latest` as a reserved string today, but all five were published **2025-09-09**,
  the day after the registry previewed, i.e. before that rule existed. Counting them as a
  current validation gap would be wrong.

## Why it matters

A client that reads an entry and tries to install it gets a hard failure, and the entry keeps
advertising a version that no longer exists. `registry#93` was closed on 2026-10-23 by
consolidating into `#1715`, with the explicit note that *"this closure does not mean checks or
removals have been implemented"*; `#1715` was then closed as completed on 2026-11-03. This
snapshot, 13 days later, is the measurement of what such a check would still find.

For comparison, `#1715` measured 157 entries whose version did not exist against a
14,431-entry npm/PyPI denominator (1.09%) on 2026-10-04. This snapshot gives 274 against
22,526 references (1.22%) on 2026-11-16. The **rate is roughly stable; the count nearly
doubled** because the registry grew. The denominators differ (entries vs distinct
registry/identifier/version triples) and the two numbers should not be subtracted.

## Cheapest fix

The registry already has `ValidatePackage`, which performs exactly this check at publish
time. Re-running it on a schedule and recording the result rather than deleting anything
keeps the entry's history intact while letting clients see the state:

- on failure, set a `_meta` field such as `lastVerifiedAt` + `verificationStatus:
  ok | package-missing | version-missing` and leave the entry in place;
- do not delete — `#93`'s concern about cross-distribution revocation (npm removed, OCI and
  MCPB copies still live) needs a decision, not an automatic delete.

## Reproducing

The check is one request per package against the public registry APIs. There is no
authentication and nothing is downloaded. The list above is regenerable in about 8 minutes
with 48 concurrent workers on a consumer connection.

## Limits

- One snapshot. Packages are unpublished and re-published continuously; a different day
  gives a different list.
- "version not published" is decided from the registry's own `versions`/`releases` maps. A
  version present with zero files is counted as absent, because it cannot be installed.
- Only npm and PyPI were checked. mcpb (2,384), oci (1,941), nuget (183) and cargo (134)
  entries are out of scope here.
- Ties between a missing package and a network failure were resolved by retrying; the final
  run had no unresolved entries, but a transient 404 from a CDN would be recorded as missing.
