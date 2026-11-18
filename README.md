# Canari

<!-- mcp-name: io.github.lanbass869-cell/canari -->

[![CI](https://github.com/lanbass869-cell/canari/actions/workflows/ci.yml/badge.svg)](https://github.com/lanbass869-cell/canari/actions/workflows/ci.yml)
![tests](https://img.shields.io/badge/tests-762%20passing-brightgreen)
![coverage](https://img.shields.io/badge/coverage-86%25%20line%20%7C%2085%25%20branch-brightgreen)
![mutation](https://img.shields.io/badge/mutation%20kill-100%25%20(52%20mutants)-brightgreen)
![release](https://img.shields.io/github/v/release/lanbass869-cell/canari)
[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/lanbass869-cell/canari)
[![Canari on Glama](https://glama.ai/mcp/servers/lanbass869-cell/canari/badges/score.svg)](https://glama.ai/mcp/servers/lanbass869-cell/canari)

Agent component verification ledger - signed, offline-verifiable, history-preserving attestations for MCP servers, agent skills, and DSH plugins.

Named after the canary in the coal mine: the first to detect that something went wrong.

## What it does

1. **Weekly scan** of agent component ecosystems (npm, PyPI, MCP Registry, dsh.so)
2. Each component gets a **signed attestation**: DSSE/Ed25519 envelope whose payload is an **in-toto Statement v1** (`subject[]` with `digest.sha256`, `predicateType`, `predicate`) binding: artifact hash + host version + scan scenario. Readable by GUAC / cosign / slsa-verifier without Canari-specific code.
3. Attestations are **offline-verifiable** by anyone with the public key
4. History is **never deleted** - version changes create supersession chains
5. Public **machine-readable feed** for any AI agent or host to consume
6. **Trust heuristics**: release cadence (L2.4), metadata anomaly (L2.5), typosquatting (L2.6).
   Which of these appear in an attestation depends on the entry point - see
   [Which checks come from which entry point](#which-checks-come-from-which-entry-point).
7. **Consumer install gate** with policies: `canari-verify bundle.json --key pub.json --gate --gate-policy paranoid`

## Install

```
pip install canari-mcp
```

Also on [PyPI](https://pypi.org/project/canari-mcp/) and as a
[GitHub release](https://github.com/lanbass869-cell/canari/releases/tag/v0.1.0)
(wheel + sdist + `SHA256SUMS` + Ed25519 signature). Both channels ship byte-identical
artifacts; see `docs/release-process.md` to verify the signed release.

```
canari-gate --store out --list
```

## Open dataset

`dataset/` is the published snapshot of the ledger under **CC-BY-4.0**: **5170 signed
attestations over 1417 components**, the canonical feed, drift reports, the schema, both
public keys and a `MANIFEST.json` with a sha256 per file. Verify a bundle offline with
`canari-verify`; verify the whole snapshot with the manifest (see `dataset/README.md`).
Refresh it after a scan with `python scripts/sync_dataset.py`.

## Append-only public log (verifiable without trusting us)

Every published verdict bundle and every upstream dataset snapshot is committed
into a signed, append-only Merkle log at
[`docs/log/`](https://lanbass869-cell.github.io/canari/log/). This closes a gap
that a signature alone cannot: a signed attestation proves *who* said something,
never that an older statement was not quietly deleted or re-issued with a
different verdict.

- **Latest head**: `docs/log/head-latest.json` (size, root, Ed25519 signature)
- **Latest offline bundle**: `docs/log/bundle-latest.json`
- **c2sp.org checkpoint**: `docs/log/checkpoint.txt` -- the same head as a
  signed note in `c2sp.org/tlog-checkpoint` + `signed-note` +
  `tlog-cosignature` form, so an existing transparency-log witness can co-sign
  it without adopting anything of ours. Pinned against another project's
  published test vectors (`tests/test_checkpoint.py`).
- **Format**: [`docs/spec/append-only-log.md`](docs/spec/append-only-log.md)
  (RFC 9162 hashing, inclusion + consistency proofs, explicit list of what the
  proof does *not* claim)
- **Cross-implementation vectors**: `docs/spec/merkle-vectors.json` (168 cases),
  checked by two independent verifiers

```
# no network, no canari install needed for the Node path
node docs/spec/verify_offline.js docs/log/bundle-latest.json --log-id canari-snapshot-log

# "the head I recorded yesterday is still a prefix of today's"
python -m canari.verify_offline docs/log/bundle-latest.json \
  --pinned-prefix <root-you-saved-last-week>
```

A new head is appended daily by `.github/workflows/append-only-log.yml`. The
publish path refuses to sign (`LogTruncated` / `LogRewritten`) if the on-disk
log contradicts a head it already published, because a log that re-signs a
rewrite under its own key manufactures false assurance.

## Quality gates (enforced in CI)

| Gate | Threshold | Current |
|---|---|---|
| tests | green on 3.10/3.12/3.13 | 863 collected, 852 passing, 11 env-skip (10 network, 1 platform) |
| line coverage | >= 85% | 85.3% combined (CI gates on the combined figure) |
| mutation kill rate | >= 90% (equivalent mutants excluded) | 100% (47/47 killed + 2 equivalent, 3 skipped) |
| live-data audit | sampled attestations re-derive from npm/PyPI | 18/18 |

Run them yourself before every push:

```
python scripts/quality_gate.py
```

That single command runs **lint + tests + coverage + mutation**, which is the same
set CI enforces. Running only `pytest tests` is not a substitute: it skips the
coverage gate and the lint gate, and this repository once stayed red for nine
consecutive commits that way.

## Quick start

```
# install
pip install canari-mcp

# run a scan
canari-baseline --limit 50

# verify an attestation offline
canari-verify out/attestations/npm_some-package.bundle.json --key out/public_key.json

# verify + policy gate (exit 0 ALLOW / 5 BLOCK / 6 REVIEW)
canari-verify out/attestations/npm_some-package.bundle.json --key out/public_key.json \\
    --gate --gate-policy strict

# custom policy file
canari-verify bundle.json --key out/public_key.json --gate --gate-policy-file my-policy.json
```

### Policy file example

```json
{"name": "my-policy", "block_on_findings": true, "require_native_provenance": false}
```

## Consumer side (the part a host actually uses)

### 1. Look up a component and gate it

```
# resolve the newest signed attestation for a component and run the gate
canari-gate --store out --registry npm --name express
canari-gate --store out --registry dsh-registry --name aegis --policy paranoid --json

# exit codes: 0 ALLOW, 5 BLOCK, 6 REVIEW, 3 not found
canari-gate --store out --list
```

### 2. Record another scanner's result as a signed, timestamped attestation

**Live example:** [20 PyPI MCP servers, scanned by bandit, recorded and signed](https://lanbass869-cell.github.io/canari/scan/) - every record on that page
can be verified with `canari-verify` using the public key shipped beside it.

Canari does not scan anything itself. What it adds is durability: a scanner
tells you what it thinks *today*, Canari records what it said *on each date*,
signed and offline-verifiable, and keeps the history when the verdict flips.

`canari-ingest-sarif` reads a SARIF 2.1.0 report from any external scanner
(NVIDIA SkillSpector, Snyk agent-scan, Tencent AI-Infra-Guard, ...) and writes a
normal Canari bundle:

```
canari-ingest-sarif \
  --sarif skillspector.sarif \
  --name @modelcontextprotocol/server-filesystem --version 2025.1.0 \
  --registry npm \
  --artifact-sha256 <sha256 of the scanned artifact> \
  --key out/private_key.pem --out out/attestations
```

Rules it enforces, so the ledger cannot become a rubber stamp:

- **The upstream tool is named, not hidden.** Every check records
  `tool = <scanner>/<version>` and `checker.id` says it was ingested by Canari.
- **The artifact digest is required.** A scan result without the scanned
  artifact's sha256 cannot be bound to anything, so the command refuses.
- **An unusable report is an error, not a pass.** No run block, or
  `executionSuccessful: false`, yields verdict `error`.
- **Findings move the verdict.** Critical/high → `fail`; lower severity →
  `pass-with-findings`; no findings → `pass`.

### 2. Drift report (what changed since last week)

```
canari-drift --store out --write out/drift
# verdict flips / same-version silent changes / findings added / findings removed
```

`run_weekly.py` writes this report automatically after every scan.

### 3. Use it from any MCP host (dsh, Codex, Claude, ...)

`canari-mcp` speaks MCP over stdio (zero dependencies) and exposes three tools:
`gate_check`, `verify_bundle`, `store_summary`.

```json
{
  "mcpServers": {
    "canari": {
      "command": "canari-mcp"
    }
  }
}
```

No arguments needed: the wheel ships a snapshot of the newest signed attestation
per component (1417 components, rebuilt by `scripts/build_snapshot.py` from
`dataset/`), so `gate_check` answers out of the box. Point `--store` (or
`$CANARI_STORE`) at a full ledger checkout when you want the complete
supersession history instead of the snapshot.

A host (or agent) can then ask: "is npm:express allowed to install?" and get
`ALLOW / BLOCK / REVIEW` with reasons, backed by a signed, offline-verifiable
attestation.

### 4. Gate the actual install command

`canari-guard` wraps an install command, checks every component against the
ledger, and refuses to execute when the verdict blocks:

```
canari-guard -- dsh plugin --profile wbpj add dsh-purge
canari-guard -- npm install some-mcp-server
canari-guard -- pip install mcp-server-fetch==0.2.1

# exit 0 allowed+executed | 5 blocked by ledger | 6 review not confirmed
# --dry-run prints what would run; --allow-review accepts pass-with-findings
```

The host is never patched - the guard sits in front of the install command.

For DeepSeek Harness (dsh), add this to the profile's `cordis.patch.yml`
(verified end-to-end on dsh: the model called `mcp__canari__store_summary` and
received the live component count):

```yaml
    - id: mcp-canari
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: canari
        transport: stdio
        command: 'canari-mcp'          # or: python -m canari.mcp_server
        args: ['--store', '<path-to-store>',
               '--key', '<path-to-store>/public_key.json']
        failOnStartupError: true
```


## Multi-registry coverage

| Registry | Source | What we check | What we inherit |
|---|---|---|---|
| npm | search API + packument + tarball sha256 | existence, version, artifact hash, maintainers | - |
| PyPI | Simple API + JSON API | same | - |
| MCP Registry | official REST | identity presence | - |
| dsh.so | JSON API | **reference existing L1-L5 conclusions** (not re-scanned) | dsh.so verdicts |

## Which checks come from which entry point

Two entry points produce attestations, and they do **not** run the same checks.
That is deliberate: a single-component CLI has no comparison corpus, so it cannot
answer a question about a set.

| check | `canari-baseline` (one component) | weekly scan / `run_multi` |
|---|---|---|
| L1.1 registry present | yes | yes |
| L1.2 version resolved | yes | - |
| L2.1 artifact hash | yes | yes |
| L2.2 maintainer set | yes | - |
| L2.3 manifest fields | yes | - |
| L2.4 release cadence | yes | yes |
| L2.5 metadata anomaly | - | yes |
| L2.6 typosquatting | **no** | yes |
| L2.7 / L2.8 dsh plugin refs | - | yes (dsh only) |

L2.6 is absent from the single-component path because a typosquat verdict is a
statement about a **set** of names, not about one name. When it does run, the row
records the set it compared against:

```json
"comparison_corpus": {
  "registry": "pypi",
  "kind": "name-set",
  "size": 620,
  "digest": "sha256:...",
  "canonicalization": "sha256(utf-8, casefolded names sorted asc, LF-joined, trailing LF)",
  "as_of": "2026-11-16T05:31:35Z"
}
```

plus a `corpus:<registry>:sha256:...:n=<size>` line in `evidence_refs`. Without it
the same package can be "clean" against five names and "a typosquat" against six
hundred; see [docs/analysis-corpus-dependence.md](docs/analysis-corpus-dependence.md)
for the measurements. A small `size` is itself the warning: `n=1` cannot produce a
typosquat finding at all.

### Known overstatement in already-published records (2026-11-18)

Until 2026-11-18 the record verdict was `"pass" if sha else "fail"`, so any record whose
artifact downloaded was marked passing even when checks inside it reported `unsupported`.
Re-deriving the verdict from each signed record's own checks finds:

| registry | records | would be reclassified |
|---|---|---|
| pypi | 2,763 | 2,233 (80.8%) |
| npm | 1,464 | 584 (39.9%) |

The signed records were **not** rewritten — an append-only log that edits its own history is
worthless. See [`docs/DISCLOSURE-false-pass-20261118.md`](docs/DISCLOSURE-false-pass-20261118.md)
for what was affected, what changed in the code, and the one gap this audit surfaced
(`canari-gate` resolves a record by name but never compares `artifact_sha256` against the
bytes the user is about to install).

## Honest limitations

- This is a **risk signal, not a safety guarantee**
- M0/M1 covers meta-level checks (L1-L2); behavioral checks (L3+) are M1+
- Scan coverage is limited to what registries expose publicly
- `expires_at` is 7 days - attestations go stale, re-scan needed
- L2.6 verdicts are **relative to the recorded comparison corpus**. Comparing two
  attestations that used different corpora is not a comparison of the packages.

## The threat model this addresses

postmark-mcp (MITRE ATLAS AML.CS0053): 15 clean versions, then one poisoned commit, ~300 orgs affected. After takedown, **no host was notified**. The gap: no longitudinal observation, no cross-host revocation feed, no portable verdict.

Canari fills that gap.

## License

Apache-2.0. See LICENSE and SECURITY.md.
