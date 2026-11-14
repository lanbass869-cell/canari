---
license: cc-by-4.0
language:
  - en
pretty_name: Canari Verification Ledger
tags:
  - security
  - supply-chain
  - mcp
  - agent
  - in-toto
  - attestation
  - ai-agent-security
size_categories:
  - 1K<n<10K
task_categories:
  - text-classification
configs:
  - config_name: default
    data_files:
      - split: train
        path: feeds/feed-multi-*.json
---

# Canari Verification Ledger

Signed, offline-verifiable verification conclusions for AI agent components
(MCP servers, npm packages, PyPI packages, dsh plugins), produced by real scans
of public registries.

This is not a benchmark and not a labelled ML dataset. It is an **audit
ledger**: a time series of what a verification pipeline concluded about a
specific artifact, cryptographically bound to that artifact, with every
re-scan preserved instead of overwriting the previous row.

## Why it exists

Agent components are installed from public registries with almost no
provenance. postmark-mcp shipped 15 clean versions and then a poisoned commit;
after takedown no host was notified. The gap is not "detect the malicious
package" - many scanners do that - it is that **conclusions do not persist, do
not travel, and cannot be checked by the party about to install the thing.**

Each record here answers: *for this exact artifact digest, what did the
verification conclude, when, under which scenario, and what came before?*

## Contents

| Path | What |
|---|---|
| `attestations/` | one DSSE/Ed25519 bundle per scan of one component |
| `feeds/` | `feed-multi-*.json` (canonical per-component view), `run-feed-*.json` (per-run) |
| `drift/` | per-run drift reports: verdict flips, same-version silent changes, findings deltas |
| `attestation-v0.1.json` | JSON Schema (draft 2020-12) of the predicate |
| `public_key.json`, `public_key_20261108.json` | Ed25519 public keys (two generations) |
| `key_registry.json` | key lifecycle (valid_from / valid_until / revoked_at) |
| `MANIFEST.json` | sha256 of every file in this dataset |

**Scale of this snapshot:** 5170 attestations over 1417 components across four
registries (npm 225 / PyPI 611 / MCP Registry 60 / dsh.so 521 components;
1064 / 2051 / 465 / 1590 records respectively), 2402 chained attestations,
6 multi feeds + 10 run feeds, 5196 hashed files.

## Record format

The DSSE payload is a standard **in-toto Statement v1**, so GUAC, cosign and
slsa-verifier can read it without any Canari-specific code:

| Field | Value |
|---|---|
| `_type` | `https://in-toto.io/Statement/v1` |
| `subject[0].name` | `<registry>:<name>@<version>` |
| `subject[0].digest.sha256` | artifact sha256 - **present only when the bytes were actually fetched** |
| `subject[0].digest.canari-component-id` | sha256 of the component reference, used for metadata-only records instead of fabricating an all-zero hash |
| `predicateType` | `https://agentcheck.dev/attestation/v0.1` |
| `predicate.verdict` | `pass` / `pass-with-findings` / `fail` / `unsupported` / `error` |
| `predicate.checks` | per-check verdict + evidence reference |
| `predicate.supersedes` | payload digest of the previous attestation for the same component |
| `predicate.generated_at`, `predicate.expires_at` | when it was produced, when it goes stale |

`unsupported` is deliberately distinct from `pass`: absence of evidence is not
evidence of safety, and the gate blocks on it.

## Verify it yourself

```bash
pip install canari-mcp
canari-verify attestations/<any>.bundle.json --key public_key.json
canari-verify --chain attestations/     # whole supersession DAG
```

No network, no account, no service. Then verify the snapshot itself against
`MANIFEST.json` (5196 sha256 entries).

## Honest limits

- **Risk signal, not a safety guarantee.** `pass` means our checks found
  nothing, not that the component is safe.
- **Sample, not census.** Coverage is what the registries expose publicly; this
  is a sample of each ecosystem.
- **Signature proves origin, not correctness.** A valid signature proves the
  ledger produced the record - not that the verdict is right.
- **Weekly cadence, and records go stale.** Every attestation carries
  `expires_at` (7 days). `MANIFEST.json.generated_at` says when this snapshot
  was cut.
- **581 of the 1417 components carry no artifact `sha256`** (521 dsh.so +
  60 MCP Registry). Those sources publish identity but no downloadable
  artifact, so the record keeps an all-zero `artifact_sha256` and relies on
  registry identity instead of fabricating a hash. The other **836 components
  carry a real `sha256`** obtained by fetching the artifact bytes (225 npm +
  611 PyPI). 836 + 581 = 1417.

## License

Data: **CC-BY-4.0**. Code (the scanner + verifier that produced it):
Apache-2.0, at https://github.com/lanbass869-cell/canari
