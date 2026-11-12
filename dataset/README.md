# Canari Open Dataset

License: **CC-BY-4.0** (code is Apache-2.0; the data is separately licensed).

This is the published snapshot of the Canari verification ledger: real signed
attestations produced by real scans, plus the feed, drift reports, schema and
public keys needed to verify everything offline.

## Contents

| Path | What |
|---|---|
| `attestations/` | DSSE/Ed25519 bundles whose payload is an **in-toto Statement v1** (`subject[]` + `predicateType` + `predicate`); one per scan of one component, multiple generations form supersession chains |
| `feeds/` | `feed-multi-*.json` = canonical component-level view; `run-feed-*.json` = what one scan produced |
| `drift/` | per-run drift reports (verdict flips, same-version silent changes, findings deltas) |
| `attestation-v0.1.json` | JSON Schema (2020-12) |
| `public_key.json` | current Ed25519 public key |
| `public_key_20261108.json` | archived public key (keeps older bundles verifiable) |
| `key_registry.json` | key lifecycle: valid_from / valid_until / revoked_at |
| `MANIFEST.json` | sha256 of every file above, plus counts |

## Verify any bundle offline

```
pip install canari-mcp
canari-verify attestations/<file>.bundle.json --key public_key.json
canari-verify --chain attestations/
```

No network, no accounts: DSSE signature + in-toto Statement v1 shape + schema
+ per-check breakdown.

## Consuming the attestations elsewhere

The DSSE payload is a standard in-toto Statement v1, so existing tooling can
read it without any Canari-specific code:

| Field | Value |
|---|---|
| `_type` | `https://in-toto.io/Statement/v1` |
| `subject[0].name` | `<registry>:<name>@<version>` |
| `subject[0].digest.sha256` | artifact sha256, present only when the bytes were actually fetched |
| `subject[0].digest.canari-component-id` | sha256 of the component reference, used for metadata-only records instead of fabricating an all-zero `sha256` |
| `predicateType` | `https://agentcheck.dev/attestation/v0.1` |
| `predicate` | the Canari attestation: verdict, checks, evidence, supersession |

`canari-verify` reports the Statement shape separately from the signature, so
a bundle with a valid signature but a non-standard statement cannot be
mistaken for an in-toto attestation.

## Verify the snapshot itself

`MANIFEST.json` lists a sha256 for every file in this directory:

```
python - <<'PY'
import hashlib, json
m = json.load(open("MANIFEST.json", encoding="utf-8"))
bad = [p for p, h in m["sha256"].items()
       if hashlib.sha256(open(p, "rb").read()).hexdigest() != h]
print("files:", len(m["sha256"]), "mismatched:", bad)
PY
```

## What the attestations contain

Per component: registry, name, version, artifact sha256, host class, the list of
checks with per-check verdict + evidence reference, overall verdict
(`pass` / `pass-with-findings` / `fail` / `unsupported` / `error`), expiry,
generation timestamp, and `supersedes` pointing at the previous payload digest.

Checks shipped today: registry presence, version resolution, artifact hash,
maintainer set, manifest fields, dsh.so install/security conclusions, npm Sigstore
provenance, PyPI PEP 740, plus three metadata heuristics (release cadence,
metadata anomaly, typosquatting).

## Honest limits

- This is a **risk signal, not a safety guarantee**. A `pass` means the checks we
  run found nothing, not that the component is safe.
- Coverage is a sample of each ecosystem, not the whole ecosystem.
- Signature validity proves the ledger produced it, not that the verdict is right.
- Refresh cadence: weekly. `MANIFEST.json.generated_at` says when this snapshot was cut.
