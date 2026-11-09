# Canari Open Dataset: Agent Component Verification Attestations

License: CC-BY-4.0
Generated: 2026-11-09

## Contents
- attestations/: signed DSSE/Ed25519 attestation bundles (243 files)
- feeds/: scan run feeds with verdict summaries (2 files)
- attestation-v0.1.json: JSON Schema (2020-12)
- public_key.json: Ed25519 public key for offline verification
- key_registry.json: key lifecycle (valid_from/valid_until/revoked_at)

## Format
Each attestation is a DSSE envelope (application/vnd.in-toto+json) containing
a signed verdict about one AI agent component. Checks: L1-L2 meta checks
(registry presence, version resolved, artifact hash, maintainer set, manifest
fields) plus native provenance ingestion (npm Sigstore / PyPI PEP 740).

## Verification
python -m canari.__main__ <bundle.json> --key public_key.json
python -m canari.__main__ --chain attestations/
