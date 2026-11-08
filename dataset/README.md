# Canari Open Dataset: Agent Component Verification Attestations

License: CC-BY-4.0
Generated: 2026-11-08

## Contents
- attestations/: signed DSSE/Ed25519 attestation bundles (244 files)
- feeds/: scan run feeds with verdict summaries (2 files)
- attestation-v0.1.json: JSON Schema
- public_key.json: Ed25519 public key

## Format
Each attestation is a DSSE envelope containing a signed verdict about one
AI agent component. Verdict comes from L1-L2 meta checks + native provenance.

## Verification
python -m canari.verify_cli <bundle.json> <public_key.json>
