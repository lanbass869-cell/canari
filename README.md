# Canari

Agent Component Verification Ledger — M0 implementation (schema v0.1 + verify CLI + Top-50 npm baseline).

Read `docs/HANDOVER` in the private repo for project context; this repo is the engineering line only.

## Quick start

```
E:\Temp\tbdig\_venv_pr_a\Scripts\python.exe -m pytest tests/
E:\Temp\tbdig\_venv_pr_a\Scripts\python.exe -m canari.baseline --limit 50
E:\Temp\tbdig\_venv_pr_a\Scripts\python.exe -m canari.verify_cli out\attestations\01_x.bundle.json --key out\public_key.json -v
```

## Layout

- `schemas/attestation-v0.1.json` — byte-copy of the handover repo draft (sync test guards drift; semantic changes need WorkBuddy review)
- `canari/schema.py` — load/validate + install-gate predicate
- `canari/signing.py` — DSSE via in-toto Envelope + securesystemslib (ed25519)
- `canari/verify_cli.py` — offline verifier (exit 0/1/2/3 = ok/sig-fail/schema-fail/usage)
- `canari/npm_enum.py` — npm search enumeration + packument integrity fetch
- `canari/baseline.py` — Top-50 meta-only scan -> 50 signed bundles + public feed + failure counts
- `tests/` — schema sync, signing roundtrip/tamper, gate predicate, builder honesty, CLI e2e

## Honesty contract (M0)

- meta-only baseline NEVER claims L2.1 artifact hash pass — `unsupported` with sha512 evidence, `artifact_sha256` stays empty
- fetch errors are counted in the feed (`fetch_errors`), never silently dropped
- `unsupported != failed != pass` (dsh-testkit semantics)

