# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in Canari (the verification tool itself),
please open a private GitHub security advisory at:
https://github.com/lanbass869-cell/canari/security/advisories/new

Do NOT open a public issue for security vulnerabilities.

## Scope

- The `canari` Python package (schema validation, signing, CLI)
- The weekly scan pipeline
- The attestation format

## What is NOT in scope

- Vulnerabilities in scanned components (report those to the component author
  or via the component registry)
- False positives/negatives in scan verdicts (these are risk signals, not guarantees)

## Trust Scope

Canari attestations answer: "what did the scanner observe at time T about artifact hash H?"

They do NOT answer: "is this component safe to install?" — that requires
human judgment informed by the evidence, not a binary yes/no from an automated tool.
