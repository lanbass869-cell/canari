# Canari

Agent component verification ledger - signed, offline-verifiable, history-preserving attestations for MCP servers, agent skills, and DSH plugins.

Named after the canary in the coal mine: the first to detect that something went wrong.

## What it does

1. **Weekly scan** of agent component ecosystems (npm, PyPI, MCP Registry, dsh.so)
2. Each component gets a **signed attestation** (DSSE/in-toto, ed25519) binding: artifact hash + host version + scan scenario
3. Attestations are **offline-verifiable** by anyone with the public key
4. History is **never deleted** - version changes create supersession chains
5. Public **machine-readable feed** for any AI agent or host to consume
6. **Trust heuristics**: release cadence (L2.4), metadata anomaly (L2.5), typosquatting (L2.6)
7. **Consumer install gate** with policies: `canari-verify bundle.json --key pub.json --gate --gate-policy paranoid`

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

## Multi-registry coverage

| Registry | Source | What we check | What we inherit |
|---|---|---|---|
| npm | search API + packument + tarball sha256 | existence, version, artifact hash, maintainers | - |
| PyPI | Simple API + JSON API | same | - |
| MCP Registry | official REST | identity presence | - |
| dsh.so | JSON API | **reference existing L1-L5 conclusions** (not re-scanned) | dsh.so verdicts |

## Honest limitations

- This is a **risk signal, not a safety guarantee**
- M0/M1 covers meta-level checks (L1-L2); behavioral checks (L3+) are M1+
- Scan coverage is limited to what registries expose publicly
- `expires_at` is 7 days - attestations go stale, re-scan needed

## The threat model this addresses

postmark-mcp (MITRE ATLAS AML.CS0053): 15 clean versions, then one poisoned commit, ~300 orgs affected. After takedown, **no host was notified**. The gap: no longitudinal observation, no cross-host revocation feed, no portable verdict.

Canari fills that gap.

## License

Apache-2.0. See LICENSE and SECURITY.md.
