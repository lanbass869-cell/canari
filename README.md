# Canari

[![CI](https://github.com/lanbass869-cell/canari/actions/workflows/ci.yml/badge.svg)](https://github.com/lanbass869-cell/canari/actions/workflows/ci.yml)
![tests](https://img.shields.io/badge/tests-357%20passing-brightgreen)
![coverage](https://img.shields.io/badge/coverage-90%25%20line%20%7C%2083%25%20branch-brightgreen)
![mutation](https://img.shields.io/badge/mutation%20kill-100%25%20(52%20mutants)-brightgreen)
![release](https://img.shields.io/github/v/release/lanbass869-cell/canari)

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

## Install

From the latest GitHub release (wheel + sdist, checksum + Ed25519 signed):

```
pip install https://github.com/lanbass869-cell/canari/releases/download/v0.1.0/canari_mcp-0.1.0-py3-none-any.whl
canari-gate --store out --list
```

Then verify what you downloaded (see `docs/release-process.md` for the one-liner).

## Quality gates (enforced in CI)

| Gate | Threshold | Current |
|---|---|---|
| tests | green on 3.10/3.12/3.13 | 357 passing |
| line coverage | >= 85% | 90% |
| mutation kill rate | >= 90% (equivalent mutants excluded) | 100% (50/50) |
| live-data audit | sampled attestations re-derive from npm/PyPI | 18/18 |

Run them yourself: `python scripts/quality_gate.py`

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
      "command": "canari-mcp",
      "args": ["--store", "E:/Temp/tbdig/canari/out",
               "--key", "E:/Temp/tbdig/canari/out/public_key.json"]
    }
  }
}
```

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
        command: 'E:\Temp\tbdig\_venv_pr_a\Scripts\python.exe'
        args: ['-m', 'canari.mcp_server', '--store', 'E:\Temp\tbdig\canari\out',
               '--key', 'E:\Temp\tbdig\canari\out\public_key.json']
        cwd: 'E:\Temp\tbdig\canari'
        failOnStartupError: true
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
