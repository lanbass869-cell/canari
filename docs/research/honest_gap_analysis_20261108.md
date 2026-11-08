# Canari vs Competitors: Honest Gap Analysis (2026-11-08)

> After multi-registry scan completed (294 attestations: npm 100 + PyPI 94 + MCP Registry 100).
> All competitor READMEs downloaded and analyzed. This is the honest assessment.

## Scan Results

| Registry | Count | Verdicts |
|---|---|---|
| npm | 100 | 99 pass, 1 error |
| PyPI | 94 | 94 pass |
| MCP Registry | 100 | 100 pass-with-findings |
| Total | 294 | 191 pass, 100 pass-with-findings, 2 fail, 1 error |

Schema integrity: 99.6%. Zero hidden errors.

## Gap 1: Scan depth = 0 vs competitors 71 vulnerability patterns

NVIDIA SkillSpector has 71 vulnerability patterns, 0-100 risk scoring, LLM semantic analysis, OSV.dev CVE queries, SARIF output.

Canari has: L1.1_REGISTRY_PRESENT + L2.1_ARTIFACT_HASH.

Canari L1-L2 metadata checks = SkillSpector 0/71 vulnerability patterns. We cannot even detect "does this package have install scripts."

Fix: integrate sentinel audit-install as first L3 scanner adapter. Not self-built - sentinel already has stable JSON output + exit codes + 51 rules. Canari calls it + parses results + signs.

## Gap 2: No runtime monitoring = agentseal has 225 attack probes

agentseal (382 stars) has MCP tool poisoning probes, RAG poisoning probes, multimodal attack probes, behavioral genome mapping, PDF reports.

Canari: zero runtime behavior detection.

But: runtime monitoring is a different product. Canari is a supply chain ledger, not an IDS. Plan section 2.2 explicitly excludes this.

## Gap 3: No identity system = Attestix has full DID/VC

Attestix (685 stars) has DID documents, Verifiable Credentials, UCAN delegation, hash-chained audit, SSRF protection, AES-256-GCM key storage, MCP server integration.

Canari: only ed25519 signing + simple hash chain.

But: Attestix does agent identity ("who am I"), Canari does component verification ("is this package safe"). Different trust domains. Can coexist.

## Gap 4: No community scan contribution = ai-trust has community model

opena2a ai-trust (4 stars): community members submit scan results, trust graph aggregates, 0-100 trust score.

Canari: only self-scan self-store. No community contribution.

But: community contribution needs users. Canari is M1, users = 0.

## Gap 5: No real dashboard

agentseal: PDF reports + dashboard. Canari: 100-line HTML with FileReader.

## What Canari Has That Competitors Do Not

| Capability | SkillSpector | Aguara | Attestix | ai-trust | agentseal | Canari |
|---|---|---|---|---|---|---|
| Signed attestation (DSSE/ed25519) | No | No | Yes | No | No | Yes |
| Offline verification | No | No | Yes | No | No | Yes |
| Supersession chain | No | No | No | No | No | Yes |
| Bi-temporal (T/T-prime) | No | No | No | No | No | Yes |
| Weekly auto scan (Task Scheduler) | No | No | No | No | No | Yes |
| Drift comparison | No | No | No | No | No | Yes |
| Same-source revocation propagation | No | No | No | No | No | Yes (framework) |
| Failure audit (public error counts) | No | No | No | No | No | Yes |
| Cross-registry unified feed | No | No | No | No | No | Yes |
| Install gate (verdict to ALLOW/BLOCK) | No | No | No | No | No | Yes |
| Deep scan (vulnerability patterns) | Yes | Yes | No | Yes | Yes | No (reference) |
| Runtime monitoring | No | No | No | No | Yes | No |
| DID/VC identity | No | No | Yes | No | No | No |
| Community scan contribution | No | No | No | Yes | No | No |

## Honest Position

Canari is a 300-line core code ledger skeleton, not a product.

Has: format definition, signing/verification, state management, pipeline infrastructure, 4 registry metadata collection.

Does not have: any real security detection capability, runtime monitoring, identity system, community mechanism, actual users.

If SkillSpector adds weekly auto-scan + DSSE signing + local ledger tomorrow, Canari is done. NVIDIA has 24K stars, unlimited resources, and already has OSV.dev integration.

Survival strategy: accumulate longitudinal data before NVIDIA does ledgers, submit NLnet, publish arXiv preprint. Data has a moat (time is irreversible), code does not.

## Priority Actions

1. P0: arXiv preprint (measurement paper outline) - only anti-collision defense
2. P0: NLnet application (2027-01-03 deadline)
3. P1: Integrate sentinel audit-install as L3 scanner adapter
4. P1: Open dataset (machine-readable JSON, CC-BY-4.0)
5. P2: Real dashboard (drift curve visualization)
6. P3: Community contribution API (after getting users)
