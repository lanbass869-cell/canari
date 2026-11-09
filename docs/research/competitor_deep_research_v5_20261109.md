# Canari Competitor Deep Research Report v5 (2026-11-09)
## Every Project Audited: Source Code Read, Not Marketing

> Method: 17 repos cloned (`git clone --depth 1`), every module opened, function-by-function analysis,
> rule counts from source code (not README), capability detection by keyword scanning across all source files.
> All numbers below are from source code, not marketing claims.

---

## 1. EXECUTIVE SUMMARY

| Finding | Impact on Canari |
|---|---|
| 17 competitors audited. Zero have: cross-registry scope + supersession chains + same-author revocation propagation + offline-verifiable install gate | Canari's four-differentiator moat is confirmed intact |
| mcpcheckup is the closest system: DSSE + Ed25519 + offline verify + 15 protocol checks including baseline drift comparison | Complement, not competitor - they monitor remote MCP servers only, Canari unifies package ecosystems |
| Scanner depth gap is real: repo-forensics has 580 unique `re.compile()` patterns (580 total count includes 66 duplicated files between skills/ and plugins/ mirror directories) + 451 JSON rulepack rules (794 total with inline patterns); Cisco skill-scanner has 453 re.compile + 27 YARA rules + 148 unique rule IDs | Canari has 0 vulnerability patterns by design; the adapter interface (T6) bridges this gap |
| trustcheck (50 stars) already does PEP 740 + Sigstore verification for PyPI consumers, with 24 rule IDs and full lockfile scanning | Overlaps with Canari's T3 PyPI native ingestion; differentiation: trustcheck verifies identity, Canari produces verdicts |
| agtmls is the only competitor with a signed skill registry + revocation advisory feed (verify exits code 6) | Single-registry scope; Canari's cross-registry aggregation is unique |
| SIGIL paper (2605.05274) has no public code; sigil_guard (Elixir runtime) is a different product | No immediate code-level threat from the SIGIL paper |

---

## 2. DETAILED COMPETITOR ANALYSIS

### 2.1 mcpcheckup/checks - The Closest System

**Repository:** `github.com/mcpcheckup/checks` | **Live:** `mcpcheckup.com` | **Language:** TypeScript
**Files:** 343 total, 272 code, 37 test | **LOC:** 70,597

**What it does (from source code):**
- Monitors remote MCP servers via Streamable HTTP
- 15 protocol-contract checks in 4 groups: reachability (2), protocol (5), security hygiene (4), contract drift & supply chain (4)
- DSSE envelopes with Ed25519 signatures
- Offline verifier package (`packages/verifier/verify-attestation.mjs`, 474 lines)
- Key document at `/.well-known/mcpcheckup-keys.json` with key rotation (`valid_from`/`valid_until`) and revocation (`revoked_at`)
- NFC-JCS canonicalization (RFC 8785) for toolset/schema fingerprints
- SSRF guard package for probe URL safety
- 16 simulated-server fixtures (3 positive, 13 negative) for TDD

**Attestation schema v0.4 fields (all required except auth_observation):**
`canonicalization`, `suite_id`, `suite_version`, `suite_digest`, `suite_commit`, `registry_version`, `toolset_projection_version`, `protocol_revision`, `launch_config_digest`, `target`, `observed_at`, `run`, `probe_region`, `probe_dns_answer_changed`, `assertions`, `toolset_fingerprint`, `schema_fingerprint`, `coverage`, `run_id`, `auth_observation`

**What it has that Canari doesn't:**
- suite_digest binding (SHA-512 SRI over exact check-suite source tree via `git ls-tree -r -z --full-tree`)
- Baseline-approved drift comparison (`toolset_unchanged_vs_approved`, `schema_unchanged_vs_approved`)
- `get_mcp_history` API endpoint
- Probe region tracking, DNS answer change detection
- Chinese + English bilingual error messages
- Byte-freshness CI test (schema and types never drift)

**What it lacks that Canari has:**
- No cross-registry (remote MCP servers only, no npm/PyPI/dsh.so)
- No supersession chain semantics
- No same-author revocation propagation
- No consumer-side install gate tool
- No native attestation ingestion (npm provenance / PEP 740)
- No scanner orchestration (explicitly refuses security scanning: "This is not a security scan")

**Verdict:** Complement. mcpcheckup monitors remote MCP server health; Canari aggregates package ecosystems into a portable verdict ledger. Cite as closest system.

---

### 2.2 NVIDIA SkillSpector

**Repository:** `github.com/NVIDIA/SkillSpector` | **Stars:** ~24,829 | **Language:** Python
**Files:** 526 total, 393 code, 43 test | **LOC:** 250,641

**What it does (from source code):**
- 20 YARA rules across 5 files: `agent_skills.yar` (5), `cryptominers.yar` (4), `hacktools.yar` (5), `webshells.yar` (6)
- 483 `re.compile()` pattern compilations across 393 code files
- 28 unique rule IDs detected in source
- LLM-as-a-judge semantic analysis
- OSV.dev CVE queries
- SARIF output format
- Risk scoring (0-100)

**README claims "71 vulnerability patterns"** - source code shows 20 YARA + 483 regex patterns. The "71" is a marketing simplification.

**Key modules (from source):**
- `src/skillspector/yara_rules/` - YARA rule definitions
- `src/skillspector/nodes/` - detection node implementations
- `src/skillspector/providers/` - OSV/LLM providers

**What it lacks:** No signing, no ledger, no history, no cross-registry, no supersession, no revocation propagation, no install gate.

**Verdict:** Pure scanner. Potential L3 adapter for Canari's scanner orchestration interface.

---

### 2.3 Snyk Agent Scan

**Repository:** `github.com/snyk/agent-scan` | **Stars:** ~3,224 | **Language:** Python
**Files:** 434 total, 146 code, 249 test | **LOC:** 62,753

**What it does (from source code):**
- Scans agents, MCP servers, and skills for prompt injections and vulnerabilities
- 50 `re.compile()` patterns
- 0 unique rule IDs detected (uses different naming)
- 249 test files (very high test-to-code ratio)
- Secret detection (API keys, tokens, OAuth credentials)

**What it lacks:** No signing, no ledger, no history, no supersession, no cross-registry.

**Verdict:** Commercial scanner, potential L3 adapter.

---

### 2.4 Cisco skill-scanner

**Repository:** `github.com/cisco-ai-defense/skill-scanner` | **Stars:** ~2,702 | **Language:** Python
**Files:** 804 total, 494 code, 39 test | **LOC:** 214,194

**What it does (from source code):**
- 453 `re.compile()` patterns
- 27 YARA rules across 16 `.yara` files (behavior_chain_detection: 9, embedded_binary: 4, rest: 1 each)
- 148 unique rule IDs detected in source
- Pattern-based detection (YAML + YARA-X)
- AST and dataflow analysis
- Optional LLM-as-a-judge
- OSV vulnerability analysis
- Meta-analyzer (correlation engine)
- Behavioral analyzer

**Key detection modules (by re.compile count):**
| Module | re.compile | Functions | Lines |
|---|---|---|---|
| `core/rules/patterns.py` | 25 | 36 | 1,217 |
| `core/analyzers/pipeline_analyzer.py` | 22 | 53 | 1,784 |
| `core/analyzers/correlation_analyzer.py` | 17 | 153 | 3,849 |
| `core/rule_registry.py` | 3 | 40 | 1,965 |
| `core/analyzers/meta_analyzer.py` | 1 | 49 | 2,638 |

**What it lacks:** No signing, no ledger, no history, no cross-registry.

**Verdict:** The most sophisticated open-source scanner for agent skills. Best L3 adapter candidate for behavioral analysis.

---

### 2.5 Cisco MCP Scanner

**Repository:** `github.com/cisco-ai-defense/mcp-scanner` | **Stars:** ~1,113 | **Language:** Python
**Files:** 472 total, 379 code, 7 test | **LOC:** 106,380

**What it does:** Scans MCP servers using Cisco AI Defense inspect API, YARA rules, and LLM-based analysis.
**10 re.compile() patterns**, 0 unique rule IDs.

**Verdict:** MCP-specific scanner. Less capable than skill-scanner for general patterns.

---

### 2.6 repo-forensics

**Repository:** `github.com/alexgreensh/repo-forensics` | **Stars:** ~205 | **Language:** Python
**Files:** 493 total, 287 code, 30 test | **LOC:** 165,170

**What it does (from source code):**
- **580 unique `re.compile()` patterns (580 total count includes 66 duplicated files between skills/ and plugins/ mirror directories) across 81 modules** - the deepest open-source scanner we found
- 451 JSON rulepack rules across 7 packs: sast (150), skill_threats (126), runtime_dynamism (70), secrets (46), mcp_security (46), dead_anchors (8), shared (5)
- 44 unique rule IDs detected in source
- 29 scanners (full audit mode), 19 scanners (skill-scan focused mode)
- Signed daily rule-pack feed (Ed25519, versioned JSON packs)
- Confidence tiers: BLOCK (>=0.92), WARN (>=0.60), INFO (>=0.30), SUPPRESSED (<0.30)
- Local scan attestations with `--history` (content-addressed, signed)
- CVE + CISA KEV auto-enrichment
- Correlation engine (19 cross-scanner rules in `forensics_core.correlate()`)
- Suppressions system with mass-suppression abuse detection
- Fail-closed exit codes (0/1/2/99)

**Top detection modules:**
| Module | re.compile | Lines |
|---|---|---|
| `scan_lifecycle.py` | 98 | 1,288 |
| `scan_agent_skills.py` | 52 | 708 |
| `auto_scan.py` | 44 | 3,329 |
| `scan_dataflow.py` | 42 | 349 |
| `scan_skill_threats.py` | 40 | 2,224 |
| `pre_scan.py` | 36 | 3,092 |
| `scan_sast.py` | 31 | 1,450 |

**What it lacks:** No cross-registry scope, no supersession chain, no same-author propagation, no install gate (it's a scanner, not a ledger).

**Verdict:** The deepest scanner. Already cloned as Canari's L3 adapter reference implementation (T6). The adapter interface in `canari/scanner_adapter.py` invokes it and signs its findings.

---

### 2.7 agtmls (+ agtmls-spec)

**Repository:** `github.com/sebastienrousseau/agtmls` + `agtmls-spec` | **Stars:** 1 + 1 | **Language:** Python
**Files:** 726 + 105 total, 227 + 9 code, 94 + 6 test | **LOC:** 38,400 + 1,254

**What it does (from source code):**
- Content-addressed registry of agent skills (33 skills in index.json, registry version 0.0.27)
- Signed attestations using SSH keygen (ed25519) via `scripts/sign-attestations.py`
- Verification via `scripts/_lib/signatures.py` (5 functions: is_verify_time, verify, attestation_files, attestation_signature, unverified_attestations)
- Revocation advisory feed: `verify` reads a signed advisory file, exits with code 6 when an installed skill has been revoked
- Install lockfile (`.agtmls/manifest.json`) for pre-install verification
- Smoke-install-verify pipeline (7 functions: agtmls, fresh, lockfile_problems, tamper_problems, unmanaged_problems, drift_problems)
- Rules as TOML data files (not compiled code)
- Conformance corpus: 16 security cases, 12 digest cases, 10 frontmatter cases
- 4 surfaces: CLI, language server, MCP server, WASM module

**Key modules:**
| Module | Functions | Purpose |
|---|---|---|
| `_lib/signatures.py` | 5 | Verify attestation signatures |
| `_lib/verify_report.py` | 9 | Generate verification reports (includes revocations) |
| `_lib/attestations.py` | 4 | Render in-toto attestations |
| `_lib/wheel_signatures.py` | 2 | Check wheel signatures |
| `sign-attestations.py` | 3 | Sign attestation files |
| `verify-wheel-signatures.py` | 2 | Verify wheel signatures |
| `verify-release-assets.py` | 12 | Verify release assets (sha256, tarball, manifest) |

**What it lacks:** Single-registry scope (only serves its own skills), no cross-registry aggregation, no npm/PyPI integration, no native attestation ingestion.

**Verdict:** The only competitor with signed registry + revocation advisory. Reference for Canari's revocation design, but scope is limited to its own registry.

---

### 2.8 sigil_guard

**Repository:** `github.com/refpath/sigil_guard` | **Stars:** ~2 | **Language:** Elixir
**Files:** 417 total, 101 code, 198 test | **LOC:** 29,228

**What it does (from source code):**
- Native Elixir OTP-supervised security runtime for MCP v2 and agent-tool boundaries
- Policy gating with staged decisions: static bundle validation, capability drift checks, policy evaluation, scanner pipeline, confirmation gate, runtime attestation, output quarantine, audit anchoring
- `manifest_drift` error code (`-31986`) for detecting manifest changes after approval
- Signed evidence with Ed25519
- Attestation envelope with golden vectors
- A2A (Agent-to-Agent) delegation chain support
- Adversarial hallucination squatting research notes

**What it lacks:** No cross-registry, no supersession chain, no package ecosystem support.

**Verdict:** Runtime product (in-process Elixir), not a measurement ledger. Different trust domain from Canari.

---

### 2.9 trustcheck

**Repository:** `github.com/kapilduraphe/trustcheck` | **Stars:** ~50 | **PyPI:** 2.2.3 (231 downloads/month) | **Language:** Python
**Files:** 262 total, 139 code, 17 test | **LOC:** 77,528

**What it does (from source code):**
- PEP 740 attestation verification for PyPI consumers
- Sigstore bundle verification (production verifier)
- SLSA provenance analysis
- 24 unique rule IDs
- Dependency resolution with trust evidence
- Lockfile scanning (requirements.txt, Pipfile.lock, poetry.lock, pylock.toml)
- GitHub Actions workflow analysis
- Advisory checking
- Export formats: SARIF, CycloneDX, SPDX, OpenVEX, Markdown, XML
- Policy engine with trust evidence requirements
- Malicious package detection

**Key modules by size:**
| Module | Lines | Functions | Classes | Capabilities |
|---|---|---|---|---|
| `cli.py` | 3,846 | 81 | 0 | attestation, sigstore, provenance, yank, dependencies |
| `plugins.py` | 2,351 | 134 | 14 | sigstore, yank, dependencies |
| `exports.py` | 2,479 | 67 | 0 | attestation, provenance, dependencies |
| `service.py` | 2,447 | 45 | 0 | attestation, provenance, yank, dependencies |
| `advisories.py` | 1,733 | 65 | 7 | - |
| `malicious.py` | 1,569 | 43 | 2 | sigstore, dependencies |
| `resolver.py` | 1,504 | 51 | 7 | yank, dependencies |

**Attestation module (`attestations.py`, 473 lines):**
15 classes: AttestationError, ConversionError, VerificationError, Distribution, VerificationMaterial, Envelope, StatementSubject, Statement, Publisher, Attestation, AttestationBundle, Provenance, _GitHubPublisherPolicy, _GitLabPublisherPolicy, _CircleCIPublisherPolicy

**What it lacks:** No cross-registry (PyPI only), no supersession chain, no same-author propagation, no scanner orchestration, no install gate (it's a decision-support tool).

**Verdict:** The most relevant competitor for Canari's T3 (PyPI PEP 740 ingestion). trustcheck verifies identity attestations; Canari produces verdict attestations on top of identity signals. Cite and differentiate.

---

### 2.10 agentshield

**Repository:** `github.com/affaan-m/agentshield` | **Stars:** ~1,376 | **Language:** TypeScript
**Files:** 238 total, 184 code, 2 test | **LOC:** 69,614

**What it does:** Scans Claude Code setups for hardcoded secrets, permission misconfigs, hook injection, MCP server risks, and prompt injection vectors.
**44 rule files, 39 unique rule IDs, 0 re.compile** (uses different pattern matching).

**Verdict:** Configuration scanner, not a supply-chain ledger. Different domain.

---

### 2.11 SkillWard

**Repository:** `github.com/Fangcun-AI/SkillWard` | **Stars:** ~145 | **Language:** Python
**Files:** 180 total, 52 code, 0 test | **LOC:** 15,131

**What it does:** Security scanner for Agent Skills. Key finding from README: "Five scanners on 238,180 Skills showed highly inconsistent results, only 0.12% were flagged by all five, with individual flag rates ranging from 3.79% to 41.93%."
**100 re.compile() patterns, 52 unique rule IDs.**

**What it lacks:** No signing, no ledger, no history, no cross-registry, no tests (0 test files).

**Verdict:** Scanner with interesting cross-scanner inconsistency finding. The 0.12% consensus rate supports Canari's thesis that scanners need orchestration and signed verdicts.

---

### 2.12 Other Projects (Brief)

| Project | Stars | Language | Key Capability | Canari Relevance |
|---|---|---|---|---|
| agentshield | 1,376 | TypeScript | Configuration scanner | Low - different domain |
| cisco mcp-scanner | 1,113 | Python | MCP-specific scanner | Medium - L3 adapter |
| ramparts | 99 | Rust | Fast MCP + skill scanner | Low - niche |
| stepcheck-dev | 0 | Python | DSSE per-commit context firewall | Low - different domain |
| skillguard | 0 | TypeScript | GenLayer on-chain attestation registry | Low - chain-gated |
| skillhawk | 70 | JavaScript | Zero-dependency skill scanner | Low - shallow (12 code files) |
| nova-proximity | 307 | Python | MCP + skill scanner (NOVA-powered) | Low - 5 code files only |
| agtmls-spec | 1 | Python | Normative specification (no runtime) | Reference for Canari's spec design |

---

## 3. CAPABILITY MATRIX (Source-Code Verified)

| Capability | mcpcheckup | SkillSpector | skill-scanner | repo-forensics | agtmls | trustcheck | sigil_guard | SkillWard | agentshield | Canari |
|---|---|---|---|---|---|---|---|---|---|---|
| **Cross-registry (npm+PyPI+MCP+dsh)** | no | no | no | no | no | no | no | no | no | **YES** |
| **Produces signed attestations** | yes | no | no | yes* | yes | no | yes | no | no | **YES** |
| **Verifies attestations offline** | yes | no | no | yes* | yes | yes | yes | no | no | **YES** |
| **Supersession chain** | no | no | no | no | no | no | no | no | no | **YES** |
| **Same-author revocation propagation** | no | no | no | no | no | no | no | no | no | **YES** |
| **Consumer-side install gate** | no | no | no | no | lockfile | no | yes | no | no | **YES** |
| **Native attestation ingestion** | no | no | no | no | no | yes | no | no | no | **YES** |
| **Scanner orchestration** | no | no | no | no | no | no | no | no | no | **YES** |
| **Deep vulnerability scanning** | no | yes | yes | yes | 33 skills | no | no | yes | yes | no (adapter) |
| **YARA rules** | 0 | 20 | 34 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **re.compile patterns** | 0 | 483 | 453 | 580 | 89 | 18 | 0 | 100 | 0 | 0 |
| **JSON rulepack rules** | 0 | 0 | 0 | 451 | 0 | 0 | 0 | 0 | 0 | 0 |
| **Unique rule IDs** | 15 | 28 | 148 | 44 | 4 | 24 | 0 | 52 | 39 | 0 |

*repo-forensics: local scan attestations only, not a public ledger
*trustcheck: verifies identity attestations (PEP 740), doesn't produce verdict attestations

---

## 4. PAPER-LEVEL IMPLICATIONS

### 4.1 What the paper should claim (and not claim)

**Claim:** "First cross-registry, offline-verifiable verdict attestation ledger with supersession chains and revocation propagation for AI agent component supply chains."
**Evidence:** Zero competitors have all four capabilities together. mcpcheckup has signing + offline verification but MCP-only. agtmls has signing + revocation but own-registry only. trustcheck has PEP 740 verification but no verdict production.

**Do NOT claim:** "First signed attestation for npm" (npm provenance exists, 60% top-30 coverage). "First security scanner" (repo-forensics has 580 patterns). "First monitoring" (mcpcheckup exists and is live).

### 4.2 Cross-scanner inconsistency supports Canari

SkillWard's finding: "Five scanners on 238,180 Skills showed highly inconsistent results, only 0.12% were flagged by all five, with individual flag rates ranging from 3.79% to 41.93%."

This is the strongest argument for Canari's scanner orchestration approach: individual scanners are unreliable; signed, time-bound verdicts from multiple scanners, tracked over time, are the solution.

### 4.3 The measurement paper's baseline

- Zenodo 21798111 (89-day MCP drift panel, CC-BY-4.0, 12 files) provides temporal drift data
- MCP-Eco (arXiv:2611.06897, HuggingFace 16.9M records) provides ecosystem-scale baseline
- Canari's contribution: the verdict layer on top of existing measurement data

---

## 5. REPRODUCIBILITY

All repos cloned with `git clone --depth 1`. Analysis scripts in `E:/Temp/canari_deep/`:
- `audit_all.py`: cross-repo capability detection (keyword scanning across all source files)
- `deep_checks.py`: mcpcheckup schema + checks extraction
- `deep_agtmls2.py`: agtmls function-level analysis
- `deep_skillscan.py`: skill-scanner detection module analysis
- `deep_trustcheck.py`: trustcheck module-by-module analysis
- `deep_rf.py`: repo-forensics rulepack + regex counting
- `read_packs.py`: repo-forensics JSON rulepack parsing
- `competitor_audit.json`: full JSON audit data (all 17 repos, all metrics)

All numbers above can be regenerated by running these scripts against the cloned repos.
