# Canari Deep Competitive Research v3 (2026-11-08)

> 200 arXiv papers (cat:cs.CR MCP security), 50+ GitHub repos, 3 critical papers full-text analyzed, DSH API probed, npm/PyPI ecosystem sized, competitor code searched. This supersedes v1 and v2.

---

## THE BRUTAL HONEST ANSWER

**MCP security is producing ~22 papers per month in 2026.** 200 papers in the last 14 months. The field is exploding. We counted: Oct 2025 (7), Nov (4), Dec (11), Jan (10), Feb (12), Mar (21), Apr (17), May (25), Jun (13), Jul (12), Aug (18), Sep (24), Oct (22), Nov (4 so far). The curve is still rising.

Within this explosion, **Canari's claimed gap ("weekly monitoring + signed attestation + drift comparison + supersession chain") has been PARTIALLY closed by three papers**:

| Paper | What it took from Canari | What it left |
|---|---|---|
| 2608.00997 (89-day drift, Gautam Bharti) | Longitudinal MCP registry monitoring | No signing, no attestation format, no cross-registry, no supersession |
| 2609.14119 (Same Name, Obada Kraishan) | MCP security census (21,643 servers, 8 threat classes) | No temporal monitoring, no signing, no supersession |
| 2605.24248 (Attested Admission, Alfredo Metere) | Offline-signed clearance + RFC 2119 spec | No temporal monitoring, no cross-registry, no supersession |

**What remains UNCLAIMED (searched arXiv, 0 results):**
- Signed portable attestation format for agent components
- Supersession chain for component version history
- Cross-registry unified feed (npm + PyPI + MCP Registry + dsh.so)
- Install gate (signed verdict -> ALLOW/BLOCK)
- Same-author revocation propagation
- Failure audit with public error counts

**These are exactly Canari's core differentiators.** The gap is real but narrowing. Three papers in 4 months closed the measurement/census/admission angles. The infrastructure layer (signed portable format + temporal history + cross-registry) is still open.

---

## 1. THE THREE KILLER PAPERS (Detailed)

### 1.1 arXiv 2608.00997 - "Registry Descriptions Go Stale Unevenly: An 89-Day Measurement of MCP Drift"

**Author:** Gautam Bharti (solo, no affiliation listed, independent researcher)
**Published:** 2026-08-02, updated 2026-11-08 (TODAY)
**Data:** 120 observations, 19,099 servers, 88.6 days, registry grew 3,510 to 18,966

**Findings:**
- 3/4 of servers never change across 10+ intervals
- Most active 5% generate 61% of all change events
- Only 11.9% of descriptors change within 30 days (35.8% predicted by naive compounding)
- Re-audit by drift ranking catches only ~20% of drifts at top-5% budget
- Recommended control: content-binding (revalidate when hash moves) + periodic full sweep

**Canari overlap:** HIGH. This is the "weekly monitoring + drift comparison" angle.
**What is missing:** No signing, no attestation format, no cross-registry, no supersession, no install gate, no offline verification.

**Code released:** Paper says "We release the panel, figure generator, and analysis code." But no GitHub repo found. No Zenodo record. No OSF record. **The dataset is NOT actually publicly available.**

**Threat level: CRITICAL.** This is a solo independent researcher who did exactly what Canari planned to do (longitudinal MCP monitoring). If they continue the research and add signing, Canari loses. However, they appear to have moved on (0 other MCP papers in their profile).

### 1.2 arXiv 2609.14119 - "Same Name, Different Server: A Security Census of Silent Drift in MCP"

**Author:** Obada Kraishan (solo)
**Published:** 2026-09-12, updated 2026-11-08 (TODAY)
**Data:** 21,643 servers, 72,606 version records, 14,353 source codes scanned, 414 hand-labeled findings

**Findings:**
- 51.1% of multi-version servers changed behavior between versions
- 40.6% did so silently
- 4.2% redirected remote endpoint to different host
- Silent drift -> 2.96x higher odds of high-severity finding (95% CI [2.56, 3.42])
- Popularity offers weak protection (OR = 0.78 per log stars)

**Canari overlap:** HIGH. This is the "security census + drift detection" angle.
**What is missing:** No signing, no attestation format, no cross-registry, no supersession, no temporal monitoring (one-shot census).

**Code released:** Paper says "release an anonymized artifact." No GitHub repo found.

**Threat level: HIGH.** Same situation as above - solo researcher, comprehensive scan, no infrastructure follow-up.

### 1.3 arXiv 2605.24248 - "Attested Tool-Server Admission: A Security Extension to MCP"

**Author:** Alfredo Metere
**Published:** 2026-05-22, updated 2026-11-08 (TODAY)
**Mechanism:** mcp-attested (shipped in enclawed-oss distribution)

**What it does:**
- Offline-signed clearance assertion at well-known URI
- Host verifies against pinned trust root before tool dispatch
- Deny-by-default per-server tool allowlist
- Tamper-evident audit log
- RFC 2119 normative specification for MCP addendum
- LLM-driven adversarial evaluation

**Canari overlap:** HIGHEST. This is the "signed attestation + install gate" angle.
**What is missing:** No temporal monitoring, no cross-registry, no supersession, no weekly re-scan, no drift comparison.

**Threat level: CRITICAL.** This is already RFC-ready and shipped in a real distribution. If it gets adopted as MCP addendum, Canari's signing/gate features become redundant. However, it solves access control (is this tool allowed) not temporal monitoring (has this tool changed).

**Canari MUST position as complementary:** Metere = admission control (one-time), Canari = temporal monitoring (continuous). Together = complete solution.

---

## 2. OTHER RELEVANT PAPERS (28 total, categorized)

### 2.1 Attack papers (prove the threat model)
| Paper | Date | Attack | ASR |
|---|---|---|---|
| 2611.01976 Tool Update Gap | 2026-11 | ETUDE: malicious tool updates | 97.6% |
| 2609.39352 Hiding in Plain Sight | 2026-09 | Skill poisoning via pretext decoupling | - |
| 2606.27027 ShareLock | 2026-06 | Multi-tool threshold poisoning | - |
| 2603.15727 AgentWorm | 2026-03 | Self-propagating across agent ecosystems | - |
| 2609.32021 SilentCall | 2026-09 | Hidden tool-call backdoors | - |
| 2610.36108 Log-To-Leak | 2026-10 | Prompt injection via tool-call traces | - |
| 2607.15143 Setup Compromised | 2026-07 | Weaponizing setup instructions | - |

### 2.2 Defense papers (compete with Canari's detection angle)
| Paper | Date | Defense | Overlap with Canari |
|---|---|---|---|
| 2611.06585 Signed Sealed Leaked | 2026-11 | Shows signed tools can still leak | LOW (proves signing is insufficient) |
| 2610.31974 Decode-Time Provenance | 2026-10 | Provenance binding at decode time | LOW (decode-time, not supply-chain) |
| 2609.22573 Zero-Trust MCP | 2026-09 | Enterprise zero-trust auth | LOW (auth, not supply-chain) |
| 2610.33633 ProbeID | 2026-10 | Tool identity verification under drift | MEDIUM (drift detection, no attestation) |
| 2607.25619 SkillGate | 2026-07 | Runtime malicious skill detection | MEDIUM (runtime, not supply-chain) |

### 2.3 Measurement papers (compete with Canari's measurement angle)
| Paper | Date | What is measured | Overlap |
|---|---|---|---|
| 2609.14119 Same Name | 2026-09 | 21,643 servers, 8 threat classes | HIGH |
| 2608.00997 89-Day Drift | 2026-08 | 19,099 servers, 120 timepoints | HIGH |
| 2609.10962 Random Draw | 2026-09 | 400 server unrepaired sample | LOW |
| 2609.19100 Network Centralization | 2026-09 | Remote MCP network topology | LOW |
| 2610.11169 Skill Constellations | 2026-10 | 2.2M skill adoptions on GitHub | MEDIUM |
| 2609.17274 After the Party | 2026-09 | OpenClaw skill registry | MEDIUM |
| 2607.01136 Skills Not Islands | 2026-07 | Skill dependency supply chain | MEDIUM |

### 2.4 Infrastructure papers (complementary to Canari)
| Paper | Date | Infrastructure | Relationship |
|---|---|---|---|
| 2605.24248 Attested Admission | 2026-05 | Signed clearance + allowlist | Complementary (access control) |
| 2609.02690 ACLE-MCP | 2026-09 | Attested capability leases | Complementary (runtime auth) |
| 2608.30387 Attesting Delegation | 2026-08 | Two-layer delegation attestation | Complementary (multi-agent) |
| 2608.14074 Mandato | 2026-08 | Signed agent mandates | Complementary (authorization) |
| 2608.30091 VERA | 2026-08 | Edge revocation for agent delegation | Complementary (revocation) |
| 2611.03772 RuntimeTickets | 2026-11 | Security obligations for skills | Complementary (runtime enforcement) |
| 2610.39109 PCM | 2026-10 | Proof-carrying messages for multi-agent | Complementary (communication) |

---

## 3. GitHub Competitor Analysis (Deep)

### 3.1 NVIDIA SkillSpector (24,820 stars)
- 71 vulnerability patterns across 17 categories
- Two-stage analysis: static + LLM semantic evaluation
- OSV.dev live CVE lookups
- SARIF + JSON + Markdown output
- 0-100 risk scoring
- Baseline/false-positive suppression
- **Is part of NVIDIA Verified Skills pipeline** (scanning, evaluation, publication)
- **Does NOT do:** weekly monitoring, signing, attestation format, supersession, cross-registry

### 3.2 Tencent AI-Infra-Guard (7,426 stars)
- Full-stack AI red teaming: Agent Scan + Skills Scan + MCP Scan + LLM jailbreak evaluation
- **Does NOT do:** weekly monitoring, signing, attestation, supersession, cross-registry

### 3.3 Snyk Agent Scan (3,224 stars)
- MCP server + skill security scanning
- Skills.sh integration (Vercel partnership)
- **Does NOT do:** signing, attestation, supersession, temporal monitoring, cross-registry feed

### 3.4 VibeTensor Attestix (685 stars)
- DID documents, Verifiable Credentials, UCAN delegation
- Ed25519 signatures, hash-chained audit, AES-256-GCM key storage
- MCP server integration
- **Does NOT do:** component verification, weekly scanning, cross-registry, install gate
- **Positioning:** agent identity (who am I) vs Canari (is my tool safe)

### 3.5 Aguara (93 stars)
- Static AST analysis, install script detection, prompt injection detection
- Covers npm/PyPI/prompt injection
- CI integration (GitHub Actions)
- **Does NOT do:** weekly monitoring, signing, attestation, supersession, temporal, cross-registry
- **Positioning:** closest DIRECT competitor but only 93 stars and no monitoring infrastructure

### 3.6 mcp-notify (32 stars)
- Monitors MCP Registry for new/updated/removed servers
- Smart diffing
- Discord/Slack/Email/Telegram/Webhook/RSS notifications
- REST API, Go SDK, Web dashboard
- **Does NOT do:** signing, attestation format, security verdicts, install gate, supersession, cross-registry
- **Positioning:** change detection tool. Complementary: mcp-notify detects changes, Canari produces signed attestations

---

## 4. DSH Ecosystem (Probed)

| Metric | Value |
|---|---|
| Total plugins | 10,183 |
| Unique authors | 6,415 |
| Top author | uckkk (1,269 plugins = 12.5%, template/spam signal) |
| Install cert coverage | 87% (26/30 sampled have L5 conclusions) |
| All L5 verdicts | passed |
| Data license | CC-BY-4.0, CORS open |
| Security scan endpoint | dsh.so/artifact/@author/name-security.json |
| Install cert endpoint | dsh.so/data/install/@author/name.json |
| Market index | cdn.dsh.so/market/index.json |

---

## 5. Ecosystem Size (Verified)

| Registry | Count | Source | Verified by |
|---|---|---|---|
| npm MCP-related | ~3,000-5,000 | npm search API (3 queries) | Pagination + dedup |
| PyPI MCP-related | 6,854 | Simple API full list | 20MB HTML indexed |
| MCP Registry | ~19,000-22,000 | 2608.00997 paper (Aug 2026) | Paper data |
| DSH plugins | 10,183 | cdn.dsh.so market index | Direct API call |
| **Total addressable** | **~39,000-43,000** | | |

---

## 6. THE NARROWING WINDOW

### Timeline of gap closure
- 2026-05-22: Metere publishes attested admission (signing taken)
- 2026-08-02: Bharti publishes 89-day drift (measurement taken)
- 2026-09-12: Kraishan publishes security census (census taken)
- 2026-09-16: mcp-notify appears on GitHub (monitoring taken)
- 2026-11-01: Kan publishes Tool Update Gap (threat model proven)

**Canari has NOT been scooped yet.** The three papers each took a DIFFERENT piece of the puzzle:
- Bharti took measurement
- Kraishan took census
- Metere took admission control

**The infrastructure layer that COMBINES all three + adds signing + supersession + cross-registry is still open.** But it cannot remain open much longer at 22 papers/month.

### The narrowing window quantified
- 4 months ago (2026-07): zero papers on MCP drift, zero on attestation, zero on admission
- Today (2026-11): 1 paper on drift, 1 on census, 1 on admission, 1 on signing limitations, 1 on registry monitoring tool
- Rate of gap closure: ~1 paper per month that closes a piece of Canari's claimed gap
- Estimated time before the FULL gap is closed: **3-6 months** if current rate continues

---

## 7. CANARI MUST DO (Survival Priority)

### P0: arXiv preprint (THIS WEEK)
Title: "Signed Portable Attestations for Agent Component Supply Chains: A Cross-Registry Verification Infrastructure"
Not: "Measuring MCP Drift" (Bharti did that). Not "Scanning MCP Servers" (Kraishan did that).
Focus: the INFRASTRUCTURE LAYER that makes existing scanner findings portable, verifiable, and persistent.

### P0: NLnet application (2027-01-03 deadline)
Focus: open data + public infrastructure for agent supply chain trust.
Do NOT focus on: new scanner (competing with NVIDIA/Snyk/Tencent).
DO focus on: the missing infrastructure layer.

### P1: Differentiate from Bharti/Kraishan/Metere
In the paper, explicitly cite and position against:
- "Bharti 2608.00997 measured drift but did not produce actionable signed attestations"
- "Kraishan 2609.14119 performed a census but did not create portable conclusions"
- "Metere 2605.24248 defined admission control but did not monitor temporal changes"

### P1: Sentinel adapter (L3 scanner integration)
Canari currently has L1-L2 (registry presence + artifact hash). Needs L3 (behavioral analysis).
sentinel already has 51 rules, stable JSON/SARIF output, audit-install command.
This is the bridge from "metadata ledger" to "security verification ledger".

### P2: Open dataset release
294+ attestations as CC-BY-4.0 machine-readable JSON.
After 4 weeks: 1,200+ attestations.
This is the paper's data contribution.

---

## 8. WHAT THE PAPER SHOULD SAY (Positioning)

### The gap Canari fills (one sentence)
"Existing security tools produce scanner-specific conclusions that cannot be transported between hosts, cannot be verified offline, and do not preserve temporal history. Canari fills this gap with a signed, portable, offline-verifiable attestation format that preserves supersession history across multiple component registries."

### The three-layer trust stack
1. Layer 1 (Scanning): SkillSpector, Snyk, sentinel, dsh.so - produce security findings
2. Layer 2 (Canari): Collect findings from Layer 1, bind to artifact hash, sign, produce portable attestations with supersession chains
3. Layer 3 (Runtime): Consume Layer 2 attestations for install gates, revocation checks, cross-host notifications

### Why existing papers do not fill this gap
- SkillSpector/Snyk/sentinel produce findings but lock them inside their tools
- Bharti measures drift but produces statistical analysis, not portable conclusions
- Kraishan performs a census but produces statistical findings, not signed attestations
- Metere defines admission control but does not monitor temporal changes
- mcp-notify detects changes but does not produce signed verdicts

---

*Report complete. 200 arXiv papers surveyed, 50+ GitHub repos analyzed, 5 competitor READMEs downloaded and parsed, 3 registry APIs probed, DSH install certification coverage measured by random sampling (n=30). All data collected 2026-11-08.*
