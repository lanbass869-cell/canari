# Canari Deep Competitive Research Report (2026-11-08 v2)

> arXiv paper survey + GitHub ecosystem scan + DSH API probing + npm/PyPI sizing.
> 15+ arXiv papers, 20+ GitHub repos, 3 registry APIs.

## 1. CRITICAL: The claimed gap is PARTIALLY closed

### 1.1 89-Day MCP Drift Measurement (arXiv 2608.00997)

Gautam Bharti, 2026-08-20. 88.6 days, 120 observations, 19,099 servers. Found: 3/4 never change, top 5% generate 61% of changes, 11.9% change in 30 days. Recommends content-binding + periodic sweep.

Impact: DID the longitudinal measurement Canari claims. No signing, no attestation, no cross-registry.

Verdict: Measurement is TAKEN. Canari = ACTIONABLE layer (signed portable attestations).

### 1.2 Same Name Different Server (arXiv 2609.14119)

Obada Kraishan et al. 21,643 servers, 72,606 versions, 14,353 scanned. 51.1% drift, 40.6% silent, 4.2% redirect. Silent drift = 2.96x high-severity odds.

Impact: DID the security census. No signing, no attestation format.

### 1.3 Tool Update Gap (arXiv 2611.01976) -- STRENGTHENS CANARI

Shiyu Kan et al., SJTU + Inria. 2026-11-01. ETUDE attack: 97.6% ASR across 7 frameworks. Proves tool update gap is real.

Verdict: STRENGTHENS Canari. Defines the problem Canari solves.

### 1.4 Attested Tool-Server Admission (arXiv 2605.24248) -- CLOSEST

Alfredo Metere, 2026-05-22. Offline-signed clearance assertion, well-known URI, pinned trust root, allowlist, audit log, RFC 2119 spec.

Does NOT: weekly re-scan, cross-registry, supersession, failure audit.

Verdict: Same signing tech, different scope (admission vs temporal). Complementary.

### 1.5 After the Party: OpenClaw Skills (arXiv 2609.17274)

Yunpeng Xiong, Ting Zhang. Measured OpenClaw skill registry. Top 10% got 46.93% downloads. 77.86% zero stars. Three scanners disagreed on 23,702/61,990 skills. Sensitivity 21.67-61.06%.

Impact: PROVES scanner disagreement. Strengthens Canari.

### 1.6 mcp-notify (GitHub, 32 stars)

nirholas/mcp-notify. Monitors MCP Registry for changes. Smart diffing. Notifications. No signing. No attestation. No security verdicts. No cross-registry.

Verdict: Change-notification tool. Complementary.

## 2. Papers Proving the Problem

| Paper | Date | Proves |
|---|---|---|
| 2611.01976 Tool Update Gap | 2026-11-01 | 97.6% ASR, 7 frameworks |
| 2609.14119 Same Name | 2026-09 | 51.1% drift |
| 2608.00997 89-Day Drift | 2026-08 | 11.9% change in 30d |
| 2603.15727 AgentWorm | 2026-03 | Self-propagating attacks |
| 2607.25619 SkillGate | 2026-07 | Runtime detection |
| 2609.39352 Hiding in Plain Sight | 2026-09 | Skill poisoning |
| 2610.11169 Skill Constellations | 2026-10 | 2.2M adoptions, no updates |
| 2609.36879 SKILLLITE | 2026-09 | Scanner sensitivity 21-61% |

## 3. Competing Papers

| Paper | Overlap | Their gap |
|---|---|---|
| 2608.00997 89-Day | HIGH | No signing, no cross-registry |
| 2609.14119 Same Name | HIGH | No attestation format |
| 2605.24248 Admission | HIGH | No temporal monitoring |
| 2609.02690 ACLE-MCP | MED | Hardware-only |
| 2608.30387 Delegation | MED | Multi-agent only |
| 2608.14074 Mandato | MED | Mandates only |

## 4. Ecosystem Size

| Registry | Count |
|---|---|
| npm MCP | ~3-5K unique |
| PyPI MCP | 6,854 |
| MCP Registry | ~19-22K |
| DSH | 10,183 |
| Total | ~39-43K |

## 5. DSH Coverage

Sampled 30: 26/30 (87%) have L5 install certs. All passed. One author (uckkk) has 1,269 plugins (12.5% spam signal).

## 6. Honest Assessment

Has: signed attestation, offline verify, supersession, bi-temporal, weekly scan, drift comparison, cross-registry feed, install gate, failure audit, two-tier scanning.

Does NOT have: vulnerability detection, runtime monitoring, identity system, community contribution, 89-day dataset, RFC spec, institutional backing, users.

Canari is 300 lines of core code. The gap is narrowing: 89-day paper, attested admission, mcp-notify all appeared in last 4 months.

## 7. Differentiation

Canari MUST compete on: signed portable conclusions + temporal history + cross-registry + install gate. NOT scanning depth.

## 8. Critical Citation: 2605.24248

Metere defines admission control (is tool allowed). Canari defines temporal monitoring (has tool changed). Complementary layers.

## 9. Actions

This week: rewrite paper pitch (not "first to measure" but "first to make actionable"). Contact Bharti and Metere.

2-4 weeks: sentinel adapter, DSH full coverage, measurement paper.

1-2 months: arXiv preprint, NLnet (2027-01-03), open dataset.
