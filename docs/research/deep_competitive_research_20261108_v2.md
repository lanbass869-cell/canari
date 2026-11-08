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
