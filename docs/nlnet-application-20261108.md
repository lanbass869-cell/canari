# NLnet Foundation Application: Canari

## Project: Canari - Cross-Registry Verification Ledger for AI Agent Component Supply Chains

**Contact:** Canari contributors (GitHub: lanbass869-cell/canari)
**Requested amount:** EUR 5,000 (hosting, conference travel, dataset publication)
**Duration:** 6 months
**Category:** Internet Standards / Security & Privacy / Open Source

## 1. The Problem

AI agents (Claude Code, Codex CLI, Gemini CLI, and open-source frameworks) increasingly
install third-party components: MCP servers, agent skills, and plugins. Two attack
classes dominate this supply chain:

1. **Tool update gap** (arXiv:2611.01976): trust established for a tool does not remain
   valid after code updates. The ETUDE attack achieved a 97.6% success rate by embedding
   malicious functionality into updates of initially benign tools, bypassing all
   model-visible defenses.
2. **Silent drift** (arXiv:2609.14119): 51.1% of multi-version MCP servers changed what
   they advertise between versions, 40.6% silently, 4.2% redirected their endpoint to
   a different host under the same registry identity.

The ecosystem has identity attestations (Sigstore on npm, PEP 740 on PyPI) that prove
*who* built the code, and security scanners (NVIDIA SkillSpector, Cisco, Snyk,
repo-forensics) that enumerate *what patterns* the code contains. Between these two
layers, no existing system produces **signed, offline-verifiable verdicts** that are
portable across registries, linked into supersession chains, propagated through
same-author revocation, and consumable by a client-side install gate.

## 2. The Solution: Canari

Canari is an open-source verification ledger that fills this gap. It produces
DSSE/Ed25519 signed attestation objects that bind verdicts to artifact hashes, with:

- **Cross-registry scope**: npm, PyPI, MCP Registry, dsh.so (four adapters shipped)
- **Supersession chains**: append-only; old verdicts are never deleted
- **Same-author revocation propagation**: related components are annotated when
  a revocation occurs
- **Consumer-side install gate**: signed verdicts drive ALLOW/BLOCK decisions
- **Native attestation ingestion**: npm Sigstore provenance and PyPI PEP 740 are
  consumed as input signals (verified live against express@5.3.0)
- **Scanner orchestration**: external scanners (repo-forensics, 29 scanners) are
  invoked and their findings signed; Canari does not build its own scanner
- **Failure transparency**: error counts are published, not hidden

The system is ~2,700 lines of Python with 136 tests (135 passing, 1 skipped
pending live PyPI attestation coverage). It ships three metadata-only trust
heuristics (release cadence, metadata anomaly, typosquatting) with a
policy-configurable install gate. Code, schemas, and data are published as
open artifacts.

## 3. Why NLnet?

Canari is infrastructure for the open internet: it makes trust decisions about
open-source components auditable, portable, and independent of any single vendor.
The NLnet Foundation's mission of "an open internet for everyone" aligns with
Canari's goals of:

- **No vendor lock-in**: attestations are portable JSON files, verifiable offline
  with a public key
- **Open data**: all 294+ attestations are CC-BY-4.0
- **Open standards**: DSSE (IETF SCITT), in-toto, Sigstore, PEP 740
- **No accounts, no platform**: Canari is a CLI tool and a file format, not a
  hosted service

NLnet funding would cover: dataset hosting (Zenodo), conference presentation
(FOSDEM/ CCC), and development time for the remaining P1 features.

## 4. Deliverables

| # | Deliverable | Status | Timeline |
|---|---|---|---|
| 1 | Attestation schema v0.1 (DSSE/Ed25519) | DONE | - |
| 2 | Multi-registry adapters (npm/PyPI/MCP/dsh) | DONE | - |
| 3 | Weekly scan pipeline + Task Scheduler | DONE | - |
| 4 | Native provenance ingestion (npm + PyPI) | DONE | - |
| 5 | Scanner adapter interface (repo-forensics reference) | DONE | - |
| 6 | Dashboard with supersession chain view | DONE | - |
| 7 | arXiv paper draft | DONE | - |
| 8 | Open dataset release (Zenodo + GitHub) | TODO | Month 1 |
| 9 | MCP Registry full pagination (40K+ entries) | PARTIAL | cursor pagination works; dedupe by server name added; full-history crawl Month 1 |
| 10 | Install gate CLI (consumer-side) | DONE | `canari-verify --gate` with policy files |
| 11 | Multi-signer support | TODO | Month 3 |
| 12 | Transparency log for signer keys | TODO | Month 4 |
| 13 | Integration with dsh-testkit lifecycle testing | TODO | Month 5 |
| 14 | Paper submission to arXiv + venue | TODO | Month 5 |

## 5. Team

Canari is developed by an independent contributor. The project has no corporate
backing, no institutional affiliation, and no vendor relationships with any of
the registries it monitors. This independence is deliberate: a verification
ledger must not have incentives that conflict with its verdicts.

## 6. Budget

| Item | EUR |
|---|---|
| Development time (6 months part-time) | 3,000 |
| Dataset hosting (Zenodo) | 500 |
| Conference travel + registration | 1,000 |
| Domain + infrastructure | 500 |
| **Total** | **5,000** |

## 7. Impact

If funded, Canari will be the first open-source, cross-registry, offline-verifiable
verification ledger for AI agent components. The ecosystem currently has:

- mcpcheckup (remote MCP monitoring only, no cross-registry)
- SIGIL (on-chain, imposes chain infrastructure)
- agtmls (single skill registry, no cross-registry)
- Identity attestations (prove who built, not what it does)

Canari fills the verdict layer. Every AI agent user who installs an MCP server,
a skill, or a plugin benefits from having a portable, signed verdict they can
verify offline. The dataset of 294+ (and growing weekly) attestations is a
research contribution in itself: the first longitudinal, signed corpus of
agent component trust decisions.

## 8. References

1. Kan et al., "Beyond Prompt Injection: The Tool Update Gap in LLM Agent Security", arXiv:2611.01976
2. Kraishan, "Same Name, Different Server: A Security Census of Silent Drift in MCP", arXiv:2609.14119
3. Bharti, "Registry Descriptions Go Stale Unevenly: An 89-Day Measurement of MCP Drift", arXiv:2608.00997 (data: Zenodo 21798111)
4. Metere, "Attested Tool-Server Admission: A Security Extension to MCP", arXiv:2605.24248
5. Shen et al., "Sealing the Audit-Runtime Gap for LLM Skills (SIGIL)", arXiv:2605.05274
6. Canari code repository: github.com/lanbass869-cell/canari
7. Canari paper draft: paper/main.tex in the repository
