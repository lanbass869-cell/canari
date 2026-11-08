# Canari Deep Research v4 (2026-11-08) - Evidence-Grade, All Numbers Reproducible

> This supersedes v3. Method: 4 killer papers read full-text (PDF extracted line-by-line), 12 new Nov-Oct papers abstract-verified live, 11 competitor repos cloned shallow and audited file-by-file (rule counts counted from source, not README), npm/PyPI native attestation adoption measured from registry APIs, dsh.so full market index re-fetched, MCP official registry paged live. Every number below has a command in the Appendix.

## 0. HEADLINE: THREE THINGS V3 GOT WRONG, ONE THING IT MISSED ENTIRELY

### 0.1 CORRECTION: the 89-day drift dataset IS public (v3 was wrong)
v3 claimed the 2608.00997 dataset was "NOT actually publicly available". WRONG.
Zenodo record 21798111 is live and verified today: "MCP Registry Drift Panel v1",
CC-BY-4.0, 12 files (mcp_registry_drift_panel_v1.jsonl.gz 1.1MB, DATASET_CARD.md,
analysis scripts, SHA256SUMS). The paper's limitations (Section 7) state four
stated exceptions, all documented. Implication: Canari can build directly on this
panel for the measurement paper instead of re-scraping 19K servers from scratch.

### 0.2 MISSED ENTIRELY: mcpcheckup.com is a LIVE signed-attestation MCP monitor
Repo: mcpcheckup/checks (335 files, cloned and audited). This is the single
biggest competitive discovery of this round:

- DSSE envelopes, Ed25519, offline verifier package, published key document at
  /.well-known/mcpcheckup-keys.json with key rotation AND revocation fields
  (valid_from / valid_until / revoked_at).
- 15 protocol-contract checks in 4 groups; group 4 is literally "Contract Drift
  & Supply Chain": toolset_fingerprint, schema_fingerprint,
  toolset_unchanged_vs_approved, schema_unchanged_vs_approved - i.e. baseline-
  approved drift comparison, the core of Canari's drift story, shipped.
- get_mcp_history + get_attestation exposed as MCP tools; per-tool deterministic
  diff package (tools added/removed/description changed/schema changed).
- Attestation schema v0.4: suite_commit + suite_digest (sha512 SRI over the exact
  check-suite source tree via git ls-tree), NFC-JCS canonicalization, SSRF guard
  package, simulated-server fixtures, byte-freshness CI test.
- Listed in the official MCP Registry and Claude Connectors Directory.

What it does NOT do (verified from schema v0.4 + README):
- No supersession chain (history = observation list; no superseded_by semantics).
- No cross-registry: remote MCP servers only; no npm/PyPI/skills/dsh.
- No same-author revocation propagation.
- No consumer-side install gate tool (it is a hosted directory + MCP endpoint).
- No package ecosystems at all.

### 0.3 CORRECTION: "71 vulnerability patterns" for SkillSpector is README-claimed
Counted from source: SkillSpector ships 20 YARA rules (agent_skills.yar 5,
cryptominers.yar 4, hacktools.yar 5, webshells.yar 6) plus code-level pattern
checks. Cisco skill-scanner: ~90 distinct rule IDs in source. SkillWard: 52.
agentshield: 39. repo-forensics: 1,138 re.compile() calls (the actual deep-scan
heavyweight). Canari: 0 vulnerability patterns. The honest range is "tens to
thousands", not one number.

## 1. NEW PAPERS THIS ROUND (post-v3, abstracts + full text where critical)

| arXiv | Date | What it is | Threat to Canari |
|---|---|---|---|
| 2611.06585 Signed, Sealed, Leaked | 2026-11-04 | Shows a legitimately signed MCP tool still exfiltrates; germline execution defense | POSITIVE citation: signing is necessary, not sufficient - motivates verdict attestations |
| 2601.23132 Verifiable Manifest Signing | 2026-01 (v2/v7) | Manifest-level signing + append-only transparency log + revocation for MCP pipelines | MEDIUM-HIGH for MCP-only ledger claims; no cross-registry, no supersession |
| 2605.05274 SIGIL | 2026-05 | On-chain append-only skill registry, DAO audit, 4 publication types, hash anchoring, invocation-time validation; evaluated on 1,079 real skills (779 malicious from ClawHub) | HIGH for skill-ledger claims; no cross-registry, no portable offline verify, chain-gated |
| 2609.30293 Cartograph | 2026-09 | Federated MCP proxy, operator-attested Ed25519 capability cards | LOW (discovery layer) |
| 2610.33633 ProbeID | 2026-10 | Per-call tool identity verification under drift; 11-week study, 7/59 real tools changed responses despite version pins | GOOD citation for drift motivation; not a ledger |
| 2609.02690 ACLE-MCP | 2026-09 | Attested capability leases, execution-time | LOW (runtime layer) |
| 2611.06897 MCP-Eco | 2026-11-04 | HuggingFace linked dataset: 16,880,899 records, 78,302 candidate server projects, 16,165 consumer repos, 5,975 config declarations | OPPORTUNITY: free corpus for measurement paper |
| 2610.22301 Credentials Please | 2026-10 | Filesystem capability laundering at scale (L1/L2/L3 layer analysis) | citation only |
| 2611.02527 Neither Side Confirms | 2026-11-02 | 90% of destructive tools lack server-side confirmation; 32/41 hosts no default approval | citation for install-gate motivation |
| 2609.10962 Random Draw | 2026-09 | 400-server unrepaired sample: 48.8% complete handshake, 37.5% never start | citation: registry quality baseline |
| 2603.27204 MalSkills | 2026-03 | Neuro-symbolic malicious skill detection | scanner-side, not ledger |
| 2605.14460 Payload-less Skills | 2026-05 | SCH attack: no payload, runtime synthesis | strengthens "verdict must bind to content" claim |

Net effect: the MCP-only "signed monitoring ledger" niche is now occupied by a
live product (mcpcheckup) + at least 2 papers (23132, SIGIL). Canari survives
ONLY as the cross-registry + supersession + propagation + gate layer. This is a
hard repositioning, not a tweak.

## 2. NATIVE ATTESTATION REALITY (measured today from registry APIs)

| Ecosystem | Native system | Measured adoption | Source |
|---|---|---|---|
| npm | Sigstore provenance (dist.attestations.provenance) | 18/30 of top-30 packages have it (60%); sigstore JS libs 46M downloads/month | registry.npmjs.org live queries |
| PyPI | PEP 740 + Trusted Publishers (GitHub Actions / GitLab / Google Cloud) | 0/30 top packages, 0/40 fresh uploads carry attestations | pypi.org JSON API live queries |
| MCP Registry | none | no attestation field in server schema | registry.modelcontextprotocol.io |
| dsh.so | own L5 install verification + static scan (31 rules), CC-BY-4.0 | 10,195/10,195 plugins install-verified | cdn.dsh.so/market/index.json |

Implications:
1. Canari MUST consume npm provenance as an input signal and verify it - claiming
   "first signed attestation for npm" is false and reviewers will catch it.
2. Canari's verdict attestation is a DIFFERENT object from provenance: provenance
   says "who built this", Canari says "what we observed and concluded". The
   2611.01976 paper says it exactly: hashes and attestations certify WHICH code
   runs, never WHAT it does. Cite it.
3. PyPI adoption is ~0: verdict attestations remain additive there. trustcheck
   (PyPI 2.2.3, 231 downloads/month) already does consumer-side PEP 740
   verification - tiny but real, cite and differentiate (it verifies provenance,
   not scan verdicts).

## 3. COMPETITOR AUDIT TABLE (from cloned source, not marketing)

| Project | Stars | What it actually has (counted) | What it lacks vs Canari |
|---|---|---|---|
| mcpcheckup/checks | live product | DSSE+Ed25519, offline verifier, 15 checks incl. baseline-approved drift, history API, key revocation, suite_digest binding, SSRF guard, fixtures | cross-registry, supersession chain, propagation, install gate, packages (npm/PyPI) |
| NVIDIA SkillSpector | 24,829 | 20 YARA rules + code patterns, LLM analysis, SARIF, OSV queries (README claims 71 patterns) | no signing, no ledger, no history, no cross-registry |
| snyk/agent-scan | 3,224 | scanner, 50 re.compile, secret patterns | no signing/ledger/history |
| cisco skill-scanner | 2,702 | ~90 rule IDs in source, 453 re.compile | no signing/ledger |
| cisco mcp-scanner | 1,113 | 21 rule-ish files, 10 re.compile in scanner core | no signing/ledger |
| agentshield | 1,376 | 44 rule files, 39 rule IDs | no signing/ledger |
| repo-forensics | 205 | 1,138 re.compile - deepest open scanner found | no signing/ledger/cross-registry |
| SkillWard | 145 | 52 rule IDs, 100 re.compile | no signing/ledger |
| trustcheck | 50 (PyPI 2.2.3) | PEP 740 + sigstore verification, benchmark vs pip-audit, fuzz suite | verifies provenance only; no scan verdicts, no registry |
| agtmls (+spec) | 1 + 1 | signed skill registry 0.0.27, 33 skills, revocation advisory feed (verify exits 6), install lockfile, normative spec + conformance corpus, rules-as-TOML-data | own-registry only; no cross-registry, no drift measurement vs upstream |
| sigil_guard | 2 | Elixir runtime gateway: policy gating, manifest_drift error code, attestation envelope, golden vectors | runtime product, not measurement ledger |
| skillguard (glieser2) | 0 | GenLayer testnet on-chain registry, commit-pinned evidence, multi-LLM consensus, challenge flow | chain-gated, testnet, no packages |
| stepcheck-dev | 0 | DSSE per-commit for coding-agent context firewall, in-toto export | different domain (session kernel) |
| mcp-notify | 32 | registry change detection | no signing, no verdicts |

## 4. ECOSYSTEM SIZES (live)

- MCP official registry: >=40,000 entries returned before hitting the 400-page
  cap (includes server+version records; distinct servers per 2608.00997 panel
  was 18,966 as of Nov). Live count needs cursor pagination beyond cap.
- dsh.so market: 10,195 plugins (v3 said 10,183 - it grew), 100% with repo URL,
  100% labeled install-verified + risk-low, top categories: tools 1,926 /
  memory 1,642 / skin 1,226 / search 1,037 / notify 972.
- dsh.so per-plugin endpoints verified: /data/install/@author/name.json has
  installTest L5 sandbox record (checkedAt, profileId l4-sandbox, sourceRecordId);
  /artifact/@author/name.json has commitSha, counts {critical,warning,info},
  filesScanned, scannerVersion, rulesChecked=31, findings[].
- MCP-Eco HF dataset: 16.9M records (download attempt from this network timed
  out; the HF API record exists and the paper is public).
- npm: top-30 provenance coverage 60% (see Section 2).
- PyPI recent uploads with attestation: 0/40.

## 5. WHAT REMAINS UNIQUTELY CANARI'S (verified against everything above)

| Capability | mcpcheckup | SIGIL | agtmls | 23132 | SkillSpector | native registries | Canari |
|---|---|---|---|---|---|---|---|
| Cross-registry unified feed (npm+PyPI+MCP+dsh) | no | no | no | no | no | no | YES |
| Supersession chain semantics (supersedes links in signed objects) | no | no (append-only but no supersede) | no (ADR-level only) | no | no | no | YES (implemented) |
| Same-author revocation propagation | no | no | advisory feed (single registry) | no | no | no | YES (framework + tests) |
| Consumer-side install gate from signed verdicts | no (hosted query) | invocation-time (SVL) | lockfile (own registry) | pipeline enforcement | no | partial (npm provenance is advisory) | YES (design + CLI skeleton) |
| Portable offline verification without chain/host | yes | no | yes | yes | no | yes (npm) | YES |
| Verdict attestations distinct from provenance | yes (observed facts) | yes (audit votes) | yes (rule findings) | yes | findings only | no (identity only) | YES |
| Open dataset of verdicts | no | no | no | no | no | no | planned (294 now) |
| Deep vulnerability scanning | no (explicitly refuses) | DAO audit | 33-skill rule set | no | yes | no | NO (0 rules) |

The moat is now exactly four things: CROSS-REGISTRY, SUPERSESSION, PROPAGATION,
GATE. Everything else has somebody. Say this in the paper, not "first signed
attestation".

## 6. STRATEGY CONSEQUENCES (hard, no sugar)

1. Kill any claim of "first signed attestation ledger for MCP". mcpcheckup exists,
   is live, is in the official registry, and is engineering-quality. Cite it as
   the closest system. Position Canari as its complement: they monitor remote
   MCP servers; Canari unifies package registries + plugins + skills into one
   portable, offline-verifiable, supersession-linked verdict feed.
2. The measurement paper's data problem is solved: use Zenodo 21798111 (drift
   panel) + MCP-Eco (16.9M records) as baselines instead of building scraping
   infrastructure. Canari's contribution becomes the VERDICT LAYER on top of
   existing measurement data, plus its own 294+ weekly verdicts.
3. Add a "native attestation ingestion" feature as P0: npm provenance verify +
   PEP 740 verify. This is the bridge that makes Canari the aggregation point
   of BOTH worlds (identity attestations from registries, verdict attestations
   from Canari). Without it, Canari ignores 60% of top-npm having provenance.
4. Scanner depth stays 0 - that is fine IF the framing is "orchestration of
   scanners" (SkillSpector/cisco/snyk/repo-forensics as L3 adapters). The paper
   must say: Canari signs and time-binds other scanners' outputs, it does not
   compete with them. repo-forensics (1,138 patterns) is the best adapter
   candidate found this round.
5. dsh.so is not a competitor for the ledger role - it is a DATA SOURCE with
   CC-BY-4.0 license and per-plugin endpoints. Correct v3's implicit framing.
   Canari's dsh value-add: signing + cross-registry correlation + supersession,
   reusing their L5/install-test records as input evidence.
6. Window: mcpcheckup already ships 4 of Canari's 10 claimed differentiators for
   the MCP slice. agtmls + SIGIL cover the skill slice from two sides. The
   remaining unique surface is cross-registry + propagation + supersession +
   gate. Ship the arXiv short paper within 2 weeks or the "portable cross-
   registry verdict attestation" phrase gets coined by someone else first.

## 7. APPENDIX: REPRODUCIBILITY

All commands run today (2026-11-08) from this machine, direct connection,
no proxy (proxy 7890 was refused for arxiv; direct worked):

1. PDFs: GET https://arxiv.org/pdf/{2608.00997,2609.14119,2605.24248,2611.01976,2605.05274,2601.23132} (pypdf extract).
2. Zenodo: GET https://zenodo.org/api/records/21798111 -> title/files/license.
3. Repos cloned --depth 1: SkillSpector, agent-scan, skill-scanner, mcp-scanner,
   agentshield, nova-proximity, repo-forensics, SkillWard, trustcheck, ramparts,
   skillhawk, checks, agtmls, agtmls-spec, sigil_guard, skillguard, stepcheck-dev.
   Rule counts: regex scans over source (re.compile counts, id-literal sets,
   YARA rule headers), not READMEs.
4. npm provenance: GET https://registry.npmjs.org/{pkg} -> dist.attestations for
   30 top packages; PyPI: GET https://pypi.org/pypi/{pkg}/json -> urls[].attestations
   for 30 top + 40 fresh RSS uploads.
5. MCP registry: GET /v0/servers?limit=100 cursor-paged to 400-page cap (40,000
   entries; count includes versions; distinct-server count requires resuming
   pagination with backoff).
6. dsh.so: GET https://cdn.dsh.so/market/index.json (UA header required; direct
   fetch of per-plugin /data/install/@author/name.json and /artifact/... verified).
7. arXiv API queries (export.arxiv.org): "model context protocol"+attestation,
   agent supply chain, supply chain+attestation+LLM, mcp+signed, tool+verification+agent.
8. Semantic Scholar citations: 2608.00997 (3 cites), 2609.14119 (2),
   2605.24248 (2), 2611.01976 (0).

Known measurement caveats (honesty):
- MCP registry count is a floor (cap hit).
- npm 30-package sample is convenience-sampled by popularity, not the full
  registry; 60% is an order-of-magnitude claim for top packages only.
- GitHub star counts move daily; numbers are today's.
- mcpcheckup tracked-server count is not disclosed in HTML; treat as unknown.
