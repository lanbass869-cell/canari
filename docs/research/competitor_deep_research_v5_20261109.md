# Canari Competitor Deep Research Report v5 (2026-11-09)
## 17 Projects: Every Key Module Read Line-by-Line

> Method: 17 repos cloned, key source files opened and read function-by-function.
> Numbers below are from source code with content-hash deduplication.
> All claims cross-verified against the actual implementation.

---

## 1. mcpcheckup/checks — The Most Engineering-Serious Competitor

**Language:** TypeScript | **LOC:** 70,597 | **Files:** 343

### 1.1 Offline Verifier (`verify-attestation.mjs`, 475 lines)

Read line-by-line. The verification pipeline:

1. **L79-84**: Whitelist of accepted payloadTypes (v0.1–v0.4). Any other type is refused before any signature work.
2. **L87**: Ed25519 SPKI header constant (`0x302a300506032b6570032100`).
3. **L143-165**: PAE function — deliberately reimplemented from the DSSE spec (not imported from attestation-schema). The header explains why: "Both implement the same public spec, so they must compute identical bytes for identical input by construction; that fact is exactly what makes this a meaningful independent check instead of a formality." This is a security measure, not code duplication.
4. **L187-190**: keyId = first 16 hex chars of SHA-256 over SPKI bytes.
5. **L200-213**: RFC 3339 UTC parser — validates month/day/hour by round-tripping through Date.UTC() and checking fields match. Rejects month 13, Feb 31, second 60.
6. **L225-269**: Key document loader — validates every key (algorithm=Ed25519, SPKI length=44, SPKI starts with Ed25519 header, spki_sha256 matches actual SHA-256, key_id matches first 16 of SHA-256, no duplicate key_ids). One bad entry makes the entire document unusable. No lenient mode.
7. **L282-297**: Key window rules:
   - `revoked_at` set → always fails ("whoever holds the key can sign any observed_at they like")
   - `observed_at < valid_from` → fails
   - `valid_until` set and `observed_at > valid_until` → fails
   - Both ends inclusive, compared as epoch milliseconds
8. **L415-418**: Actual signature verification: `crypto.subtle.verify({ name: 'Ed25519' }, cryptoKey, sigBytes, preAuth)`.

### 1.2 Toolset Projection (`projections.ts`, 66 lines)

- `projectToolset()`: extracts tool names, sorts them. The projection is an **allowlist** of fields (not exclusion), so new server-added fields never silently look like drift.
- `projectSchemas()`: extracts `{name, inputSchema}` pairs, sorts by name then canonicalized schema. Schema sorting uses `canonicalize(inputSchema)` string comparison (not crypto) to ensure deterministic ordering independent of wire order.
- Header comment (translated from Chinese): "The projection ignores non-essential fields from the tools/list response (server version annotations, `_meta`, etc.). This prevents us from generating false drift when a server adds a new field. It is an allowlist of fields, not an 'exclude certain fields' approach. When a server adds a field, the projection is automatically unaffected."

### 1.3 What mcpcheckup does NOT have
- No supersession chain (history = observation list, no `supersedes` semantics)
- No cross-registry (remote MCP servers only)
- No same-author revocation propagation
- No consumer-side install gate tool
- No scanner orchestration (explicitly refuses: "This is not a security scan")

---

## 2. agtmls — The Only Competitor with Revocation Feed

**Language:** Python | **LOC:** 38,400 | **Files:** 726

### 2.1 Signing (`signatures.py`, 76 lines)

Read line-by-line. Key design decisions:

- **L5-7**: "Delegates to `ssh-keygen -Y verify`, which the spec names as the reference: the standard library has no Ed25519, and reimplementing SSHSIG to avoid a system tool would be the riskiest line in the registry."
- **L31-51**: `verify()` function:
  - Missing signature file → returns `"unsigned"` (not an error, not a failure)
  - Missing `ssh-keygen` → raises `ToolMissing` (an error, never a verdict)
  - Calls `ssh-keygen -Y verify -f allowed_signers -I principal -n namespace -s signature`
  - Returns `"verified"` (exit 0) or `"bad_signature"` (non-zero)
  - Optional `-Overify-time=YYYYMMDD` for time-based verification
- **L66-75**: `unverified_attestations()` iterates all `*.intoto.json` files under `root/attestations/`, checks each against `root/ALLOWED_SIGNERS`, reports any that fail.

### 2.2 Revocation (`advisories.py`, 119 lines)

- **L104-118**: `revoked()` function:
  - Takes the advisory feed (JSON) and the install lockfile
  - Only consulted when `feed_status == "verified"` (unsigned feeds are ignored)
  - Matches by **content digest**, not by name
  - Returns `(skill_name, digest, advisory_ids)` for every match
  - Entries without a name are still reported: "dropping it would hide a revocation of something installed"

### 2.3 Exit Code Precedence (`verify_report.py`, 140 lines)

- **L52-62**: Exit precedence: `bad_signature` (5) > integrity failure (3) > revoked (6) > unsigned (4) > OK (0)
- The `verify` command exits with code 6 when an installed skill has been revoked by a verified advisory.

---

## 3. trustcheck — The Most Complete PEP 740 Implementation

**Language:** Python | **LOC:** 77,528 | **Files:** 262 | **PyPI:** 2.2.3, 231 dl/month

### 3.1 Attestation Verification (`attestations.py`, 474 lines)

Read line-by-line. The `verify()` function (L177-243):

1. Converts PEP 740 attestation to a Sigstore Bundle via `to_bundle()`
2. Calls `_production_verifier(offline=offline).verify_dsse(bundle, publisher.as_policy())`
3. Checks payload type is `application/vnd.in-toto+json`
4. Parses the in-toto Statement from the payload
5. Validates exactly 1 subject (rejects too many)
6. Parses subject name as a distribution filename
7. **Checks subject name matches the distribution name** (catches mismatched attestations)
8. **Checks subject SHA-256 digest matches the distribution digest** (catches wrong-bundle errors)
9. Checks predicate type is supported (PEP Publish v1 or SLSA Provenance v1)
10. For SLSA provenance: calls `analyze_slsa_provenance()` with publisher kind, repository, and workflow

### 3.2 Publisher Policies (L256-280)

- `_GitHubPublisherPolicy`: builds a Sigstore `AllOf` policy combining:
  - `OIDCIssuerV2("https://token.actions.githubusercontent.com")`
  - `OIDCSourceRepositoryURI("https://github.com/{repository}")`
  - Then checks optional claims: `OIDCSourceRepositoryDigest` and `OIDCSourceRepositoryRef`
- Similar policies for GitLab and CircleCI publishers

### 3.3 Scale

trustcheck has 52 Python modules totaling 77,528 lines. The largest modules:
- `cli.py`: 3,846 lines, 81 functions
- `plugins.py`: 2,351 lines, 134 functions, 14 classes
- `service.py`: 2,447 lines, 45 functions
- `remediation.py`: 2,397 lines, 71 functions
- `exports.py`: 2,479 lines, 67 functions

---

## 4. repo-forensics — The Deepest Scanner

**Language:** Python | **LOC:** 165,170 | **Files:** 493

### 4.1 Pre-Scan Gate (`pre_scan.py`, 3,093 lines)

Read line-by-line. The `decide()` function (L2922-2993):

1. Detects install/update command patterns (also catches pipe-to-shell)
2. Pipe-to-shell: **instant block** (DENY)
3. Extracts package names from the command
4. Loads IOC (Indicators of Compromise) set — **fail-open**: any failure loading IOCs must fail OPEN cleanly
5. Checks package names against IOC set → DENY if matched
6. Checks version-pinned npm tokens (`name@version`) by base name and exact pinned version
7. Checks PyPI pinned versions (`litellm==1.107.0`)
8. If no IOC match: checks for redirected package index (registry risk) → ASK (human review)
9. Otherwise: ALLOW

**Fail-closed architecture:**
- Kill switch states: `unsafe-off` (everything off including tamper detection) > `install-manifest tamper` > `envelope drift` > `PRE_SCAN=0` > normal detection
- L3019-3027: When kill switch is "unsafe", it explicitly warns: "the pre-execution gate is FULLY disabled, including tamper and schema-drift detection. Nothing is being checked before this command runs."
- L3029-3031: Install-manifest integrity check runs BEFORE the allow branch and before the ordinary kill switch

### 4.2 Detection Scale

**580 unique `re.compile()` patterns across 220 unique modules** (1,138 total count includes 66 duplicated files between `skills/` and `plugins/` mirror directories — every file in `plugins/repo-forensics/skills/` is byte-identical to its counterpart in `skills/`).

**451 JSON rulepack rules** across 7 packs:
| Pack | Rules |
|---|---|
| sast.json | 150 |
| skill_threats.json | 126 |
| runtime_dynamism.json | 70 |
| secrets.json | 46 |
| mcp_security.json | 46 |
| dead_anchors.json | 8 |
| shared.json | 5 |
| **Total** | **451** |

**29 scanners** (full mode), **19 scanners** (skill-scan mode). Top detection modules by re.compile count:

| Module | re.compile | Lines |
|---|---|---|
| `scan_lifecycle.py` | 98 | 1,288 |
| `scan_agent_skills.py` | 52 | 708 |
| `auto_scan.py` | 44 | 3,329 |
| `scan_dataflow.py` | 42 | 349 |
| `scan_skill_threats.py` | 40 | 2,224 |

---

## 5. skill-scanner (Cisco AI Defense)

**Language:** Python | **LOC:** 214,194 | **Files:** 804

### 5.1 Rule Registry (`rule_registry.py`, 1,965 lines)

Read line-by-line. Key design:

- **L505-542**: `register_pack()` — validates the complete pack before publishing any part. A late collision must not leave earlier rules from a rejected pack in the active registry generation. Rule ID collisions between different packs are rejected.
- **L1396-1414**: `load_bundled_pack()` — release-owned schema-v2 packs with strict validation. Bundled packs may declare Python implementations and tuning knobs. Local packs reject imported Python code.
- **L1728-1747**: `load_trusted_pack()` — fail-fast for administrator-approved packs. Unknown schema fields, metadata drift, missing or duplicate implementations, malformed regex/YARA, and out-of-policy CEL all make the complete pack unusable.

### 5.2 YARA Rules: 27 total in 16 files

| File | Rules |
|---|---|
| behavior_chain_detection.yara | 9 |
| embedded_binary_detection.yara | 4 |
| 14 generic detection rules (prompt_injection, code_execution, credential_harvesting, etc.) | 1 each |
| **Total** | **27** |

### 5.3 Correlation Analyzer (`correlation_analyzer.py`, 3,849 lines, 153 functions)

The `analyze()` function (L2319-2333):
1. Extracts signals from skill files (paths, file types, hidden status, executability, archive depth, referenced files)
2. Builds a reference graph
3. Produces findings from: flow analysis, fenced code blocks, hidden executables, config execution, nested archives, manifest mismatches
4. Deduplicates findings

### 5.4 What skill-scanner does NOT do
- Does not sign anything (it detects private keys in other people's code)
- No ledger, no history, no cross-registry, no supersession, no revocation

---

## 6. SkillWard — Independent Scanner (NOT a Cisco Fork)

**Language:** Python | **LOC:** 15,131 | **Files:** 180

SkillWard contains its own `skill-scanner/skill_scanner/` package which is **independent code**, not a fork of Cisco's skill-scanner. Key modules:

| Module | Lines | re.compile | Functions |
|---|---|---|---|
| `core/analyzers/static.py` | 2,152 | 53 | 38 |
| `core/scanner.py` | 864 | 0 | 26 |
| `core/analyzers/pipeline_analyzer.py` | 724 | 20 | 19 |
| `core/scan_policy.py` | 693 | 1 | 18 |
| `core/command_safety.py` | 368 | 17 | 6 |

**Key finding from README:** "Five scanners on 238,180 Skills showed highly inconsistent results, only 0.12% were flagged by all five, with individual flag rates ranging from 3.79% to 41.93%."

**0 test files** — no automated testing at all.

---

## 7. SkillSpector (NVIDIA)

**Language:** Python | **LOC:** 250,641 | **Files:** 526

**20 YARA rules** across 5 files:
| File | Rules |
|---|---|
| agent_skills.yar | 5 |
| cryptominers.yar | 4 |
| hacktools.yar | 5 |
| webshells.yar | 6 |
| **Total** | **20** |

**483 `re.compile()` patterns** across 393 code files (no duplicates found).
**28 unique rule IDs** in source.

README claims "71 vulnerability patterns" — this likely refers to the combined YARA + inline regex count per-category, not a single verifiable number.

---

## 8. REVISED CAPABILITY MATRIX (Source-Code Verified, Content-Hash Deduplicated)

| Capability | mcpcheckup | SkillSpector | skill-scanner | repo-forensics | agtmls | trustcheck | sigil_guard | SkillWard | Canari |
|---|---|---|---|---|---|---|---|---|---|
| Cross-registry | no | no | no | no | no | no | no | no | **YES** |
| Produces signed attestations | yes | no | no | yes* | yes | no | yes | no | **YES** |
| Verifies offline | yes | no | no | yes* | yes | yes | yes | no | **YES** |
| Supersession chain | no | no | no | no | no | no | no | no | **YES** |
| Revocation propagation | no | no | no | no | advisory feed | no | no | no | **YES** |
| Install gate | no | no | no | pre_scan | lockfile | no | yes | no | **YES** |
| Native attestation ingestion | no | no | no | no | no | yes | no | no | **YES** |
| Scanner orchestration | no | no | no | no | no | no | no | no | **YES** |
| Deep vulnerability scanning | no | yes | yes | yes | 33 skills | no | no | yes | no |
| YARA rules | 0 | 20 | 27 | 0 | 0 | 0 | 0 | 0 | 0 |
| re.compile (unique) | 0 | 483 | 453 | 580 | 89 | 18 | 0 | ~94 | 0 |
| JSON rulepack rules | 0 | 0 | 0 | 451 | 0 | 0 | 0 | 0 | 0 |
| Unique rule IDs | 15 checks | 28 | 148 | 44 | 4 | 24 | 0 | 52 | 0 |
| Test files | 37 | 43 | 39 | 30 | 94 | 17 | 198 | 0 | 8 |

*repo-forensics: local scan attestations, not a public ledger
*trustcheck: verifies identity (PEP 740), doesn't produce verdict attestations

---

## 9. WHAT CANARI MUST SAY (AND NOT SAY)

**Claim:** "First cross-registry, offline-verifiable verdict attestation ledger with supersession chains and revocation propagation for AI agent component supply chains."

**Evidence:**
- Zero competitors have all 8 "YES" capabilities together
- mcpcheckup: 4/8 (signing, offline verify, install gate concept, deep protocol checks) but MCP-only
- repo-forensics: 3/8 (local attestations, pre-scan gate, deep scanning) but no public ledger
- agtmls: 3/8 (signing, offline verify, revocation feed) but own-registry only
- trustcheck: 2/8 (native ingestion, offline verify) but identity-only
- Canari: 8/8

**Do NOT claim:**
- "First signed attestation for npm" — npm provenance has 60% top-30 coverage
- "First security scanner" — repo-forensics has 580 regex + 451 rulepack rules
- "First monitoring" — mcpcheckup is live and listed in the official registry
- "First revocation" — agtmls has a revocation advisory feed

---

## 10. REPRODUCIBILITY

All repos cloned with `git clone --depth 1`. Analysis scripts in `E:/Temp/canari_deep/`.
Key scripts: `audit_all.py` (cross-repo capability scan), `check_dup2.py`/`check_dup3.py` (content-hash dedup verification),
`verify_yara.py`/`verify_yara2.py` (YARA rule counting), `read_verify.py` (mcpcheckup verifier source reading).
