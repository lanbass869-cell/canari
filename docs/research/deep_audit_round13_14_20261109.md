# Canari Round 13-14 Deep Audit (2026-11-09)

Scope: every module line-by-line again after the H1-H3 heuristic commit (`236f9bb`).
Methods: static reading + live probes against real registries + mutation experiments.
Nothing here is inferred from README claims - each finding has a reproduction step.

## A. Bugs found and fixed (13)

| # | Severity | Finding | Evidence | Fix |
|---|---|---|---|---|
| BUG-63 | medium (misleading) | `verify_cli._independent_verify` was labeled "signature (independent PAE)" but performs no cryptography - it only rebuilds PAE bytes and checks canonical JSON. The real Ed25519 check is `verify_signed`. | read of verify_cli.py L49-85: no key material used | output relabeled `canonical payload (independent PAE)`; docstring states it is NOT a signature check |
| BUG-69 | high (FP) | Cadence dormancy fired on ANY historical gap >= 365d. urllib3 (gap 2009-2011) and pip (gap 495d in early history) were flagged in 2026 despite weekly releases. | live: `analyze_release_cadence('urllib3','2.8.0')` fired before fix, silent after | dormancy = gap INTO the current release only |
| BUG-71 | medium (FN) | Acceleration baseline median included the current tiny interval, diluting the signal. | synthetic 3x21d + 1h case did not fire before fix | baseline excludes the current interval |
| BUG-72 | high (usability) | Chain verifier reported 415 "unreachable" errors on the real store because two scan generations had no supersedes bridge. | `verify_cli --chain out/attestations` -> 415 errors, all parallel-generation pairs | parallel heads = note; a bundle errors only when unreachable from EVERY head |
| BUG-73 | high (key loss) | `load_or_generate_keypair` silently regenerated on a corrupt PEM, orphaning every previously signed bundle. | code read: `load_private_key` -> None -> regenerate without warning | corrupt PEM is backed up (`.corrupt-<ts>`) and a loud warning printed |
| BUG-74 | medium | `pypi_native.ingest_pypi` ignored its `version` argument - always fetched the LATEST release, risking wrong-version attestation attribution. | code read + probe: bogus version still returned latest | per-version endpoint `/pypi/{pkg}/{version}/json` |
| BUG-75 | high (dead feature) | H2 metadata anomaly had no data path: `StateStore.set_component` stored no maintainers/homepage, so `detect_metadata_anomaly` could never fire. | grep: no call site with previous metadata | state stores a `meta` snapshot per component; PyPI branch compares against it |
| BUG-76 | high (dead code) | H3 typosquatting had ZERO call sites and ZERO tests. | `git grep check_typosquatting` -> definition only | wired into the PyPI branch with the co-enumerated namespace as trusted set |
| BUG-77 | CRITICAL | Cadence read `upload_time` (no timezone suffix) while PyPI's real JSON provides `upload_time_iso_8601` (Z format). Every real timestamp parsed to None -> H1 had NEVER worked against live PyPI; only mocked ISO-Z data in probes. | live PyPI six@1.17.0: 0 findings before, `release_after_dormancy 1309d` after | read `upload_time_iso_8601` with `upload_time` fallback |
| BUG-78 | high (data loss) | MCP registry pagination returns one record per server VERSION; same name spawned N bundles, and second-granularity timestamps made same-second writes overwrite each other. | enumerated 10 records -> 10 versions of 4 servers; duplicate-name check on old store | dedupe by name keeping highest version + payload-digest suffix in filenames |
| BUG-79 | high (invalid pointers) | Legacy `state.json` entries carried a FILE PATH in `attestation_digest`; new bundles copied it into `supersedes`, producing invalid chain pointers (48 bundles affected). | payload inspection: supersedes = `E:\Temp\...bundle.json` | 64-hex guard before writing `supersedes`; 48 bundles repaired |
| BUG-80 | high (FP) | Typosquatting flagged 38/94 `mcp-server-*` packages: shared-prefix families and wrapper renames (`aistudio` vs `3daistudio`) look alike under full-name Damerau-Levenshtein. | live findings sample | strip only hyphen-boundary family prefixes, suppress suffix-wrapper renames; 8/8 true/false cases pass; population findings 38 -> 4 |
| BUG-81 | CRITICAL | `verify_signed` MUTATED the caller's envelope (in-toto `Envelope.from_dict` consumes fields). Any key-history verification - retry with the archived key after the current key fails - always failed. Score card showed sig 63.6% instead of 100%. | mutation experiment: dict changed after failed verify; retry with correct key failed | deep-copy before `from_dict`; score supports `public_keys` history; 530/530 signatures now verify |

## B. Tests added

- `tests/test_round13_fixes.py` (12): cadence parser/format, dormancy FN/FP, acceleration baseline, corrupt-key backup, PyPI per-version URL, state meta, heuristic wiring source check, verify-cli label.
- `tests/test_round14_fixes.py` (12): typosquat family cases (8 parametrized), parallel generations, unbridged supersedes target, path-shaped digest guard, verify-no-mutation.

Total: 142 passed + 1 skipped (live-PyPI-only), 5 deselected (network/marker).

## C. Live store (S1 rescan, 2026-11-09)

- Bundle files: 530 (337 from the new generation: npm 100, PyPI 181 [two generations], MCP registry 56; 193 from 2026-11-08 under the archived key)
- Components (latest per registry+name): 258 - npm 102, PyPI 100, MCP Registry 56
- Verdicts (latest per component): pass 192, pass-with-findings 64, fail 1, error 1
- Findings (latest per component): L2.4 cadence 5, L2.6 typosquatting 4
- Schema integrity 100.0% (530/530), signature integrity 100.0% (530/530 vs key history)
- Chain verification: 190 multi-bundle components, all chains valid, 0 errors
- Key history: current key persisted at `out/private_key.pem` (Ed25519); the 2026-11-08 public key archived as `out/public_key_20261108.json` (its private half was never persisted by the older pipeline - the archive keeps the old bundles verifiable)

## D. Honest gaps

1. The 2026-11-08 signing key's private half is lost (pre-persistence pipeline). Old bundles remain verifiable; they can never be re-signed. The audit trail is still intact because both keys are published.
2. PyPI native attestation coverage remains 0 in this population (PEP 740 adoption still near zero); the ingestion path is tested against mocks and per-version URLs.
3. `run_multi`'s full PyPI phase downloads the ~600K-name simple index, which was killed mid-run once; the rescan driver reuses the existing population instead. A streaming/prefix-scoped enumeration is the fix (planned).
4. The paper PDF was not regenerated (no TeX toolchain on this host); `paper/main.tex` is updated and balanced.
