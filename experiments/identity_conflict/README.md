# Does a name identify a component? (2026-11-18)

Plan line 3 asked for one cheap, falsifiable check before building anything on
"cross-ecosystem component identity": **does the same name actually refer to
different components?** If yes, the problem is real; if no, the idea is dead.

Answer: **yes, and it is measurable in the public registry snapshot.**

## Method

`probe.py` paginates `GET /v0/servers?version=latest&limit=100` to the end
(666 pages, **66,509 latest server records**, snapshot 2026-11-18) and builds
three maps from each server's `packages[]`:

- `(registryType, identifier) -> {server names}` — who claims this artifact
- `bare name -> {registryType}` — the same string on npm *and* PyPI
- `server name -> {(registryType, identifier)}` — one server, several artifacts

`verify_cross.py` then asks npm and PyPI for each name that appears on both, and
compares the normalised repository URL. Same repo = same project; different repo
= two projects wearing one name.

## Result 1 — one artifact, several owners

| quantity | count |
|---|---|
| distinct npm/PyPI identifiers in the snapshot | 22,243 |
| claimed by **more than one** server entry | **508** |
| ...where the claimants are in **different publisher namespaces** | **371** (263 npm / 108 PyPI) |

A publisher namespace is `io.github.<owner>`, `com.<org>`, etc. Two entries under
different namespaces advertising the same npm package means "which server is
this?" cannot be answered from the package name.

Example (real, unedited): npm `@4da/mcp-server` is claimed by both
`io.github.4DA-Systems/4da-mcp-server` and
`io.github.runyourempire/4da-mcp-server`; npm `@aicanvas/mcp` is claimed by
`io.github.aicanvas-me/aicanvas` and `io.github.uiNerd16/aicanvas`.

Caveat that stops this being an alarm: one organisation commonly owns two
namespaces (`com.arcnautical` and an `io.github.x` mirror), and a fork is a
legitimate second claimant. This measures **ambiguity**, not malice.

## Result 2 — one name, different components

| outcome | names | share of resolvable |
|---|---|---|
| on both npm and PyPI | 134 | — |
| same repository | 61 | 60.4% |
| **different repository** | **40** | **39.6%** |
| ...of which **different owners** | **33** | 32.7% |
| no repository URL either side | 32 | — |
| not live on both | 1 | — |

"Resolvable" = 101 names where both sides published a repository URL.

Examples where both sides are unrelated projects by different GitHub users:

| name | npm repository | PyPI repository |
|---|---|---|
| `ato-mcp` | `william-laverty/ato-mcp` | `bigred97/ato-mcp` |
| `ats-jobs-mcp` | `vovikp/ats-jobs-mcp` | `groundtruthtools/ats-jobs-mcp` |
| `edgar-mcp` | `danishashko/edgar-mcp` | `henrysouchien/edgar-mcp` |
| `godot-mcp-server` | `tomyud1/godot-mcp` | `sterion66/godot-mcp-server` |

`different-repo` is a proxy, not a verdict: one project may keep a JS and a
Python implementation in separate repositories (`aamio` does exactly that). That
is why the stricter "different owner" count is reported separately — 33 cases
where the two repositories are not even under the same account.

## What this does and does not show

**Shows**: a bare name is not an identity. 33 unambiguous collisions exist in a
single snapshot of one registry's own package list, and 371 identifiers are
claimed from more than one publisher namespace. Any system that keys components
by name alone is liable to mix two components.

This experiment found one such bug in Canari itself. The metadata tier wrote
`StateStore` entries under the bare name, and `baseline._prev()` fell back to a
plain entry unconditionally, so an npm package could be compared against a PyPI
package with the same name. Fixed in the same change: the metadata tier stamps
`meta.registry` and `baseline._prev_from()` refuses a plain entry that claims a
different registry (`tests/test_false_pass_hardening.py`,
`TestPreviousSnapshotIsRegistryAware`).

**Does not show**: which claimant is legitimate, that any of these is malicious,
or how often a *user* is affected. This is a supply-chain ambiguity measurement,
not an incident report.

## Reproduce

```
python probe.py          # ~15 min, resumable, caches servers.json
python verify_cross.py   # 134 names x 2 registries, ~15 s
```

Artifacts written here: `result.json` (registry pass), `cross_registry.json`
(per-name comparison), `multi_publisher.json`, `different_owner.json`.
`servers.json` and `servers.partial.json` are gitignored: tens of MB and
regenerable.

## Result 3 - how often is the repository even published? (2026-11-18)

`repo_coverage.py` asks each registry for the repository behind a package, without
downloading or hashing anything. 200 candidates per ecosystem:

| ecosystem | candidates | with a repository | rate |
|---|---|---|---|
| npm (`enumerate_top`) | 200 | 188 | **94.0%** |
| PyPI (`mcp-server-*`, cached simple index, 200 spread across the alphabet) | 200 | 65 | **32.5%** |

The asymmetry is the finding, and it is a data gap, not an extractor bug: spot
checks of the misses (`mcp-server-12306`, `mcp-server-aact`) return an empty
`project_urls` **and** a null `home_page`. Those packages publish no repository
anywhere in their metadata.

Consequence for the identity layer: a repository link can cover ~94% of npm MCP
packages and only ~33% of PyPI ones. For the other two thirds of PyPI, no
repository-based claim can ever be issued - "no repository" is UNKNOWN, so those
components stay outside identity enforcement until a different link exists
(maintainer identity, tool-surface fingerprint, or PyPI provenance attestations).

Also in this sample: 253 records with a repository formed 218 clusters, 13 of them
monorepos, 1 cross-registry, 0 name collisions, 0 repo changes.

## Result 4 - PEP 740 recovers part of the PyPI gap (2026-11-18)

The first guess at a provenance endpoint (`/integrity/<project>/<version>/provenance`)
404s. The real shape, confirmed against PEP 740 and live PyPI:

1. `GET https://pypi.org/simple/<project>/` with
   `Accept: application/vnd.pypi.simple.v1+json` -> `files[].provenance` is a URL
   (only for release files that carry attestations)
2. `GET <that url>` -> `attestation_bundles[].publisher.repository`

The publisher repository is signed by PyPI Trusted Publishing, so it is a
*stronger* link than `project_urls` (self-declared). Worked example:
`mcp-server-fetch` 2026.11.11 -> `modelcontextprotocol/servers`.

Recovery measured on the 135 PyPI packages that had no repository in their
metadata:

| outcome | count |
|---|---|
| recovered a repository from provenance | **15 (11.1%)** |
| no attestation on any file | 116 |
| no files at all | 3 |
| network error | 1 |

So PyPI identity coverage goes from 65/200 (**32.5%**) to 80/200 (**40.0%**).
Provenance helps, but it does not close the gap: most of these packages were not
published through Trusted Publishing at all.
