# Does the replacement for namespace-to-endpoint binding actually exist in the wild?

The MCP registry verifies that a publisher owns the domain behind a reverse-DNS
namespace. It used to also require that the remote endpoint sit on that domain
(`#180`, implemented in PR #306, Aug 2025). That requirement was deliberately
removed (`#494`, PR #769, Nov 2025) because `io.github.*` publishers and anyone
deploying to a PaaS could not satisfy it.

The stated replacement was for the endpoint to identify itself: *"we should make
a `GET https://.../mcp` or .well-known-adjacent type flow possible where you can
query the URL directly to properly identify the name of the server hosted
there"* (#494, maintainer comment). That shipped as **SEP-2127: MCP Server
Cards** (merged 2026-10-06): a card at `<streamable-http-url>/server-card`, and
an `/.well-known/ai-catalog.json` at the host root.

This measures whether the replacement is actually in use. **It is, at 2.81% in
exactly the population that needs it.**

## The rule used to decide "should this endpoint be on this domain"

Namespace authentication in `internal/api/handlers/v0/auth/common.go`
(`BuildPermissions`) works like this: a verified domain `D` yields the reverse
namespace `reverse(D)`, and a subdomain grant extends it by labels. So a server
may publish under namespace `N` only if some domain `D` exists whose reverse is a
**prefix** of `N`.

```
com.example/server   -> own example.com
ac.inference.sh/mcp  -> own inference.ac  (or sh.inference.ac)
io.github.user/repo  -> GB auth, not DNS; user.github.io is the natural reading
```

So the domains implied by a namespace are `reverse(n1..ni)` for every prefix
length `i >= 2` (a single label is a TLD, not an ownable domain). `exact` means
the endpoint host equals one of those or is a subdomain of one. This is stricter
and more faithful than a "reversed string plus suffixes" heuristic — under it,
`ac.inference.sh/mcp` serving `api.inference.sh` is **not** exact, because the
name claims `inference.ac`.

## Pass 1 — full census, no network

Full pagination of `GET /v0/servers?version=latest`: **654 pages, 65,340 latest
records** (65,340 distinct names), 2026-11-16. 21,021 declare no `remotes`
(32.2%); 44,319 do (67.8%). First remote URL per server.

| namespace kind | with remote | exact | mismatch |
|---|---|---|---|
| reverse-DNS (`ai.x`, `com.a.b`, …) | 27,064 | **25,729 (95.07%)** | 1,335 (4.93%) |
| `io.github.*` | 17,255 | 10 (0.06%) | 17,245 (99.94%) |

`io.github.*` cannot satisfy a domain rule by construction — which is the reason
`#494` removed it. The population a card is meant to cover is therefore the
**1,335 reverse-DNS servers whose endpoint is not on a domain their name
implies**.

## Pass 2 — probe those endpoints

For each host, `GET <remote-url>/server-card` and
`GET https://<host>/.well-known/ai-catalog.json`. A card counts only if it is a
JSON object with the server-card media type, or with `$schema` + `name` +
`remotes`. A catalog counts only if it is a JSON object with `entries` or
`specVersion`. Error bodies do not count — most JSON responses were
`{"error": ...}` or `{"detail": ...}`.

Coverage: **all 889 unique hosts** in the 1,335-server gap (no sampling), plus
random samples of 574 `exact` hosts and 359 `io.github.*` hosts as controls.

## Result

| group | hosts probed | self-describes (card or catalog) | rate (95% CI) |
|---|---|---|---|
| **gap** — claims a domain, endpoint elsewhere | 889 | 25 | **2.81%** (1.91–4.12) |
| exact — control | 574 | 48 | 8.36% (6.37–10.91) |
| `io.github.*` | 359 | 17 | 4.74% (2.98–7.45) |

Gap vs exact: **chi2 (Yates) = 21.51, df = 1, p < 0.001.** Adoption is inversely
related to need.

Restricting the gap to the class that most needs machine-readable identity —
endpoint on a PaaS default host (`*.workers.dev`, `*.supabase.co`, `*.run.app`,
`*.vercel.app`, …):

| class | hosts | self-describes |
|---|---|---|
| gap, hosted on a PaaS default domain | 342 | **3 (0.9%)** |

## The cards that do exist are mostly, not always, correct

54 cards were returned across all probes. **46 (85.2%) carry a `name` identical
to the registry name.** The 8 that differ:

| registry name | card `name` | what it looks like |
|---|---|---|
| `co.huggingface/hf-mcp-server` | `huggingface.co/mcp` | not reverse-DNS — spec requires reverse-DNS |
| `io.github.gokimedia/sewlore-measurement-reference` | `com.gitbook.sites.mcp/site_qHMh7` | the **hosting platform's** card, served for someone else's server |
| `ai.echoo.www/public-catalog` | `ai.echoo/public-catalog` | namespace variant |
| `com.modevc/chart-ollama-downloads-local-llm-adoption` | `com.modevc/radar` | different leaf |
| `io.planzer/mcp` | `io.planzer/planzer` | different leaf |
| `io.github.moelayyan90/xguard-control-plane` | `io.github.moelayyan90/xguard` | different leaf |
| `io.github.pipeworx-io/worldbank` | `io.pipeworx/worldbank` | migrated to a domain namespace |
| `io.github.bitcoinresearchkit/bitview` | `space.bitview.mcp/bitview` | migrated to a domain namespace |

Two are worth attention: one card is not in the required reverse-DNS form, and
one is a platform card that a naive "does the card name match the registry name"
check would flag — correctly, but for the wrong reason.

## What the registry does not publish

The publish token carries the verified domain in `AuthMethodSubject`
(`CreateJWTClaimsAndToken`), but the published entry does not. Every entry's
`_meta` contains only `status`, `statusChangedAt`, `publishedAt`, `updatedAt`,
`isLatest`. There is no field naming the domain that was verified and no field
naming the authentication method.

So a client cannot reconstruct the domain check even if it wanted to: for a
reverse-DNS name it can *guess* the domain from the namespace, and for the 1,335
servers in the gap that guess is wrong by construction. The namespace does not
tell you which prefix length was actually verified.

## Files

| file | contents |
|---|---|
| `summary.json` | census aggregates and the classification rule |
| `gap_servers.json` | the 1,335 gap addresses |
| `card_probe.json` | all 1,822 probe results |
| `adoption_rates.json` | rates with Wilson 95% intervals |
| `scripts/pull_registry.py` | full pagination of the latest snapshot |
| `scripts/classify_domain.py` | namespace → implied domains → exact/mismatch |
| `scripts/probe_cards.py` | card + catalog probe |

## Limits

- One snapshot, one day. Point estimates, not a trend.
- `exact` is a string relation. It does not prove the same organisation controls
  both sides; a squatter can own `evil.example` and publish `example.evil/mcp`.
- Only the first remote URL is used when a server declares several.
- Public suffixes are not special-cased: a namespace like `uk.co.foo` yields a
  candidate `co.uk`, which is not an ownable domain. This affects multilevel-TLD
  namespaces only.
- The probe requests `<endpoint>/server-card`. A card published elsewhere is
  counted as absent — which is the point: a client cannot find it either.

## Note on an earlier number

`experiments/mcp_witness/` reported 84.0% for this question. That was a sampling
artifact: the 800 records were the first pages of a name-ordered listing, so they
covered only names beginning with `a`, almost all reverse-DNS. The figures above
replace it.
