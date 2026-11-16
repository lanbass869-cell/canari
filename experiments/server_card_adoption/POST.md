# Measurement: Server Card adoption in the official registry, 41 days after SEP-2127

### Summary

The registry verifies that a publisher owns the domain behind a reverse-DNS
namespace, but it no longer checks that the remote endpoint sits on that domain
(`#180` added the check in Aug 2025; `#494` removed it in Nov 2025 because
`io.github.*` publishers and PaaS deployments could not satisfy it).

The stated replacement was for the endpoint to identify itself. That shipped as
**SEP-2127: MCP Server Cards** (merged 2026-10-06): a card at
`<streamable-http-url>/server-card`, and an `/.well-known/ai-catalog.json` at the
host root.

I measured whether the replacement is in use. Three findings, all from the full
registry rather than a sample:

1. **The servers that need a card most are the least likely to publish one.**
   Of 27,064 reverse-DNS servers with a remote endpoint, 1,335 (4.93%) serve
   from a domain their namespace does not imply. Probing **all 889 unique hosts**
   in that gap, **2.81%** self-describe (1.91–4.12% CI). A control sample of
   servers that *do* match reaches 8.36% (6.37–10.91%). chi2 (Yates) = 21.51,
   df = 1, p < 0.001. The worst class — gap endpoints on a PaaS default host — is
   **0.9%** (3 of 342).
2. **The registry does not publish the domain it verified.** The publish token
   carries it in `AuthMethodSubject`, but the published entry's `_meta` contains
   only `status`, `statusChangedAt`, `publishedAt`, `updatedAt`, `isLatest`. A
   client cannot reconstruct the domain check even in principle, because the
   namespace does not say which prefix length was actually verified.
3. **`server.json` has no field that points at a card.** None of the seven
   versioned schemas under `internal/validators/schemas/`, nor the draft schema in
   `docs/reference/server-json/draft/`, defines a property for the card's
   location, so a client must guess `<endpoint>/server-card`. "No card" and "card
   somewhere else" are indistinguishable.

Where cards do exist they are mostly right but not always: of 54 cards returned
across all probes, 46 (85.2%) carry a `name` identical to the registry name. One
of the eight that differ is not in reverse-DNS form at all
(`co.huggingface/hf-mcp-server` -> `huggingface.co/mcp`), and one is a hosting
platform's own card served for someone else's server
(`io.github.gokimedia/sewlore-measurement-reference` at `sewlore.gitbook.io`
returns `com.gitbook.sites.mcp/site_qHMh7`).

### How it was measured

One snapshot, **2026-11-16**.

**Deciding what "should match" means.** `internal/api/handlers/v0/auth/common.go`
(`BuildPermissions`) turns a verified domain `D` into the reverse namespace
`reverse(D)`, and a subdomain grant extends it by labels. So namespace `N` is
legitimate only if some domain `D` has `reverse(D)` as a **prefix** of `N` — that
is, `D = reverse(n1..ni)` for some prefix length `i >= 2` (a single label is a
TLD, not ownable):

```
com.example/server   -> example.com
ac.inference.sh/mcp  -> inference.ac, sh.inference.ac
io.github.user/repo  -> github.io (GitHub auth), user.github.io
```

`exact` = the endpoint host equals one of those or is a subdomain of one. This is
stricter than a "reversed string plus suffixes" heuristic, and it matters:
`ac.inference.sh/mcp` serving `api.inference.sh` is **not** exact, because the
name claims `inference.ac`.

**Pass 1 — census, no network.** Full pagination of
`GET /v0/servers?version=latest`: **654 pages, 65,340 latest records** (65,340
distinct names). 21,021 declare no `remotes` (32.2%); 44,319 do (67.8%).

| namespace kind | with remote | exact | mismatch |
|---|---|---|---|
| reverse-DNS (`ai.x`, `com.a.b`, …) | 27,064 | **25,729 (95.07%)** | 1,335 (4.93%) |
| `io.github.*` | 17,255 | 10 (0.06%) | 17,245 (99.94%) |

`io.github.*` cannot satisfy a domain rule by construction — that is why `#494`
removed it. The population a card is meant to cover is the **1,335 reverse-DNS
servers whose endpoint is not on a domain their name implies**.

**Pass 2 — probe those endpoints.** For each host,
`GET <remote-url>/server-card` and
`GET https://<host>/.well-known/ai-catalog.json`. A card counts only if it is a
JSON object with the server-card media type, or with `$schema` + `name` +
`remotes`; a catalog only if it is a JSON object with `entries` or `specVersion`.
Error bodies do not count — most JSON responses were `{"error": ...}` or
`{"detail": ...}`.

Coverage: **all 889 unique hosts** in the 1,335-server gap (no sampling), plus
random samples of 574 `exact` hosts and 359 `io.github.*` hosts as controls.

### Result

| group | hosts probed | self-describes (card or catalog) | rate (95% CI) |
|---|---|---|---|
| **gap** — claims a domain, endpoint elsewhere | 889 | 25 | **2.81%** (1.91–4.12) |
| exact — control | 574 | 48 | 8.36% (6.37–10.91) |
| `io.github.*` | 359 | 17 | 4.74% (2.98–7.45) |

Narrowing the gap to the class that most needs machine-readable identity:

| class | hosts | self-describes |
|---|---|---|
| gap, endpoint on a PaaS default domain (`*.workers.dev`, `*.supabase.co`, `*.run.app`, `*.vercel.app`, …) | 342 | **3 (0.9%)** |

### What I think would move it

Three small, non-breaking changes, in the order I would do them:

1. **Publish the verified domain.** It already exists in the publish token
   (`AuthMethodSubject`). Adding e.g. `_meta` `verifiedDomain` and `authMethod`
   costs nothing at publish time and lets a client tell whether an endpoint is on
   the domain the publisher proved — without re-introducing any rule. The
   namespace alone is ambiguous: 1,335 entries are served from a domain their
   namespace does not imply, and nothing in the entry says which of the candidate
   domains was verified.
2. **Let the entry point at the card.** An optional `serverCard` (URL) on the
   server object, or a documented `_meta` key, so a client with a registry entry
   does not have to guess `<endpoint>/server-card`. This also separates a
   tenant's card from a hosting platform's card on the same origin, which is the
   gitbook case above.
3. **One line of best-practice guidance for publishers:** *if your endpoint is
   not on the domain your namespace names, publishing a card is the only
   machine-readable way for a client to check that the endpoint is yours.* The
   1,335 servers in the gap are the audience, and today 2.8% of them have acted
   on it.

I am not proposing to bring back the domain rule. The reason it was dropped is
sound: 17,245 `io.github.*` servers with a remote could never comply, and PaaS
deployments cannot align a host with a namespace they do not own. The question
here is only whether the replacement is being adopted where it matters, and
right now it is adopted least in exactly those places.

### Limits

- One snapshot, one day. Point estimates, not a trend.
- `exact` is a string relation. It does not prove the same organisation controls
  both sides; a squatter can own `evil.example` and publish `example.evil/mcp`.
- Only the first remote URL is used when a server declares several.
- Public suffixes are not special-cased: a namespace like `uk.co.foo` yields the
  candidate `co.uk`, which is not ownable. This affects multilevel-TLD namespaces
  only.
- The probe requests `<endpoint>/server-card`. A card published elsewhere is
  counted as absent — which is the finding: a client cannot find it either.

### Disclosure

I build a scanner that records signed snapshots of the registry. The numbers
above stand alone, and the census aggregates, the 1,335 gap addresses, all 1,822
probe results and the three scripts that produce them are in one directory:
`https://github.com/lanbass869-cell/canari/tree/main/experiments/server_card_adoption`

Method and per-host data are CC BY 4.0; scripts MIT.
