# Does the replacement for namespace↔endpoint binding actually exist in the wild?

The MCP registry used to require that a remote endpoint sit on the domain the
server name claimed. That rule was implemented (#180 → PR #306, Aug 2025),
then deliberately removed (#494 → PR #769, Nov 2025) because it could not be
satisfied by `io.github.*` publishers or by anyone deploying to a PaaS. The
stated replacement was for the endpoint to identify itself: *"we should make a
`GET https://.../mcp` or .well-known-adjacent type flow possible where you can
query the URL directly to properly identify the name of the server hosted
there"* (#494, maintainer comment).

That replacement shipped as **SEP-2127: MCP Server Cards** (merged 2026-10-06,
Extensions Track): a card at `<streamable-http-url>/server-card` and an
`/.well-known/ai-catalog.json` at the host root.

**Nobody has published how many registry endpoints actually serve one.** This
measures that, and the result is that the mechanism is adopted least by exactly
the servers that need it.

## What we measured

Two passes over the same snapshot, both on 2026-11-16.

### Pass 1 — full registry census, no network

Full pagination of `GET /v0/servers?version=latest`: **654 pages, 65,340
latest server records** (65,340 distinct names). 21,021 declare no `remotes`
(32.2%); 44,319 do (67.8%).

For each server with a remote, take the first remote URL's host and derive the
domain its namespace implies:

```
ac.inference.sh/mcp -> {inference.sh, ac.inference.sh}
ai.ankra/platform   -> {ankra.ai, ai.ankra}
io.github.user/repo -> {user.github.io}
```

`exact` = host equals a candidate or is a subdomain of one. `partial` = same
registrable suffix but not equal or a subdomain. `mismatch` = neither.

| namespace kind | with remote | exact | partial | mismatch |
|---|---|---|---|---|
| reverse-DNS (`ai.x`, `com.x.y`, …) | 27,064 | **25,650 (94.78%)** | 88 (0.33%) | 1,326 (4.90%) |
| `io.github.*` | 17,255 | 11 (0.06%) | 0 | 17,244 (99.94%) |

`io.github.*` cannot satisfy a domain rule by construction — that is the reason
#494 removed the check. The interesting population is the **1,414 reverse-DNS
servers whose endpoint is not on the domain their own name claims**.

### Pass 2 — probe those endpoints for self-identification

For each host, `GET <remote-url>/server-card` and
`GET https://<host>/.well-known/ai-catalog.json`. A hit requires a parseable
JSON object with either the server-card media type, or `$schema` + `name` +
`remotes` together, for the card; and `entries` or `specVersion` for the
catalog. Error bodies (`{"error": ...}`) are not counted — 144 responses parsed
as JSON but only 22 were cards.

Coverage:

- **gap** — all 972 unique hosts in the 1,414-server gap, no sampling.
- **exact-sample** — 578 unique hosts, random sample of the 25,650 `exact`.
- **github-sample** — 359 unique hosts, random sample of the 17,255
  `io.github.*` with a remote.

## Result

| group | hosts | self-describes (card or catalog) | rate (95% CI) |
|---|---|---|---|
| **gap** (claims a domain, endpoint elsewhere) | 972 | 31 | **3.19%** (2.26–4.49) |
| exact-sample (control) | 578 | 51 | 8.82% (6.77–11.42) |
| github-sample | 359 | 17 | 4.74% (2.98–7.45) |

Gap vs exact: **χ² (Yates) = 21.85, df = 1, p < 0.001**. Adoption is *inversely*
related to need.

Narrowing the gap to the worst class — a reverse-DNS name, an endpoint on a
different domain, and that domain being a PaaS default host
(`*.workers.dev`, `*.supabase.co`, `*.run.app`, `*.vercel.app`, …):

| class | hosts | self-describes |
|---|---|---|
| gap, brand label still appears in the host | 427 | 20 (4.7%) |
| gap, no brand overlap at all | 545 | 11 (2.0%) |
| gap, hosted on a PaaS default domain | 347 | **3 (0.9%)** |

So the endpoint that is least able to be identified — 347 of them — almost
never identifies itself.

### The cards that do exist are correct

In the 330-server pass-1 sample, 22 served a genuine card. **22/22 had `name`
byte-identical to the registry name.** Adoption is low, but where it exists it
is not wrong. Example (`https://app.apogee.ad/mcp/server-card`):

```json
{"$schema":"https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json",
 "name":"ad.apogee/apogee","version":"1.1.0",
 "remotes":[{"type":"streamable-http","url":"https://app.apogee.ad/mcp"}]}
```

## Why this matters

The gap is 1,414 servers, or 3.2% of every remote server in the registry. A
client that wants to know "is the thing at this URL the thing this name
describes" has, today:

1. **the domain check** — works for 94.78% of reverse-DNS servers, but was
   deliberately removed as a *policy*, so nothing enforces it and nothing
   surfaces it;
2. **the card check** — works for 3.19% of exactly the servers that need it.

Neither covers the gap. A registry entry also has **no field pointing at the
card**: the `server.json` schema in `modelcontextprotocol/registry` (all seven
versioned schemas under `internal/validators/schemas/`, plus
`docs/reference/server-json/draft/server.schema.json`) contains no
`serverCard`/`server-card`/`cardUrl` property. A client that has a registry
entry must guess `<endpoint>/server-card`, which is why "no card" and "card
somewhere else" are indistinguishable.

## Limits

- One snapshot, one day. The registry grows fast; these are point estimates.
- "Exact" is a string relation between name and host. It does not prove the
  same organisation controls both — a squatter can own `evil.example` and
  publish `example.evil/mcp`. It only proves the endpoint sits on the domain
  the name names.
- Only the first remote URL per server is used when a server declares several.
- `partial` is computed by comparing the last two DNS labels; a namespace like
  `ai.ankra` and a host `platform.ankra.app` are counted as `mismatch`, which is
  correct under a strict reading (the name claims `ankra.ai`) but understates
  same-organisation cases. 440 of the 1,414 gap servers still carry their brand
  label in the endpoint host.
- 10 hosts in the earlier 330-server sample failed TLS; they are excluded from
  the rates rather than counted as misses.
- The card probe sends a `GET` to the endpoint path plus `/server-card`. Servers
  that publish a card at another location are counted as absent, which is the
  point: a client cannot find them either.

## Files

| file | contents |
|---|---|
| `summary.json` | census aggregates |
| `gap_servers.json` | the 1,414 addresses, with `brand_overlap` soft/hard |
| `card_probe.json` | all 1,909 probe results, per host |
| `adoption_rates.json` | rates with Wilson 95% intervals |
| `scripts/pull_registry.py` | full pagination of the latest snapshot |
| `scripts/classify_domain.py` | name → candidate domains → exact/partial/mismatch |
| `scripts/probe_cards.py` | card + catalog probe |
