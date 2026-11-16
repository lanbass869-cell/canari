# What a client can verify about a remote endpoint today: full census, and three missing pieces

### Summary

`#180` made the registry require that a remote endpoint sit on the domain the
server name claims. `#494` removed that requirement in Nov 2025, correctly:
`io.github.*` publishers and anyone on a PaaS could not satisfy it. The
replacement was to be self-identification by the endpoint — SEP-2127 Server
Cards, merged 2026-10-06 (still marked **Experimental** in the extension README).

I did a full census to see what a client can actually check today. The answer is:
**the domain check works for 95.07% of reverse-DNS servers by luck of naming, and
for the remaining 1,335 there is currently no runnable check at all** — because
three small pieces are missing.

1. **The registry does not publish the domain it verified.** Publishing under
   `com.example` means you proved you own `example.com`
   (`auth.BuildPermissions` reverses the domain; a subdomain grant extends it by
   labels). But the published entry's `_meta` contains only `status`,
   `statusChangedAt`, `publishedAt`, `updatedAt`, `isLatest`. The verified domain
   is in the publish token (`AuthMethodSubject`), not in the record. For 1,335
   servers the namespace does not say which candidate domain was verified, so a
   client cannot reconstruct the check.
2. **`server.json` has no field pointing at a card.** None of the seven
   versioned schemas under `internal/validators/schemas/`, nor the draft schema
   under `docs/reference/server-json/draft/`, defines a property for the card's
   location. A client must guess `<endpoint>/server-card`; "no card" and "card
   somewhere else" are indistinguishable.
3. **No live card points at a resolvable card schema.** Of the 54 real Server
   Cards the probe found, 45 reference
   `https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json`
   and 1 references `/schemas/mcp-server-card/v1.json` — both **404**. Five point
   at `/schemas/2025-12-11/server.schema.json`, which does resolve but is the
   registry's *server.json* schema, not the card schema. Three declare no
   `$schema`. So **0 of 54** resolve to a card schema. (The host is fine:
   `/schemas/2025-12-11/server.schema.json` returns 200. This is the known
   `ext-server-card#54`, still open.)

### The census

Full pagination of `GET /v0/servers?version=latest` on **2026-11-16**: **654
pages, 65,340 latest records**, 65,340 distinct names. 21,021 declare no
`remotes` (32.2%); 44,319 do (67.8%).

For each, take the first remote URL's host and compare it against the domains the
namespace implies. The candidate set follows the auth rule — `D` such that
`reverse(D)` is a prefix of the namespace, with at least two labels (a single
label is a TLD):

```
com.example/server   -> example.com
ac.inference.sh/mcp  -> inference.ac, sh.inference.ac
io.github.user/repo  -> github.io (GitHub auth), user.github.io
```

| namespace kind | with remote | endpoint on an implied domain | not |
|---|---|---|---|
| reverse-DNS (`ai.x`, `com.a.b`, …) | 27,064 | **25,729 (95.07%)** | 1,335 (4.93%) |
| `io.github.*` | 17,255 | 10 (0.06%) | 17,245 (99.94%) |

`io.github.*` cannot satisfy a domain rule by construction, which is exactly why
`#494` removed it. The population a card is meant to cover is the **1,335
reverse-DNS servers whose endpoint is elsewhere**.

I probed **all 889 unique hosts** in that gap:

| group | hosts probed | serves a card or AI catalog | rate (95% CI) |
|---|---|---|---|
| **gap** — claims a domain, endpoint elsewhere | 889 | 25 | **2.81%** (1.91–4.12) |
| control — endpoint on an implied domain | 574 (random) | 48 | 8.36% (6.37–10.91) |
| `io.github.*` | 359 (random) | 17 | 4.74% (2.98–7.45) |

chi2 (Yates) gap vs control = **21.51, df = 1, p < 0.001**. Restricting the gap
to endpoints on a PaaS default host (`*.workers.dev`, `*.supabase.co`,
`*.run.app`, `*.vercel.app`, …): **3 of 342 (0.9%)**.

This is early for an Experimental extension and I would not read 2.81% as
failure. The point is the shape: the servers that most need an out-of-band
identity are the least likely to have one, so **the gap is not being closed by
adoption** — and it cannot be, while the three pieces above are missing.

### The cards that exist are mostly, not always, right

46 of 54 (85.2%) carry a `name` identical to the registry name. Of the eight that
differ, two are worth naming: one is not in reverse-DNS form at all
(`co.huggingface/hf-mcp-server` -> `huggingface.co/mcp`), and one is a hosting
platform's own card served for someone else's server
(`io.github.gokimedia/sewlore-measurement-reference` at `sewlore.gitbook.io`
returns `com.gitbook.sites.mcp/site_qHMh7`). The other six look like namespace or
leaf variants of the same publisher.

That second case is why guess-the-path is not enough as a discovery rule: on
shared hosting, `<endpoint>/server-card` can be the platform's card, not the
tenant's. An explicit pointer on the registry entry removes the ambiguity.

### What I would change, in order

1. **Publish `verifiedDomain` and `authMethod` in `_meta`.** Both already exist at
   publish time. This makes the domain check reconstructable without
   re-introducing any rule, and it is the only way to resolve the 1,335
   ambiguous entries.
2. **Add an optional `serverCard` (URL) to the server object** (or a documented
   `_meta` key under the publisher-provided extension) so a client does not have
   to guess, and so a platform card cannot be mistaken for the tenant's.
3. **Ship a resolvable card schema URL** and, in the publisher docs, one line:
   *if your endpoint is not on the domain your namespace names, publishing a
   card is the only machine-readable way for a client to check that the endpoint
   is yours.*

All three are additive. None reintroduces `#180`.

### Limits

- One snapshot, one day. Point estimates, not a trend.
- `exact` is a string relation. It does not prove the same organisation controls
  both sides; a squatter can own `evil.example` and publish `example.evil/mcp`.
- Only the first remote URL is used when a server declares several.
- Public suffixes are not special-cased, so a namespace like `uk.co.foo` yields
  the candidate `co.uk`. This affects multilevel-TLD namespaces only.
- The probe requests `<endpoint>/server-card` and
  `/.well-known/ai-catalog.json`. A card published elsewhere counts as absent —
  which is the point.
- `{"error": ...}` and `{"detail": ...}` bodies are not counted as cards.

### Disclosure

I build a scanner that records signed snapshots of the registry. The numbers
stand alone: census aggregates, the 1,335 gap addresses, all 1,822 probe results
and the three scripts that produce them are in
`https://github.com/lanbass869-cell/canari/tree/main/experiments/server_card_adoption`
(CC BY 4.0 data, MIT scripts).

Related: `#494` (rule removed), `#1715` (no periodic re-validation), `#1706`
(target changes between versions), `#1783` (content-integrity fields),
`ext-server-card#54` (card schema 404).
