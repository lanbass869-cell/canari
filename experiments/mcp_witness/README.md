> **Correction (2026-11-16, later the same day).** The 84.0% figure below is a
> sampling artifact and should not be quoted. The 800-record sample came from the
> first pages of `/v0/servers`, which paginate in name order, so it covered only
> names beginning with `a` — almost entirely reverse-DNS namespaces. The full
> census (all 65,340 latest records) finds **95.07% of the 27,064 reverse-DNS
> servers with a remote endpoint sitting on a domain their namespace implies**, while
> `io.github.*` servers cannot satisfy a domain rule by construction (0.06% do).
> See `experiments/server_card_adoption/` for the full numbers, and for what the
> registry put in place of the domain rule.

# Do MCP registry names bind to anything?

For npm and PyPI a package name is a **label**: nothing outside the registry
verifies what it means. `Certified Multi-Source Integrity` (arXiv 2609.34245)
measured this on 450 npm packages and found that after collapsing shared origin
only **two** control domains remain (registry + repository), **none reach three**.

MCP registry names look different: they are reverse-DNS (`ac.mizan/registry`,
`dev.inbin/agent-email`, `io.github.user/repo`). If a name is a claim about a
domain, then DNS and TLS are a witness the registry does not control - a witness
npm simply does not have.

This measures whether that claim is actually kept.

## Method

- Pulled **800** records from the official MCP registry (`v0/servers`, 8 pages of
  100, 2026-11-16).
- De-duplicated to the latest version per server name: **368 servers**.
- 330 have at least one remote URL; 310 distinct hosts.
- For every host, fetched `https://<host>/` **through the system's normal HTTP
  path with certificate verification on**. A 4xx/5xx counts as TLS success (the
  handshake completed); a TLS error counts as failure. 300/310 succeeded
  (SSLEOFError x9, RemoteDisconnected x1).
- For every server, derived the domain its namespace implies and compared it with
  the host:

```
dev.inbin/agent-email  -> candidates {inbin.dev, dev.inbin}
                          (reversed form, plus every suffix of the name)
ac.inference.sh/mcp    -> candidates {sh.inference.ac, inference.sh}
io.github.user/repo    -> matched against <user>.github.io
```

A server is **exact** if the host equals a candidate or is a subdomain of one.

## Result

| category | servers | share |
|---|---|---|
| **exact** - endpoint lives on the domain its name implies | **309** | **84.0%** |
| no remote (stdio only, no domain to check) | 38 | 10.3% |
| TLS failed | 10 | 2.7% |
| partial - related but not an exact match | 7 | 1.9% |
| **mismatch** - endpoint on an unrelated domain | **4** | **1.1%** |

**84% of MCP servers are served from the domain their registry name claims.**

That is a materially stronger identity binding than any package registry has: an
npm name says nothing about a domain, so there is nothing to check.

## The four mismatches are the interesting part

| registry name | actual endpoint |
|---|---|
| `ai.1325/mcp` | `agoclnqfyinwjxdmjnns.supabase.co` |
| `ai.bankee/inferventis-mcp` | `mcp-server-295985738387.europe-west1.run.app` |
| `ai.benroberts/b4-index` | `b4-index.vercel.app` |
| `ai.agent-bev/library` | `mcp.bev-cuvee.org` |

Three of the four are **platform default URLs** (Supabase, Cloud Run, Vercel): the
operator deployed to a PaaS and never bound a domain, so the reverse-DNS name is
decoration. The fourth points at a *different* organisation's domain entirely.

A client cannot tell these apart from the 84% without checking, and the check is
cheap - a DNS lookup and a TLS handshake.

## Witness counting

Treating registry / endpoint domain / repository as three witnesses:

| | this census (MCP) | 2609.34245 (npm) |
|---|---|---|
| apparent witnesses (mean) | 2.24 | 3 (by construction) |
| corruption-distinct after collapsing shared origin | **2.24** | **~2** |
| collapse factor beta = (apparent - distinct) / apparent | **0.000** | ~0.33 |

beta is zero because the three control domains really are different parties: the
registry operator, whoever holds the endpoint's domain, and the repository
platform/owner. Only 4 of 368 servers sit on a shared PaaS subdomain, so there is
almost nothing to collapse.

**The asymmetry with npm is the point.** npm's third witness (repository
back-reference) is served by the same platform that built the provenance, so it
collapses. MCP's third witness is a *domain*, which the registry does not own and
cannot mint - and 84% of servers actually use it.

## Limits

- One registry snapshot, one day. The registry grows fast; the 84% is a point
  estimate, not a trend.
- "Exact" is a string relation between the registry name and the host. It does not
  prove the same organisation controls both - a squatter can register
  `evil.example` and publish `example.evil/mcp`. It does prove the endpoint is on
  the domain the name names, which is what a client can check.
- 10 hosts failed TLS and are counted separately rather than as mismatches; some of
  those may be exact.
- Only the first remote URL per server was checked when a server declared several.
- The reverse-DNS candidate derivation is a heuristic. Seven "partial" cases are
  related-but-not-equal (e.g. `ai.ankra/platform` -> `platform.ankra.app`), which a
  stricter rule would call mismatches.
