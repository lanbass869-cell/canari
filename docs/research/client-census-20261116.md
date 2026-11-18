# Do MCP clients verify the server they connect to?

A source-level census of nine open-source MCP clients and SDKs (2026-11-16),
answering a question the MCP security literature leaves open: `Same Name,
Different Server` (arXiv 2609.14119) reports that **4.2% of multi-version servers
redirected their remote endpoint to a different host while keeping their registry
identity**, and notes "a change the protocol never surfaces to installed clients".
It does not measure whether clients defend themselves.

## Method

**Attempted: 12 repositories. Usable: 9.** Each was fetched as a source tarball
from `punkweye/awesome-mcp-clients` plus the three official SDKs and `fastmcp`.
Three tarballs did not download completely -- `cline/cline`, `Chainlit/chainlit`
and `CherryHQ/cherry-studio` -- and are excluded rather than half-scanned. The
nine below are what "nine clients" means throughout this document: nine
repositories that could be read in full, not nine of twelve claims about the
whole ecosystem.

**10,158 source files** (`.py .ts .tsx .js .jsx .go`) were scanned, excluding
`node_modules`, `dist`, `build`, tests, docs, examples and fixtures. Five capability
families were matched with literal patterns, and **every hit was then read by hand** —
this step is not optional: the raw grep produced 1,887 hits of which roughly 1,880
were false positives (see below).

| family | what it would mean |
|---|---|
| TLS_DISABLED | the client can be told to skip certificate verification |
| PINNING | the client pins a server's certificate / key / SPKI |
| ENDPOINT_CHANGE | the client remembers a server's URL and reacts when it changes |
| ATTESTATION | the client verifies a signed statement about the server |
| ALLOWLIST | the client has a trusted-server store |

## Result

| repo | files | TLS off | pinning | endpoint change | attestation | allowlist |
|---|---|---|---|---|---|---|
| LibreChat | 6218 | 0 | 0 | 0 | 0 | 0 |
| CodePilot | 1385 | 0 | 0 | 0 | 0 | 0 |
| AnythingLLM | 1182 | 0 (see note) | 0 | 0 | 0 | 0 |
| python-sdk | 355 | 0 | 0 | **guard** | 0 | 0 |
| 5ire | 309 | 0 | 0 | 0 | 0 | 0 |
| fastmcp | 309 | 0 | 0 | 0 | 0 | 0 |
| typescript-sdk | 272 | 0 | 0 | **guard** | 0 | 0 |
| go-sdk | 125 | 0 | 0 | 0 | 0 | 0 |
| chatmcp | 3 | 0 | 0 | 0 | 0 | 0 |

**Nothing in nine clients pins a server's identity, warns on endpoint change, or
verifies an attestation.** In 10,158 files there is not one implementation of the
capability that would let a client tell "the server I approved" from "a server that
now claims the same registry identity".

## The one defence that does exist, and what it does not cover

The official SDKs do not follow cross-origin redirects. From
`python-sdk/src/mcp/client/sse.py`:

> "MCP requests follow a redirect only when it stays on the endpoint's origin (same
> scheme, host and port, or http to https on the same host with default ports) and
> keeps the request method ... any other redirect is not followed, so connecting
> fails with `httpx2.HTTPStatusError` for the redirect response. **The client's
> `follow_redirects` setting is not consulted**."

and `streamable_http.py`:

> "Redirect to {location} not followed: it would downgrade this HTTPS endpoint to
> plain HTTP."

This is a real, deliberate anti-hijack policy that overrides the HTTP client's own
configuration, and 6 of the 9 scanned projects depend on the SDK that implements it.
But it defends only the **runtime redirect** vector. The vector `2609.14119`
measured — a registry entry that now points at a different host — arrives as a new
configuration value, not as a redirect, so the guard never sees it. A client
connects to the new host because that is what it was told to connect to.

So the ecosystem is asymmetric: **the cheap defensive primitive is shipped and
inherited; the thing that actually distinguishes "same server" from "same name" is
absent.**

## False positives, and why they had to be read by hand

The literal patterns produced 1,887 hits. Almost all were unrelated:

- `PINNING` 995 hits in LibreChat: agent **context** fingerprints
  (`computeAgentRequestFingerprint`), not certificate pinning.
- `ATTESTATION` 688 hits in LibreChat: **message** provenance and LangGraph
  **tool-call** signatures, not server attestation.
- `PINNING` 127 in CodePilot: workspace route fingerprints.
- `PINNING` 7 in fastmcp: an OAuth storage directory named from a key hash.
- `TLS_DISABLED` 3 in AnythingLLM: a Confluence document loader's `bypassSSL`
  option, unrelated to MCP transports.
- A targeted follow-up search for server-identity attestation returned 39 hits, all
  of which were tool-call signatures or message provenance.

A census that reported the raw counts would have concluded the opposite of the
truth.

## Limits

- Nine usable repositories out of twelve attempted, not the whole ecosystem.
  Three tarball downloads failed; the two largest closed-source clients (Claude
  Desktop, Cursor) cannot be inspected at all.
- Source inspection shows what a client *can* do, not what its users do. A client
  with no pinning code cannot pin; a client with none found here is not proof that
  every deployment is unprotected (an operator may pin at the network layer).
- `chatmcp` contributed only 3 files to the scan (the tarball is mostly assets), so
  its row is weak evidence.
- Patterns are literal. A defence implemented under an unexpected name would be
  missed; the hand-read step reduces but does not eliminate that risk.

## Reproduce

```
python scan.py     # expects tarballs already extracted under a clients/ directory
```
