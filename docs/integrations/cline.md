# Using canari-mcp-gate with Cline

`canari-mcp-gate` is a stdio wrapper. You point one MCP entry at it instead of at
the server's own command; it looks the component up in the signed ledger, then
starts the real server and proxies stdio byte-for-byte.

## What it does and does not do

**Does**

- Blocks the server from starting when the ledger says `BLOCK`.
- Stops and asks you to confirm when the ledger says `REVIEW`.
- Leaves the MCP stream completely untouched: nothing is parsed, buffered or
  rewritten, so framing and large payloads are safe.

**Does not**

- Stop you from removing the wrapper. This is a *configuration-level* gate: MCP
  clients treat `command` as an opaque string, so whoever can edit the config can
  bypass it. This is not a policy engine and not tamper-proof.
- Gate components it cannot identify. A local script (`python -m x`,
  `node ./server.js`) has no registry identity, so it is `UNKNOWN` and runs.
  Use `--on-unknown=block` if you would rather it refuse.

## Configuration

### Cline

Cline reads `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
(macOS) or the equivalent `globalStorage` path on Windows/Linux. Wrap the entry:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "canari-mcp-gate",
      "args": [
        "--store", "/absolute/path/to/canari/out",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"
      ]
    }
  }
}
```

The `--` is required: everything after it is the command that would have been
there before.

### Any other stdio client

The same shape works for Continue, Cherry Studio and dsh: replace `command` with
`canari-mcp-gate`, keep the original command after `--`.

## Options

| flag | default | meaning |
|---|---|---|
| `--store DIR` | `$CANARI_STORE` or `./out` | attestation store |
| `--registry` / `--name` / `--version` | derived from the command | override identity |
| `--policy` | `default` | gate policy (`strict`, `release-gate`, `lax`, `paranoid`) |
| `--key` | none | public key JSON; enables signature verification |
| `--on-unknown` | `allow` | `allow` \| `block` \| `review` for components not in the ledger |
| `--allow-review` | off | accept `REVIEW` without prompting again |
| `--quiet` | off | suppress the one-line decision banner on stderr |

## Exit codes

| code | meaning |
|---|---|
| child's own code | the wrapped server exited; its status is propagated |
| 5 | blocked by the ledger; the server was never started |
| 6 | review required and `--allow-review` not given |
| 3 | usage or store error |
| 127 | the wrapped command was not found |

## Verifying it actually gates

```bash
# 1. ALLOW: a component the ledger has a passing attestation for
canari-mcp-gate --store out --registry npm --name 12306-mcp -- echo hi

# 2. BLOCK: a component the ledger fails
canari-mcp-gate --store out --registry dsh-registry --name agent-body -- echo hi
# exits 5; "echo hi" never runs

# 3. UNKNOWN with a strict posture
canari-mcp-gate --store out --on-unknown block --registry npm --name never-seen -- echo hi
# exits 5
```

## Limits

- Config-level only; bypassable by editing the config. Enterprise enforcement
  needs the client's own policy mechanism (for example Cline's enterprise
  allowlist) or a signed, read-only config.
- Identity is derived from the launch command. `npx -y pkg` and `uvx pkg` are
  recognised; a wrapper script that hides the real package name is `UNKNOWN`.
- A `server-side` change after install is out of scope: this gates *starting* a
  component, not what it does once running.
