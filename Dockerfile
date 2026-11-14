# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Canari MCP server: stdio transport, ships a snapshot of the newest signed
# attestation per component, so no network or local ledger checkout is needed.
WORKDIR /app

COPY pyproject.toml README.md ./
COPY canari ./canari

RUN pip install --no-cache-dir .

# MCP servers speak JSON-RPC over stdio; this container is meant to be launched
# by an MCP host with `docker run -i --rm ghcr.io/lanbass869-cell/canari`.
ENTRYPOINT ["canari-mcp"]
