"""Canari - Agent Component Verification Ledger.

Cross-host attestation ledger for agent components (MCP servers / agent
skills / DSH plugins). Weekly scans produce signed, offline-verifiable,
history-preserving verification attestations.

Zero-heavy-dependency philosophy (inherited from MemTether):
  hard deps: jsonschema, in-toto (signing), nothing else.
"""

__version__ = "0.0.1"

