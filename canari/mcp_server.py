# -*- coding: utf-8 -*-
"""mcp_server.py - canari-mcp: expose the ledger to any MCP host (dsh, Codex,
Claude, ...) over stdio JSON-RPC 2.0. Zero dependencies (stdlib only).

Tools:
  gate_check     - resolve a component's newest attestation and run the gate
  verify_bundle  - offline signature+schema verification of one bundle
  store_summary  - coverage/verdict counts + latest drift headline

Usage: canari-mcp [--store DIR] [--key PATH]

With no --store the server reads the snapshot bundled in the wheel (the newest
signed attestation per component, built by scripts/build_snapshot.py). Without
that, a fresh `pip install canari-mcp` would answer "no attestation" for every
component, because the full ledger lives in the repo, not in the wheel.
"""
import argparse
import json
import os
import sys

from canari.consumer import check_component, list_components
from canari.drift import compute_drift

PROTOCOL_VERSION = "2025-06-18"
from canari import __version__ as _VERSION

SERVER_INFO = {"name": "canari", "version": _VERSION}

TOOLS = [
    {"name": "gate_check",
     "description": "Look up a component (registry+name[,version]) in the signed "
                    "attestation ledger and return the install-gate decision "
                    "(ALLOW/BLOCK/REVIEW) with reasons.",
     "inputSchema": {"type": "object",
                     "properties": {"registry": {"type": "string",
                                                 "enum": ["npm", "pypi", "mcp-registry", "dsh-registry"]},
                                    "name": {"type": "string"},
                                    "version": {"type": "string"},
                                    "policy": {"type": "string",
                                               "description": "default|strict|release-gate|lax|paranoid"}},
                     "required": ["registry", "name"]}},
    {"name": "verify_bundle",
     "description": "Offline verification of one canari bundle: DSSE/Ed25519 "
                    "signature + schema + per-check breakdown.",
     "inputSchema": {"type": "object",
                     "properties": {"bundle_path": {"type": "string"},
                                    "key_path": {"type": "string"}},
                     "required": ["bundle_path", "key_path"]}},
    {"name": "store_summary",
     "description": "Coverage summary of the local ledger store plus the latest "
                    "drift headline (verdict flips / silent changes).",
     "inputSchema": {"type": "object", "properties": {}}},
]


def _tool_gate_check(args, store, key):
    res = check_component(store, args.get("registry", ""), args.get("name", ""),
                          version=args.get("version"), key_path=key,
                          policy=args.get("policy", "default"))
    return res


def _tool_verify_bundle(args, store, key):
    from canari.schema import validate_attestation
    from canari.signing import verify_signed
    try:
        with open(args["bundle_path"], "r", encoding="utf-8") as f:
            b = json.load(f)
    except Exception as e:
        return {"ok": False, "error": "cannot read bundle: %s" % e}
    kp = args.get("key_path") or key
    if not kp:
        return {"ok": False, "error": "no key_path given and no server default key"}
    try:
        with open(kp, "r", encoding="utf-8") as f:
            pub = json.load(f)
    except Exception as e:
        return {"ok": False, "error": "cannot read key: %s" % e}
    ok, payload, err = verify_signed(b.get("envelope"), pub)
    schema_errs = validate_attestation(payload) if ok else []
    return {"ok": bool(ok) and not schema_errs, "signature_ok": ok,
            "signature_error": err, "schema_errors": schema_errs,
            "verdict": (payload or {}).get("verdict"),
            "subject": (payload or {}).get("subject", {})}


def _tool_store_summary(args, store, key):
    comps = list_components(store)
    by_reg = {}
    by_verdict = {}
    for c in comps:
        by_reg[c["registry"]] = by_reg.get(c["registry"], 0) + 1
        by_verdict[c["verdict"]] = by_verdict.get(c["verdict"], 0) + 1
    rep = compute_drift(store)
    return {"components": len(comps), "by_registry": by_reg, "by_verdict": by_verdict,
            "drift": {"compared": rep["compared"],
                      "verdict_flips": len(rep["verdict_flips"]),
                      "silent_changes": len(rep["silent_changes"]),
                      "findings_added": len(rep["findings_added"]),
                      "findings_removed": len(rep["findings_removed"])}}


def _handle(msg, store, key):
    method = msg.get("method", "")
    mid = msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid,
                "result": {"protocolVersion": PROTOCOL_VERSION,
                           "capabilities": {"tools": {}},
                           "serverInfo": SERVER_INFO}}
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params", {}) or {}
        name = params.get("name", "")
        args = params.get("arguments", {}) or {}
        try:
            if name == "gate_check":
                res = _tool_gate_check(args, store, key)
            elif name == "verify_bundle":
                res = _tool_verify_bundle(args, store, key)
            elif name == "store_summary":
                res = _tool_store_summary(args, store, key)
            else:
                return {"jsonrpc": "2.0", "id": mid,
                        "error": {"code": -32602, "message": "unknown tool: %s" % name}}
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text",
                                            "text": json.dumps(res, ensure_ascii=False, indent=1)}],
                               "isError": False}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": "tool error: %s" % e}],
                               "isError": True}}
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": "method not found: %s" % method}}


def serve(stdin=None, stdout=None, store="out", key=None):
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        resp = _handle(msg, store, key)
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            stdout.flush()


def default_store():
    """Store to query when the user passes none.

    1. $CANARI_STORE (explicit operator override)
    2. ./out            (running from a checkout of the repo - full history)
    3. bundled snapshot (installed wheel - newest attestation per component)
    """
    env = os.environ.get("CANARI_STORE")
    if env:
        return env
    if os.path.isdir(os.path.join("out", "attestations")):
        return "out"
    snap = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_snapshot")
    if os.path.isdir(os.path.join(snap, "attestations")):
        return snap
    return "out"


def default_key(store):
    """Public key that belongs to the store being queried, if one is present."""
    for name in ("public_key.json",):
        p = os.path.join(store, name)
        if os.path.isfile(p):
            return p
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="canari-mcp",
                                 description="Expose the canari ledger to MCP hosts over stdio.")
    ap.add_argument("--store", default=None,
                    help="ledger directory (default: ./out, else the bundled snapshot)")
    ap.add_argument("--key", default=None, help="default public key JSON for verification")
    a = ap.parse_args(argv)
    store = a.store or default_store()
    key = a.key if a.key is not None else default_key(store)
    serve(store=store, key=key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
