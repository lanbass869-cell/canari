# -*- coding: utf-8 -*-
"""consumer.py - consumer-side lookup: component -> latest attestation -> gate decision.

This is the missing "product" layer between the ledger and a host that installs
components: given (registry, name[, version]) resolve the newest signed
attestation in the store and evaluate the install gate against it.
"""
import json
import os

from canari.gate import evaluate_gate


def iter_bundles(store_dir):
    """Yield (path, payload) for every readable bundle in <store>/attestations."""
    att_dir = os.path.join(store_dir, "attestations")
    if not os.path.isdir(att_dir):
        return
    for fn in sorted(os.listdir(att_dir)):
        if not fn.endswith(".bundle.json"):
            continue
        fp = os.path.join(att_dir, fn)
        try:
            with open(fp, "r", encoding="utf-8") as f:
                bundle = json.load(f)
            # BUG-102/F2: enumerate/list UIs report the SIGNED payload. A file
            # with no DSSE envelope has nothing signed, so it is not part of
            # the ledger - skip it rather than advertising its unsigned mirror.
            from canari.signing import read_signed_payload
            if not isinstance(bundle, dict) or not isinstance(bundle.get("envelope"), dict):
                continue
            payload, _err = read_signed_payload(bundle)
            if payload is None:
                continue
            yield fp, payload
        except Exception:
            continue


def component_bundles(store_dir, registry, name):
    """All bundles for one component, oldest -> newest (generated_at, then mtime)."""
    out = []
    for fp, p in iter_bundles(store_dir):
        s = p.get("subject", {})
        if s.get("registry") != registry or s.get("name") != name:
            continue
        out.append((p.get("generated_at", ""), os.path.getmtime(fp), fp, p))
    out.sort(key=lambda x: (x[0], x[1]))
    return [(fp, p) for _, _, fp, p in out]


def latest_attestation(store_dir, registry, name, version=None):
    """Newest bundle for a component (optionally pinned to a version).
    Returns (path, payload) or None."""
    cands = [(fp, p) for fp, p in component_bundles(store_dir, registry, name)
             if version is None or p.get("subject", {}).get("version") == version]
    return cands[-1] if cands else None


def resolve_key(store_dir, key_path=None):
    """Public key that belongs to this store.

    ★2026-11-13 (F1): a decision is only meaningful when the signature behind it
    can be checked. Callers used to obtain ALLOW by simply omitting key_path.
    The store normally ships `public_key.json` next to `attestations/`, so we
    auto-discover it instead of silently skipping verification. Returns None
    only when no key exists at all - and then the gate fails closed.
    """
    if key_path:
        return key_path
    if not store_dir:
        return None
    cand = os.path.join(store_dir, "public_key.json")
    return cand if os.path.isfile(cand) else None


def check_component(store_dir, registry, name, version=None, key_path=None,
                    key_registry_path=None, policy="default", policy_file=None):
    """Resolve the latest attestation and run the install gate.

    Returns a plain dict (JSON-serializable) so CLI/MCP/other hosts share the
    exact same decision path:
      {found, decision, reasons, policy, verdict, subject, generated_at, bundle}
    """
    hit = latest_attestation(store_dir, registry, name, version=version)
    if hit is None:
        return {"found": False, "decision": "BLOCK",
                "reasons": ["no attestation for %s:%s%s in store" % (
                    registry, name, ("@" + version) if version else "")],
                "policy": policy, "verdict": "", "subject": "", "generated_at": "",
                "bundle": None}
    fp, payload = hit
    dec = evaluate_gate(fp, key_path=resolve_key(store_dir, key_path),
                        key_registry_path=key_registry_path,
                        policy_name=policy, policy_file=policy_file)
    s = payload.get("subject", {})
    return {"found": True, "decision": dec.decision, "reasons": dec.reasons,
            "policy": dec.policy, "verdict": dec.verdict,
            "subject": "%s@%s (%s)" % (s.get("name", "?"), s.get("version", "?"),
                                       s.get("registry", "?")),
            "generated_at": payload.get("generated_at", ""),
            "bundle": fp}


def list_components(store_dir):
    """Latest attestation per (registry, name) - sorted, deduped."""
    seen = {}
    for fp, p in iter_bundles(store_dir):
        s = p.get("subject", {})
        key = (s.get("registry", "?"), s.get("name", "?"))
        gen = p.get("generated_at", "")
        if key not in seen or gen >= seen[key][0]:
            seen[key] = (gen, p.get("verdict", ""), s.get("version", ""), fp)
    return [{"registry": k[0], "name": k[1], "generated_at": v[0],
             "verdict": v[1], "version": v[2], "bundle": v[3]}
            for k, v in sorted(seen.items())]
