# -*- coding: utf-8 -*-
"""signing.py - DSSE sign/verify via in-toto Envelope + securesystemslib 1.6.

Library choice per docs/research/lineF (reviewed conclusion, do NOT re-litigate):
  - in-toto 3.1.0 Envelope (DSSE payloadType application/vnd.in-toto+json)
  - securesystemslib 1.x CryptoSigner/SSlibKey (ed25519). NOTE: 1.x removed the
    old module-level API; verification lives on SSlibKey.verify_signature and
    SSlibKey.from_dict takes (keyid, key_dict).
  - PyPI package "dsse" is an UNRELATED project (Drone Swarm Search) - never install

Signature is over the DSSE PAE of the payload bytes. The inline
attestation["signature"] block mirrors keyid/sig for schema compliance; the
DSSE envelope in the bundle is the authoritative signature.
"""
import base64
import json

from canari.schema import _PREDICATE_TYPE

try:
    from in_toto.models.metadata import Envelope
    from securesystemslib.signer import CryptoSigner, SSlibKey
except ImportError as e:
    raise RuntimeError(
        "in-toto>=3.1 + securesystemslib are hard dependencies: "
        "pip install in-toto") from e

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def generate_keypair():
    """Generate an ed25519 keypair (securesystemslib 1.x CryptoSigner).

    Returns (signer: CryptoSigner, public_key: SSlibKey).
    Persist signer.private_bytes to a keystore; publish public_key.to_dict().
    """
    signer = CryptoSigner.generate_ed25519()
    return signer, signer.public_key


def sign_attestation(att: dict, signer) -> dict:
    """Sign the attestation; returns {"envelope": dict, "payload": dict}.

    The payload includes the inline signature block (schema-required), so we
    build payload -> sign -> inject sig -> re-sign. Verification always goes
    through the envelope; the inline block is informational/compliance.
    """
    def _build(a):
        payload_bytes = json.dumps(a, ensure_ascii=False, sort_keys=True).encode("utf-8")
        env = Envelope(payload=payload_bytes, payload_type=DSSE_PAYLOAD_TYPE, signatures={})
        sig = signer.sign(env.pae())
        env.signatures = {sig.keyid: sig}
        a2 = dict(a)
        a2["signature"] = {"envelope": "DSSE", "keyid": sig.keyid,
                           "sig": sig.signature, "payload_type": _PREDICATE_TYPE}
        return a2, env

    att1, _ = _build(att)      # pass 1: get keyid/sig for the inline block
    att2, env = _build(att1)   # pass 2: final payload incl. inline block
    return {"envelope": env.to_dict(), "payload": att2}


def verify_signed(envelope_dict: dict, public_key_dict: dict):
    """Verify a DSSE envelope against an SSlibKey dict.

    Returns (ok, payload_or_None, error_or_None). Never raises for verify
    failures - failures are data (the CLI prints them), not crashes.
    """
    try:
        env = Envelope.from_dict(envelope_dict)
        if len(env.signatures) != 1:
            return False, None, "expected exactly 1 signature, got %d" % len(env.signatures)
        keyid, sig_obj = next(iter(env.signatures.items()))
        # securesystemslib from_dict POPS all fields from key_dict (mutates!) -
        # pass a copy so the caller's key dict survives repeated verify calls.
        key = SSlibKey.from_dict(keyid, dict(public_key_dict))
        key.verify_signature(sig_obj, env.pae())
        payload = json.loads(env.payload.decode("utf-8"))
        return True, payload, None
    except Exception as e:
        return False, None, "%s: %s" % (type(e).__name__, str(e)[:200])


def export_public_key(public_key) -> str:
    """Public key as canonical JSON string (what we publish in keyring)."""
    return json.dumps(public_key.to_dict(), ensure_ascii=False, sort_keys=True)


def save_private_key(signer, path: str):
    """Persist signer private key (PEM) to a file for cross-run key reuse.
    Without this, every run generates a new keypair and all previous bundles
    fail signature verification (documented in baseline.py run())."""
    with open(path, "wb") as f:
        f.write(signer.private_bytes)


def load_private_key(path: str):
    """Load a persisted private key (PEM). Returns CryptoSigner or None.
    Uses cryptography library to parse PEM -> CryptoSigner constructor."""
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        pem = open(path, "rb").read()
        priv_key = load_pem_private_key(pem, password=None)
        return CryptoSigner(priv_key)
    except Exception:
        return None


def load_or_generate_keypair(key_path: str):
    """Load persisted private key or generate a new one. Returns (signer, pub_key, is_new).
    This is the correct way to maintain a stable signing identity across runs."""
    import os
    if os.path.exists(key_path):
        signer = load_private_key(key_path)
        if signer is not None:
            return signer, signer.public_key, False
    signer, pub_key = generate_keypair()
    save_private_key(signer, key_path)
    return signer, pub_key, True


def create_key_registry_entry(public_key, key_path: str) -> dict:
    """Create a key registry entry with lifecycle fields (mcpcheckup pattern).
    
    Fields:
      key_id: sha256(SPKI)[:16] - same derivation as mcpcheckup
      keytype, scheme, keyval: from SSlibKey.to_dict()
      valid_from: now (ISO 8601 UTC)
      valid_until: null (no expiry by default)
      revoked_at: null (not revoked)
      private_key_path: path to the persisted PEM file
    """
    import hashlib
    from datetime import datetime, timezone
    
    key_dict = public_key.to_dict()
    keyval = key_dict.get("keyval", {})
    public_bytes = keyval.get("public", "")
    
    # Derive key_id from the public key bytes (same as mcpcheckup)
    try:
        raw = base64.b64decode(public_bytes)
    except Exception:
        raw = public_bytes.encode("utf-8") if isinstance(public_bytes, str) else public_bytes
    key_id = hashlib.sha256(raw).hexdigest()[:16]
    
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    return {
        "key_id": key_id,
        "keytype": key_dict.get("keytype", "ed25519"),
        "scheme": key_dict.get("scheme", "Ed25519"),
        "keyval": keyval,
        "valid_from": now,
        "valid_until": None,
        "revoked_at": None,
        "private_key_path": key_path,
    }


def save_key_registry(registry: dict, path: str):
    """Save key registry to a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=1, ensure_ascii=False)


def load_key_registry(path: str) -> dict | None:
    """Load key registry from a JSON file. Returns None if missing/corrupt."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def revoke_key(registry: dict, reason: str = "") -> dict:
    """Mark a key as revoked. A revoked key's signatures are never accepted."""
    from datetime import datetime, timezone
    registry["revoked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if reason:
        registry["revocation_reason"] = reason
    return registry


def is_key_valid(registry_entry: dict, at_time: str = None) -> tuple[bool, str]:
    """Check if a key is valid at the given time (or now).
    Returns (valid, reason_if_invalid).
    
    Rules (mcpcheckup pattern):
      - revoked_at set: always invalid, whatever the time
      - at_time < valid_from: invalid
      - valid_until set and at_time > valid_until: invalid
      - Both ends inclusive
    """
    from datetime import datetime, timezone
    
    if registry_entry.get("revoked_at"):
        return False, "key was revoked at %s" % registry_entry["revoked_at"]
    
    valid_from = registry_entry.get("valid_from", "")
    if not valid_from:
        return False, "key has no valid_from"
    
    check_time = at_time or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    if check_time < valid_from:
        return False, "time %s is before key valid_from %s" % (check_time, valid_from)
    
    valid_until = registry_entry.get("valid_until")
    if valid_until and check_time > valid_until:
        return False, "time %s is after key valid_until %s" % (check_time, valid_until)
    
    return True, ""
