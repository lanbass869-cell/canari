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
