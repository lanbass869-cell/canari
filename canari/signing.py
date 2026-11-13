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
import re

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


def _nfc_normalize(obj):
    """Recursively NFC-normalize every string in a JSON-serializable structure.
    Prevents Unicode normalization differences from producing different hashes
    for the same logical content (mcpcheckup nfc-jcs/v1 pattern).
    Also detects NFC key collisions."""
    import unicodedata
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        result = {}
        seen_keys = {}
        for k, v in obj.items():
            normalized_key = unicodedata.normalize("NFC", k) if isinstance(k, str) else k
            if normalized_key in seen_keys:
                raise ValueError(
                    "NFC_KEY_COLLISION: keys %r and %r both normalize to %r"
                    % (seen_keys[normalized_key], k, normalized_key)
                )
            seen_keys[normalized_key] = k
            result[k] = _nfc_normalize(v)
        return result
    if isinstance(obj, list):
        return [_nfc_normalize(item) for item in obj]
    return obj


# Credential shape detection (mcpcheckup credential-shapes.ts pattern)
_CREDENTIAL_RULES = [
    ("jwt", lambda s: bool(re.match(r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", s))),
    ("authorization header", lambda s: bool(re.search(r"(?i)\b(?:bearer|basic|token|dpop)\s+[A-Za-z0-9._~+/-]{8,}", s))),
    ("private key block", lambda s: "-----BEGIN" in s and "PRIVATE KEY" in s),
    # Each alternative carries a MINIMUM LENGTH for the secret body. Without
    # one, ordinary identifiers match: "mcp-server-time-allenash-pypi-test"
    # contains "pypi-" and was rejected as a credential, which aborted an
    # entire 700-package scan (2026-11-13). Real tokens are long.
    ("vendor key prefix", lambda s: bool(re.search(
        r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"
        r"|gh[pousr]_[A-Za-z0-9]{30,}"
        r"|github_pat_[A-Za-z0-9_]{40,}"
        r"|xox[abprs]-[A-Za-z0-9-]{10,}"
        r"|glpat-[A-Za-z0-9_-]{20,}"
        r"|whsec_[A-Za-z0-9+/=]{16,}"
        r"|npm_[A-Za-z0-9]{30,}"
        r"|pypi-[A-Za-z0-9_-]{40,}"
        r"|AKIA[0-9A-Z]{16}"
        r"|AIza[0-9A-Za-z_-]{20,}", s))),
    ("long hex run", lambda s: bool(re.search(r"(?:^|[^0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z])", s))),
    ("high-entropy token", lambda s: any(
        len(p) >= 24 and any(c.isupper() for c in p) and any(c.islower() for c in p) and any(c.isdigit() for c in p)
        for p in re.split(r"[^A-Za-z0-9+/=_-]+", s)
    )),
    ("credential variable access", lambda s: bool(re.search(
        r"(?:password|secret|token|api_key|credential|private_key)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_-]{8,}", s, re.I
    ))),
]


# Fields whose values are our own computed hashes/digests - exempt from credential scanning
# (mcpcheckup does the same: OWN_VALUE_PATHS in credential-shapes.ts)
_OWN_HASH_FIELDS = {
    "artifact_sha256", "scenario_sha256", "suite_digest", "suite_commit",
    "launch_config_digest", "toolset_fingerprint", "schema_fingerprint", "run_id",
    # DSSE signature fields - these are our own cryptographic outputs, not credentials
    "keyid", "sig",
    # Canonicalization profile identifier
    "canonicalization",
    # Public metadata fields - not credentials
    "homepage",
    # Supersession chain and revocation references (contain our own digests)
    "supersedes", "ref",
    # Provenance identity references: a Sigstore identity ends with the git commit
    # SHA (".../release.yml@af0ad67c..."), which is a *reference*, not a secret.
    # Without this exemption the long-hex-run rule rejects every npm package whose
    # provenance comes from a SHA-pinned workflow - the attestation is downgraded
    # to "error" and the component is lost from the ledger (BUG-97).
    "v1_identity",
}


def credential_shapes(value, path="") -> list:
    """Find credential-shaped strings anywhere in a JSON-serializable value.
    Returns list of "<path>: <rule>" strings. Empty = clean.
    Percent-decoded forms are also checked (mcpcheckup pattern).
    Fields in _OWN_HASH_FIELDS are exempt (they're our own computed digests)."""
    import urllib.parse
    # Skip our own hash fields
    leaf = path.split(".")[-1] if path else ""
    if leaf in _OWN_HASH_FIELDS:
        return []
    results = []
    if isinstance(value, str):
        decoded = urllib.parse.unquote(value)
        for name, matcher in _CREDENTIAL_RULES:
            if matcher(value) or matcher(decoded):
                results.append("%s: %s" % (path or "<root>", name))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            results.extend(credential_shapes(v, "%s.%d" % (path, i) if path else str(i)))
    elif isinstance(value, dict):
        for k, v in value.items():
            # Skip evidence_refs - registry references like "pypi-json:name", not credentials
            if k == "evidence_refs":
                continue
            # Skip signature dict - our own crypto outputs (keyid, sig)
            if k == "signature":
                continue
            results.extend(credential_shapes(v, "%s.%s" % (path, k) if path else k))
    return results


STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


def payload_digest(predicate: dict) -> str:
    """Canonical digest of an attestation body, EXCLUDING the inline signature.

    Why exclude: the inline signature block is a by-product of signing (it is
    re-derived on every re-sign) and the DSSE envelope is the authoritative
    signature. Including it made the supersession chain self-destruct on any
    re-sign - every historical pointer became dangling. The digest must be a
    function of the *content*, not of the signature over it.
    """
    body = {k: v for k, v in (predicate or {}).items() if k != "signature"}
    return hashlib_sha256(json.dumps(body, ensure_ascii=False, sort_keys=True))


def hashlib_sha256(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def subject_ref(predicate: dict) -> dict:
    """Build the in-toto `subject` entry for a predicate.

    A real artifact hash is used as `sha256`. When the artifact bytes were
    never obtained (registry metadata only), we must NOT fabricate a sha256 -
    an all-zero digest would look like a real one to any consumer. In that case
    the subject carries an explicit `canari-component-id` digest (sha256 over
    the canonical component reference) and the predicate records
    `subject_digest_basis = "component-identity"`.
    """
    s = (predicate or {}).get("subject", {}) or {}
    registry = s.get("registry", "")
    name = s.get("name", "")
    version = s.get("version", "") or ""
    ref = "%s:%s@%s" % (registry, name, version) if version else "%s:%s" % (registry, name)
    art = (s.get("artifact_sha256") or "").lower()
    if len(art) == 64 and art != "0" * 64 and all(c in "0123456789abcdef" for c in art):
        return {"name": ref, "digest": {"sha256": art}}
    return {"name": ref, "digest": {"canari-component-id": hashlib_sha256(ref)}}


def build_statement(predicate: dict) -> dict:
    """Wrap an attestation body in an in-toto Statement v1 (SLSA/GUAC/cosign compatible)."""
    # NOTE: the predicate is embedded VERBATIM. Adding derived fields here
    # would make the signed predicate diverge from the unsigned top-level
    # mirror, which check_payload_integrity() treats as tampering. The digest
    # basis is recoverable from the subject's digest algorithm name.
    return {
        "_type": STATEMENT_TYPE,
        "subject": [subject_ref(predicate)],
        "predicateType": _PREDICATE_TYPE,
        "predicate": dict(predicate),
    }


def unwrap_statement(payload: dict) -> dict:
    """Return the attestation body from a signed payload.

    Accepts both the in-toto Statement v1 wrapper (current format) and the bare
    attestation body written by releases before the migration, so historical
    bundles keep verifying against the same key.
    """
    if not isinstance(payload, dict):
        return {}
    if payload.get("_type") == STATEMENT_TYPE and isinstance(payload.get("predicate"), dict):
        return payload["predicate"]
    return payload


def sign_attestation(att: dict, signer) -> dict:
    """Sign the attestation; returns {"envelope": dict, "payload": statement,
    "predicate": attestation}.

    The DSSE payload is an in-toto Statement v1 whose `predicate` is the
    Canari attestation. The statement carries the standard fields every
    in-toto consumer (GUAC, cosign, slsa-verifier) needs to build graph edges.

    The payload includes the inline signature block (schema-required), so we
    build predicate -> sign -> inject sig -> re-sign. Verification always goes
    through the envelope; the inline block is informational/compliance.

    Credential shape detection (mcpcheckup pattern): scans the payload before
    signing to prevent accidentally embedding credentials in a public artifact.
    """
    # Credential scan before signing
    cred_hits = credential_shapes(att)
    if cred_hits:
        raise ValueError(
            "CREDENTIAL_IN_PAYLOAD: %d credential-shaped string(s) detected in the attestation: %s"
            % (len(cred_hits), "; ".join(cred_hits[:5]))
        )

    # NFC normalization (mcpcheckup nfc-jcs/v1 pattern)
    att = _nfc_normalize(att)

    def _build(a):
        stmt = build_statement(a)
        payload_bytes = json.dumps(stmt, ensure_ascii=False, sort_keys=True).encode("utf-8")
        env = Envelope(payload=payload_bytes, payload_type=DSSE_PAYLOAD_TYPE, signatures={})
        sig = signer.sign(env.pae())
        env.signatures = {sig.keyid: sig}
        a2 = dict(a)
        a2["signature"] = {"envelope": "DSSE", "keyid": sig.keyid,
                           "sig": sig.signature, "payload_type": _PREDICATE_TYPE}
        return a2, env

    att1, _ = _build(att)      # pass 1: get keyid/sig for the inline block
    att2, env = _build(att1)   # pass 2: final payload incl. inline block
    # `payload` is the bare attestation body: it is the unsigned convenience
    # mirror written next to the bundle (same role as before the migration) and
    # the thing callers hash for supersession. The in-toto Statement wrapper
    # lives ONLY inside envelope.payload, which is what external consumers
    # (GUAC / cosign / slsa-verifier) read.
    return {"envelope": env.to_dict(), "payload": att2,
            "statement": build_statement(att2), "predicate": att2}


def legacy_payload_digest(predicate: dict) -> str:
    """Digest as computed by releases before the in-toto migration.

    That version hashed the CANONICAL FULL attestation including the inline
    `signature` block. It is kept only so chains written by those releases keep
    resolving; new bundles use payload_digest() (signature-independent).
    """
    return hashlib_sha256(json.dumps(predicate or {}, ensure_ascii=False, sort_keys=True))


def read_signed_statement(bundle: dict):
    """Return the DSSE-signed payload EXACTLY as signed (statement or legacy body).

    A bundle file stores two copies of the signed content:

      envelope.payload  - base64 of the canonical JSON; this is what is signed
      payload           - a convenience copy for readers, NOT covered by the sig

    Anything that makes a decision must read the signed copy. Returns
    (payload, error).
    """
    import base64
    if not isinstance(bundle, dict):
        return None, "bundle is not a JSON object"
    env = bundle.get("envelope")
    # ★2026-11-11 (F1): NO FALLBACK. If the envelope is absent, is not an
    # object, or carries no decodable payload, this file has no signed content
    # and must be treated as unusable. An earlier version silently fell back to
    # the UNSIGNED top-level copy, which let an attacker delete
    # envelope.payload and then edit that copy freely - restoring the exact
    # bypass this function exists to prevent.
    if not isinstance(env, dict):
        return None, "bundle has no DSSE envelope (cannot be trusted)"
    if not env.get("payload"):
        return None, "DSSE envelope has no payload (cannot be trusted)"
    try:
        raw = base64.b64decode(env["payload"])
        payload = json.loads(raw.decode("utf-8"))
    except Exception as e:                                   # noqa: BLE001
        return None, "cannot decode signed payload: %s" % e
    if not isinstance(payload, dict):
        return None, "signed payload is not a JSON object (%s)" % type(payload).__name__
    return payload, None


def read_signed_payload(bundle: dict):
    """Return the signed ATTESTATION body (in-toto `predicate`), never the wrapper.

    Consumers reason about verdict/subject/checks, so this unwraps the in-toto
    Statement v1 envelope. Bundles written before the migration carried the bare
    attestation; unwrap_statement() returns those unchanged.
    """
    payload, err = read_signed_statement(bundle)
    if err:
        return None, err
    return unwrap_statement(payload), None


def check_payload_integrity(bundle: dict):
    """Verify the unsigned top-level copy agrees with the signed one.

    Returns (ok, reason, signed_predicate).

    The top-level ``payload`` mirrors what was signed (an in-toto Statement v1).
    The two copies are written with different inline ``signature`` blocks
    (pass 1 vs pass 2 of sign_attestation), so every other field must match
    exactly. Divergence means somebody edited the copy that is not protected by
    the signature - the bypass that let a tampered bundle report a pass while
    the signature still verified.
    """
    signed_stmt, err = read_signed_statement(bundle)
    if err:
        return False, err, None
    signed = unwrap_statement(signed_stmt)
    top_stmt = bundle.get("payload")
    if not isinstance(top_stmt, dict):
        return False, "bundle has no top-level payload", signed
    top = unwrap_statement(top_stmt)

    # The mirror is always the bare attestation body, while the signed payload
    # is an in-toto Statement wrapping it (or a bare body on legacy bundles).
    # unwrap_statement() normalises both, so only the body is compared.

    # Compare canonical BYTES, not Python values: {"v": true} == {"v": 1} and
    # {"v": 1} == {"v": 1.0} are equal as Python dicts, so a value-level
    # comparison can miss a text-level edit of the unsigned copy.
    def _canon(d):
        return json.dumps({k: v for k, v in d.items() if k != "signature"},
                          ensure_ascii=False, sort_keys=True).encode("utf-8")
    a_raw, b_raw = _canon(top), _canon(signed)
    if a_raw != b_raw:
        a = {k: v for k, v in top.items() if k != "signature"}
        b = {k: v for k, v in signed.items() if k != "signature"}
        changed = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
        return False, (
            "top-level payload does not match the signed payload "
            "(differing fields: %s)" % ", ".join(changed[:8] or ["<byte-level>"])
        ), signed
    return True, None, signed


def verify_signed_raw(envelope_dict: dict, public_key_dict: dict):
    """Verify a DSSE envelope; return the payload EXACTLY as signed.

    For current bundles the payload is an in-toto Statement v1; for bundles
    written before the migration it is the bare attestation body.

    Returns (ok, payload_or_None, error_or_None). Never raises for verify
    failures - failures are data (the CLI prints them), not crashes.
    """
    try:
        import copy as _copy
        # BUG-81: from_dict consumes/mutates its input; never touch the caller's dict
        env = Envelope.from_dict(_copy.deepcopy(envelope_dict))
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


def verify_signed(envelope_dict: dict, public_key_dict: dict):
    """Verify a DSSE envelope and return the ATTESTATION (predicate).

    The in-toto Statement v1 wrapper is an integration detail; every consumer
    in this codebase wants verdict/subject/checks, so this unwraps by default.
    Use verify_signed_raw() when the statement itself is the subject of the
    check (e.g. asserting in-toto compliance).
    """
    ok, payload, err = verify_signed_raw(envelope_dict, public_key_dict)
    if not ok:
        return False, None, err
    return True, unwrap_statement(payload), None


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
    This is the correct way to maintain a stable signing identity across runs.
    BUG-73 fix: a CORRUPTED existing PEM is backed up (never overwritten) and a
    loud warning is printed before regenerating - silent key loss orphans every
    previously signed bundle and breaks the audit trail."""
    import os
    import shutil
    if os.path.exists(key_path):
        signer = load_private_key(key_path)
        if signer is not None:
            return signer, signer.public_key, False
        # key file exists but cannot be parsed -> do NOT silently destroy it
        backup = key_path + ".corrupt-" + str(int(__import__("time").time()))
        try:
            shutil.copy2(key_path, backup)
            print("[key] WARNING: existing key file is corrupt; backed up to %s" % backup)
        except OSError as e:
            print("[key] WARNING: existing key file is corrupt AND backup failed: %s" % e)
        print("[key] WARNING: generating a NEW keypair - all bundles signed with the old key will no longer verify against the new public key")
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

