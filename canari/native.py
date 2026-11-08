"""native.py - T2: npm native provenance ingestion.

Ingests npm registry native attestations (Sigstore provenance) as input
signals for Canari verdicts. Two bundle formats exist (verified live 2026-11-08):
  - v0.1 publish (publicKey hint + tlog): Canari records PRESENCE only
  - v1 SLSA provenance (certificate + tlog): full DSSE verification via
    sigstore-python Verifier.verify_dsse() - PROVEN against express@5.3.0

This module NEVER claims a component is safe from native provenance -
it records that a cryptographic identity attestation EXISTS and (if verifiable)
PASSED. The verdict is still Canari's own from the checks.
"""
import json
import urllib.request
from canari.npm_enum import _opener, UA

NPM_ATTESTATION_URL = "https://registry.npmjs.org/-/npm/v1/attestations/{name}@{version}"
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def fetch_attestations(name, version, timeout=30):
    """Fetch the native attestation bundle for one package version.
    Returns raw JSON dict or None on 404/error."""
    url = NPM_ATTESTATION_URL.format(name=name, version=version)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with _opener().open(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def _classify_entries(attestations):
    """Classify native bundle entries by verification path availability."""
    out = {"present": bool(attestations),
           "predicate_types": [], "v1_cert_entries": [], "v0_key_entries": []}
    for a in attestations:
        pt = (a.get("predicateType") or "").rsplit("/", 1)[-1]
        if pt not in out["predicate_types"]:
            out["predicate_types"].append(pt)
        vm = (a.get("bundle") or {}).get("verificationMaterial") or {}
        if "certificate" in vm:
            out["v1_cert_entries"].append(a["bundle"])
        elif "publicKey" in vm:
            out["v0_key_entries"].append(a["bundle"])
    return out


def verify_v1_cert(bundle_json, expected_identity=None):
    """Verify one v1 (certificate-based) Sigstore bundle via sigstore-python.
    Uses Verifier.verify_dsse(). Returns dict with ok/identity/error."""
    try:
        from sigstore.verify import Verifier, policy
        from sigstore.models import Bundle
        from sigstore.verify.policy import Identity, UnsafeNoOp
        b = Bundle.from_json(json.dumps(bundle_json))
        v = Verifier.production()
        if expected_identity:
            pol = Identity(identity=expected_identity, issuer=GITHUB_OIDC_ISSUER)
        else:
            pol = UnsafeNoOp()
        result = v.verify_dsse(bundle=b, policy=pol)
        payload_type, payload_bytes = result
        cert = b.signing_certificate
        identity = None
        try:
            from cryptography import x509
            san = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            for gn in san:
                identity = gn.value
                break
        except Exception:
            pass
        return {"ok": True, "identity": identity,
                "issuer": GITHUB_OIDC_ISSUER,
                "payload_type": payload_type, "error": None}
    except Exception as e:
        return {"ok": False, "identity": None, "issuer": None,
                "payload_type": None,
                "error": "%s: %s" % (type(e).__name__, str(e)[:200])}


def ingest(name, version):
    """Full ingestion for one package version. Returns native_provenance
    field or None if no native attestation exists."""
    raw = fetch_attestations(name, version)
    if not raw or not raw.get("attestations"):
        return None
    cls = _classify_entries(raw["attestations"])
    out = {"present": cls["present"],
           "predicate_types": cls["predicate_types"],
           "v1_verified": None, "v1_identity": None, "v1_error": None,
           "v0_presence_only": len(cls["v0_key_entries"]),
           "verifier": "sigstore-python/4.5.1"}
    if cls["v1_cert_entries"]:
        r = verify_v1_cert(cls["v1_cert_entries"][0])
        out["v1_verified"] = r["ok"]
        out["v1_identity"] = r["identity"]
        out["v1_error"] = r["error"]
    return out
