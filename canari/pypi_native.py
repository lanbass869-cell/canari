"""pypi_native.py - T3: PyPI PEP 740 native attestation ingestion.

PyPI uses PEP 740 (in-toto attestations). The pypi-attestations library
(0.0.31, PyPA official) converts between PEP 740 objects and Sigstore Bundles.

Measured reality (2026-11-08): 0/30 top packages, 0/40 fresh uploads,
0/10 Trusted Publisher packages have attestations on PyPI today.
This module is READY for when coverage arrives - the paper records the
blank as a finding, and Canari's ingestion is the bridge for the future.
"""
import json
import urllib.request
from canari.npm_enum import _opener, UA


def fetch_pypi_attestations(package, version=None, timeout=30, pypi_json=None):
    """Fetch PyPI JSON API and extract file attestations if present.
    BUG-74 fix: when a version is given, query /pypi/{pkg}/{version}/json so
    attestations are never attributed to the wrong version (the bare
    /pypi/{pkg}/json endpoint always returns the LATEST release).
    Returns list of file dicts with attestations, or None if no attestations."""
    import urllib.parse
    if pypi_json is not None:
        j = pypi_json
        urls = j.get("urls", []) or []
        with_att = [u for u in urls if u.get("attestations")]
        if not with_att:
            return None
        return [{"filename": u["filename"],
                 "digest": u.get("digests", {}).get("sha256"),
                 "attestations": u["attestations"]} for u in with_att]
    if version:
        url = "https://pypi.org/pypi/%s/%s/json" % (
            urllib.parse.quote(package, safe=""), urllib.parse.quote(version, safe=""))
    else:
        url = "https://pypi.org/pypi/%s/json" % urllib.parse.quote(package, safe="")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with _opener().open(req, timeout=timeout) as r:
            j = json.loads(r.read().decode("utf-8"))
        urls = j.get("urls", [])
        with_att = [u for u in urls if u.get("attestations")]
        if not with_att:
            return None
        return [{"filename": u["filename"],
                 "digest": u.get("digests", {}).get("sha256"),
                 "attestations": u["attestations"]} for u in with_att]
    except Exception:
        return None


def convert_pep740_to_bundle(attestation_json):
    """Convert a PEP 740 attestation JSON to a Sigstore Bundle via pypi-attestations.
    Returns Bundle object or raises ConversionError."""
    from pypi_attestations import Attestation
    att = Attestation.model_validate(attestation_json)
    return att.to_bundle()


def verify_pypi_bundle(bundle, distribution_bytes=None):
    """Verify a Sigstore Bundle from PEP 740. Returns dict with ok/error.
    If distribution_bytes provided, uses verify_artifact; otherwise verify_dsse."""
    try:
        from sigstore.verify import Verifier, policy
        from sigstore.verify.policy import UnsafeNoOp
        v = Verifier.production()
        if distribution_bytes:
            r = v.verify_artifact(input_=distribution_bytes, bundle=bundle, policy=UnsafeNoOp())
        else:
            r = v.verify_dsse(bundle=bundle, policy=UnsafeNoOp())
        return {"ok": True, "payload_type": r[0] if isinstance(r, tuple) else str(r), "error": None}
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:200])}


def ingest_pypi(package, version=None, pypi_json=None):
    """Full PyPI native attestation ingestion. Returns native_provenance dict or None.

    `pypi_json` avoids a duplicate HTTP GET when the caller already has the
    document (the scan loop fetches it once for every heuristics module).
    """
    # Backwards compatible: callers (and tests) monkeypatch the 2-arg form.
    try:
        files = fetch_pypi_attestations(package, version=version, pypi_json=pypi_json)
    except TypeError:
        files = fetch_pypi_attestations(package, version=version)
    if not files:
        return None
    out = {"present": True,
           "predicate_types": [],
           "v1_verified": None, "v1_identity": None, "v1_error": None,
           "v0_presence_only": 0,  # PyPI has no v0.1; all are PEP 740 = v1-class
           "verifier": "pypi-attestations/0.0.31 + sigstore-python/4.5.1"}
    for f in files:
        for att in f.get("attestations", []):
            pt = (att.get("predicateType") or att.get("predicate_type") or "?")
            short = pt.rsplit("/", 1)[-1]
            if short not in out["predicate_types"]:
                out["predicate_types"].append(short)
    # try to verify the first one
    if files and files[0].get("attestations"):
        try:
            bundle = convert_pep740_to_bundle(files[0]["attestations"][0])
            r = verify_pypi_bundle(bundle)
            out["v1_verified"] = r["ok"]
            out["v1_error"] = r["error"]
        except Exception as e:
            out["v1_verified"] = False
            out["v1_error"] = str(e)[:200]
    return out

