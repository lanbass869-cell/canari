# -*- coding: utf-8 -*-
"""score.py - Canari scoring card (MemTether hub_score pattern).

Four dimensions, each reproducible, no LLM judge, no subjective scoring:
  1. Coverage: what % of the target ecosystem have we attested?
  2. Freshness: what % of attestations are within their 7-day TTL?
  3. Integrity: what % of bundles pass signature + schema verification?
  4. Failure transparency: are fetch/parse errors counted and public?

Every score must be reported with: sample size, calculation method, known distortions.
(A score without these three is a lie - MemTether lesson, same discipline.)
"""
import json, os, time


def score(out_dir: str, public_key: dict = None, public_keys: list = None) -> dict:
    """Score the current state of the attestation store.
    Returns a dict with all four dimensions + distortions."""
    from canari.schema import validate_attestation
    from canari.signing import verify_signed

    att_dir = os.path.join(out_dir, "attestations")
    if not os.path.isdir(att_dir):
        return {"error": "no attestations directory"}

    bundles = sorted(f for f in os.listdir(att_dir) if f.endswith(".bundle.json"))
    total = len(bundles)
    if total == 0:
        return {"error": "empty attestation store"}

    n_sig_pass = 0
    n_schema_pass = 0
    n_fresh = 0
    n_expired = 0
    n_stale_no_expiry = 0
    errors = []

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ")

    for fname in bundles:
        if not fname.endswith(".bundle.json"):
            continue
        fpath = os.path.join(att_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                bundle = json.load(f)
        except Exception as e:
            errors.append({"file": fname, "error": str(e)[:80]})
            continue

        payload = bundle.get("payload", {})
        env = bundle.get("envelope", {})

        # integrity (if we have any public key from the signing-key history)
        keys = list(public_keys or [])
        if public_key:
            keys.insert(0, public_key)
        if keys:
            ok_any = False
            last_err = None
            for k in keys:
                ok, _, err = verify_signed(env, k)
                if ok:
                    ok_any = True
                    break
                last_err = err
            if ok_any:
                n_sig_pass += 1
            else:
                errors.append({"file": fname, "error": "sig: %s" % (last_err or "")[:60]})

        # schema
        schema_errors = validate_attestation(payload)
        if not schema_errors:
            n_schema_pass += 1

        # freshness (7-day TTL)
        expires = payload.get("expires_at", "")
        if expires:
            if expires > now:
                n_fresh += 1
            else:
                n_expired += 1
        else:
            n_stale_no_expiry += 1

    n_verified = n_sig_pass if (public_key or public_keys) else total

    return {
        "total_attestations": total,
        "coverage": {
            "description": "count of attested components (absolute, not % - ecosystem size varies)",
            "value": total,
        },
        "freshness": {
            "description": "% of attestations within 7-day TTL",
            "fresh": n_fresh,
            "expired": n_expired,
            "no_expiry": n_stale_no_expiry,
            "pct_fresh": round(n_fresh / total * 100, 1) if total else 0,
            "known_distortion": "first run will be 100% fresh; this metric only becomes meaningful after 2+ weeks",
        },
        "integrity": {
            "description": "% of bundles passing signature + schema verification",
            "sig_pass": n_sig_pass,
            "schema_pass": n_schema_pass,
            "pct_schema": round(n_schema_pass / total * 100, 1) if total else 0,
            "pct_sig": round(n_sig_pass / total * 100, 1) if total else 0,
            "key_available": bool(public_key),
        },
        "failure_transparency": {
            "description": "errors are counted, not hidden",
            "error_count": len(errors),
            "errors_sample": errors[:5],
        },
        "distortions": [
            "coverage is absolute count, not % of ecosystem (ecosystem size unknown)",
            "freshness is trivially 100% on first run (TTL not yet expired)",
            "integrity verification requires the private-run public key",
            "schema is v0.1 draft - field semantics may change after review",
        ],
    }


def format_report(score_dict: dict) -> str:
    """Human-readable scoring report."""
    if "error" in score_dict:
        return "ERROR: %s" % score_dict["error"]
    lines = ["=" * 60, "Canari Scoring Card", "=" * 60]
    lines.append("  Total attestations: %d" % score_dict["total_attestations"])
    f = score_dict["freshness"]
    lines.append("  Freshness: %.1f%% (%d fresh / %d expired)" % (f["pct_fresh"], f["fresh"], f["expired"]))
    i = score_dict["integrity"]
    lines.append("  Schema integrity: %.1f%%" % i["pct_schema"])
    if i["key_available"]:
        lines.append("  Signature integrity: %.1f%%" % i["pct_sig"])
    ft = score_dict["failure_transparency"]
    lines.append("  Errors: %d (all counted, none hidden)" % ft["error_count"])
    lines.append("-" * 60)
    lines.append("  Known distortions:")
    for d in score_dict.get("distortions", []):
        lines.append("    - %s" % d)
    lines.append("=" * 60)
    return "\n".join(lines)
