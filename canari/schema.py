# -*- coding: utf-8 -*-
"""schema.py - attestation JSON Schema loading + validation (M0 task 1).

Single source of truth: schemas/attestation-v0.1.json, byte-copied from the
private handover repo docs/canari/attestation-v0.1.schema.json (commit
fd37b18). Field semantics live THERE; any semantic change must go through
the WorkBuddy review line (HANDOVER-canari.md section 5).

The sync test (tests/test_schema_sync.py) fails loudly if the two copies
drift - the same pattern as MemTether's dual_repo_guard.
"""
import json
import os

# schema lives inside the package (pip-installable); repo-level schemas/ is a
# byte-copy for the sync test. Source of truth: the handover repo's draft.
_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "attestation-v0.1.json")

_PREDICATE_TYPE = "https://agentcheck.dev/attestation/v0.1"

_LIVE_STATUSES = frozenset({"pass", "pass-with-findings"})
# verdicts that must block an install gate (plan section 5.3)
_GATE_BLOCKING = frozenset({"fail", "error"})


def load_schema():
    """Load the bundled JSON Schema (2020-12). Raises if file missing."""
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_attestation(att):
    """Validate an attestation dict against the schema.

    Returns list of human-readable error strings; empty list = valid.
    (We never raise for schema errors - callers decide pass/fail and the
    failure must be observable in output, not as a traceback.)
    """
    try:
        from jsonschema import Draft202012Validator
    except ImportError as e:
        raise RuntimeError("jsonschema is a hard dependency: pip install jsonschema") from e
    schema = load_schema()
    validator = Draft202012Validator(schema)
    errors = []
    for err in sorted(validator.iter_errors(att), key=lambda e: list(e.absolute_path)):
        path = "/".join(str(p) for p in err.absolute_path) or "<root>"
        errors.append("%s: %s" % (path, err.message))
    return errors


def assert_unverified_has_reason(att: dict):
    """Independent invariant check (mcpcheckup pattern, third layer).
    
    Layer 1: JSON Schema (anyOf/then on checks[].assertion_status)
    Layer 2: this function (independent of schema, doesn't trust schema is correct)
    Layer 3: verify_cli.py output (prints warning for UNVERIFIED without reason)
    
    Rule: assertion_status == 'UNVERIFIED' must have either reason or
    unverified_reason with a non-empty key. Empty key counts as missing.
    """
    return unverified_without_reason(att)


def unverified_without_reason(att: dict) -> list:
    """IDs of 'unsupported' checks that carry no explanation.

    F6: the documented invariant is "an unsupported check must say WHY it could
    not run". This used to be a `pass` placeholder that nobody called, so the
    rule was advertised in three docstrings and enforced nowhere. It now
    returns the offending check ids so callers can surface/reject them.
    """
    bad = []
    for check in (att or {}).get("checks", []):
        if check.get("verdict") != "unsupported":  # Canari uses "unsupported"
            continue
        evidence = check.get("evidence_ref") or ""
        if not evidence.strip():
            bad.append(check.get("id", "<no-id>"))
    return bad


def verdict_semantics():
    """Documented meaning of each run verdict (consumers depend on this)."""
    return {
        "pass": "every substantive check produced evidence and none failed",
        "pass-with-findings": "checks ran; at least one recorded a finding or non-pass "
                              "detail that the operator should read",
        "fail": "at least one substantive check failed",
        "unsupported": "the checks could not be performed (missing data/artifact); "
                       "this is NOT a pass - absence of evidence is not evidence of safety",
        "error": "the pipeline could not complete; the attestation records the failure",
    }


# Checks that establish something substantive about the COMPONENT, as opposed
# to merely proving its name exists in a registry. Two legitimate families:
#   1. we fetched the bytes ourselves   (L2.1 hash / L3.1 static scan)
#   2. an upstream authority evaluated it (L2.7 / L2.8 = dsh.so install+security
#      conclusions, which Canari references rather than re-derives)
# Measured 2026-11-14 against the live store: with family 1 only, 321 dsh
# records that DO carry upstream install/security conclusions were wrongly
# blocked; adding family 2 keeps every legitimately-evidenced record (1157) and
# still blocks the 346 registry-presence-only records.
_ARTIFACT_EVIDENCE_IDS = frozenset({
    "L2.1_ARTIFACT_HASH",
    "L3.1_STATIC_SCAN",
    "L2.7_PLUGIN_SECURITY_REF",
    "L2.8_PLUGIN_INSTALL_REF",
})


def has_artifact_evidence(att):
    """True if at least one check actually assessed the artifact (not just its name).

    ★2026-11-13: 346 published mcp-registry records carried verdict
    `pass-with-findings` with ONE check - L1.1_REGISTRY_PRESENT - and an
    all-zero artifact_sha256. Under `lax` the gate said ALLOW, and
    `canari-verify` printed "gate: ALLOW". Nothing about the component was
    verified. A verdict without artifact evidence must never read as
    installable.
    """
    checks = (att or {}).get("checks") or []
    for c in checks:
        if c.get("id") in _ARTIFACT_EVIDENCE_IDS and c.get("verdict") in ("pass", "pass-with-findings"):
            return True
        # an explicit "we could not check the bytes" verdict is evidence of
        # ABSENCE, not of safety, so it never counts
    return False


def is_gate_passing(att):
    """Install-gate predicate: artifact hash matches latest attestation AND
    verdict is not gate-blocking. Per plan section 5.3:
    verdict NOT IN {fail, error} (pass-with-findings still installs).
    Unsupported/error are excluded from the gate - absence of a verdict is
    NOT a pass (dsh-testkit semantics: unsupported != failed != pass).

    ★2026-11-13: additionally requires ARTIFACT evidence. A record whose only
    check is registry presence is not a passing verdict - see
    has_artifact_evidence().
    """
    v = (att or {}).get("verdict")
    if not v:
        return False
    if v not in _LIVE_STATUSES:
        return False
    return has_artifact_evidence(att)
