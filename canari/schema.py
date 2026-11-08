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


def is_gate_passing(att):
    """Install-gate predicate: artifact hash matches latest attestation AND
    verdict is not gate-blocking. Per plan section 5.3:
    verdict NOT IN {fail, error} (pass-with-findings still installs).
    Unsupported/error are excluded from the gate - absence of a verdict is
    NOT a pass (dsh-testkit semantics: unsupported != failed != pass)."""
    v = (att or {}).get("verdict")
    if not v:
        return False
    return v in _LIVE_STATUSES
