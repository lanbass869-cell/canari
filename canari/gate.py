"""gate.py - E1: Consumer-side install gate with policy engine.

Takes a signed attestation bundle and decides ALLOW / BLOCK / REVIEW.
Trustcheck's PolicySettings pattern: multiple built-in policies with
configurable thresholds. Canari's policies are simpler (verdict-based,
not CVE-based) but follow the same structure.

Usage:
    from canari.gate import evaluate_gate, GateDecision
    decision = evaluate_gate(bundle_path, key_path, policy="strict")
    # decision.decision == "ALLOW" | "BLOCK" | "REVIEW"
    # decision.reasons == list of human-readable strings
"""
import json
import os
from dataclasses import dataclass, field

from canari.schema import is_gate_passing
from canari.signing import verify_signed


@dataclass(slots=True)
class GatePolicy:
    """Controls when a component is allowed to install."""
    name: str = "default"
    min_verdict: str = "pass"
    require_fresh: bool = True
    require_key_valid: bool = True
    require_native_provenance: bool = False
    fail_on_error_check: bool = True
    allowed_registries: list = field(default_factory=list)


BUILTIN_POLICIES = {
    "default": GatePolicy(name="default"),
    "strict": GatePolicy(
        name="strict", min_verdict="pass", require_fresh=True,
        require_key_valid=True, fail_on_error_check=True,
    ),
    "release-gate": GatePolicy(
        name="release-gate", min_verdict="pass", require_fresh=True,
        require_key_valid=True, require_native_provenance=True,
        fail_on_error_check=True,
    ),
    "lax": GatePolicy(
        name="lax", min_verdict="pass", require_fresh=False,
        require_key_valid=False, fail_on_error_check=False,
    ),
}


@dataclass(slots=True)
class GateDecision:
    decision: str  # "ALLOW", "BLOCK", "REVIEW"
    reasons: list
    policy: str
    verdict: str = ""
    subject: str = ""
    fresh: bool = True
    key_valid: bool = True
    native_provenance_present: bool = False


def _check_freshness(payload):
    from datetime import datetime, timezone
    expires = payload.get("expires_at", "")
    if not expires:
        return True, None
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if now > expires:
        return False, "attestation expired at %s (now %s)" % (expires, now)
    return True, None


def evaluate_gate(bundle_path, key_path=None, key_registry_path=None,
                  policy_name="default", policy_overrides=None):
    if policy_name not in BUILTIN_POLICIES:
        raise ValueError("unknown policy: %s (available: %s)" % (policy_name, list(BUILTIN_POLICIES)))
    from dataclasses import replace
    policy = replace(BUILTIN_POLICIES[policy_name])
    if policy_overrides:
        for k, v in policy_overrides.items():
            if not hasattr(policy, k):
                continue  # unknown field silently skipped
            # Type validation for list fields
            if k == "allowed_registries" and not isinstance(v, list):
                raise ValueError("policy_overrides.allowed_registries must be a list, got %s" % type(v).__name__)
            setattr(policy, k, v)

    reasons = []
    decision = "ALLOW"

    try:
        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as e:
        return GateDecision(decision="BLOCK", reasons=["cannot read bundle: %s" % e], policy=policy_name)

    envelope = bundle.get("envelope")
    payload = bundle.get("payload", {})
    if not envelope:
        return GateDecision(decision="BLOCK", reasons=["bundle has no envelope"], policy=policy_name)

    verdict = payload.get("verdict", "error")
    subject = payload.get("subject", {})
    subject_name = "%s@%s (%s)" % (subject.get("name", "?"), subject.get("version", "?"), subject.get("registry", "?"))

    if key_path:
        if not os.path.exists(key_path):
            return GateDecision(decision="BLOCK",
                                reasons=["key file not found: %s (signature NOT verified)" % key_path],
                                policy=policy_name, verdict=verdict, subject=subject_name)
        try:
            with open(key_path, "r", encoding="utf-8") as f:
                pub = json.load(f)
        except Exception as e:
            return GateDecision(decision="BLOCK",
                                reasons=["key file is not valid JSON: %s" % e],
                                policy=policy_name, verdict=verdict, subject=subject_name)
        ok, _, err = verify_signed(envelope, pub)
        if not ok:
            return GateDecision(decision="BLOCK",
                                reasons=["signature verification FAILED: %s" % (err or "unknown")],
                                policy=policy_name, verdict=verdict, subject=subject_name)

    if not is_gate_passing(payload):
        decision = "BLOCK"
        reasons.append("verdict is %s (gate blocks)" % verdict)

    # Min verdict check: only "strict" blocks pass-with-findings
    if policy.min_verdict == "pass" and verdict == "pass-with-findings" and policy.name == "strict":
        decision = "BLOCK"
        reasons.append("policy %s requires verdict=pass, got pass-with-findings" % policy.name)

    if policy.require_fresh:
        fresh, reason = _check_freshness(payload)
        if not fresh:
            decision = "BLOCK"
            reasons.append("stale: %s" % reason)

    key_valid = True
    if policy.require_key_valid and key_registry_path and os.path.exists(key_registry_path):
        from canari.signing import load_key_registry, is_key_valid
        registry = load_key_registry(key_registry_path)
        if registry:
            key_valid, reason = is_key_valid(registry)
            if not key_valid:
                decision = "BLOCK"
                reasons.append("signing key invalid: %s" % reason)

    if policy.fail_on_error_check:
        error_checks = [c for c in payload.get("checks", []) if c.get("verdict") == "error"]
        if error_checks:
            if decision == "ALLOW":
                decision = "BLOCK"
            reasons.append("%d check(s) with verdict=error: %s" % (
                len(error_checks), ", ".join(c["id"] for c in error_checks[:3])))

    native_prov = payload.get("native_provenance")
    native_present = bool(native_prov and native_prov.get("present"))
    if policy.require_native_provenance and not native_present:
        if decision == "ALLOW":
            decision = "REVIEW"
        reasons.append("native provenance not present (policy requires it)")

    if policy.allowed_registries:
        reg = subject.get("registry", "")
        if reg not in policy.allowed_registries:
            decision = "BLOCK"
            reasons.append("registry %r not in allowed list" % reg)

    if verdict == "pass-with-findings" and decision == "ALLOW" and policy.name == "default":
        decision = "REVIEW"
        reasons.append("pass-with-findings: %d finding(s)" % sum(
            1 for c in payload.get("checks", [])
            if c.get("verdict") != "pass" or (c.get("evidence_ref") or "").startswith("finding:")
        ))

    return GateDecision(decision=decision, reasons=reasons, policy=policy_name,
                        verdict=verdict, subject=subject_name, key_valid=key_valid,
                        native_provenance_present=native_present)
