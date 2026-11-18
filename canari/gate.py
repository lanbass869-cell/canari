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

from canari.schema import has_byte_evidence, is_gate_passing
from canari.signing import verify_signed


@dataclass(slots=True)
class GatePolicy:
    """Controls when a component is allowed to install."""
    name: str = "default"
    require_fresh: bool = True
    require_key_valid: bool = True
    require_native_provenance: bool = False
    fail_on_error_check: bool = True
    allowed_registries: list = field(default_factory=list)
    # G1: trust heuristics (L2.4 cadence / L2.5 metadata anomaly / L2.6 typosquat)
    # recorded as checks with evidence_ref "finding: ...". block_on_findings
    # upgrades the pass-with-findings REVIEW to BLOCK for a deny-by-default posture.
    block_on_findings: bool = False
    # strict posture: a pass-with-findings verdict is not installable
    allow_findings: bool = True
    # F7: should pass-with-findings escalate ALLOW -> REVIEW? default/strict/
    # custom policies say yes (a human should read the findings); the explicitly
    # lax posture says no. Keyed on this field, never on the policy *name*.
    review_findings: bool = True
    # Optional list of finding kinds to always treat as blocking, e.g.
    # ["typosquatting", "metadata", "cadence"]; empty = no keyword blocking.
    block_finding_kinds: list = field(default_factory=list)
    # ★2026-11-18: by default a relayed upstream conclusion (L2.7 / L2.8 from
    # dsh.so) counts as evidence that the artifact was assessed. That is a
    # weaker claim than "we fetched and hashed these bytes". Policies that need
    # the stronger claim set this to True; the `artifact-only` builtin does.
    require_artifact_bytes: bool = False
    # ★2026-11-18: require a signed identity claim that ties this record's
    # publishing repository to the cluster the consumer trusts. Off by default:
    # turning it on changes allow/block decisions, so it must be asked for.
    require_identity: bool = False


BUILTIN_POLICIES = {
    "default": GatePolicy(name="default"),
    "strict": GatePolicy(
        name="strict", require_fresh=True,
        require_key_valid=True, fail_on_error_check=True, allow_findings=False,
    ),
    "release-gate": GatePolicy(
        name="release-gate", require_fresh=True,
        require_key_valid=True, require_native_provenance=True,
        fail_on_error_check=True, allow_findings=False,
    ),
    "lax": GatePolicy(
        name="lax", require_fresh=False,
        require_key_valid=False, fail_on_error_check=False,
        review_findings=False,
    ),
    # artifact-only: a relayed upstream verdict is not enough; we must have
    # hashed or scanned the bytes ourselves.
    "artifact-only": GatePolicy(
        name="artifact-only", require_fresh=True,
        require_key_valid=True, fail_on_error_check=True,
        require_artifact_bytes=True,
    ),
    # G1: paranoid = any trust-heuristic finding blocks outright
    "paranoid": GatePolicy(
        name="paranoid", require_fresh=True,
        require_key_valid=True, fail_on_error_check=True,
        block_on_findings=True, allow_findings=False,
    ),
}


def load_policy_file(path: str) -> dict:
    """G2: load a JSON policy-file definition.

    Accepted keys are exactly the GatePolicy fields minus name (name comes
    from the file's "name" key or defaults to "file"). Unknown keys raise
    ValueError (config typos must fail loudly, not silently no-op).
    Returns kwargs dict suitable for policy_overrides plus "name".
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError("policy file must contain a JSON object")
    import dataclasses
    valid_fields = {fl.name for fl in dataclasses.fields(GatePolicy)}
    unknown = set(raw) - valid_fields
    if unknown:
        raise ValueError("unknown policy keys: %s (valid: %s)" % (
            sorted(unknown), sorted(valid_fields)))
    out = dict(raw)
    if not out.get("name"):
        out["name"] = "file"
    if out.get("allowed_registries") is not None and not isinstance(out["allowed_registries"], list):
        raise ValueError("allowed_registries must be a list")
    if out.get("block_finding_kinds") is not None and not isinstance(out["block_finding_kinds"], list):
        raise ValueError("block_finding_kinds must be a list")
    for bool_key in ("require_fresh", "require_key_valid", "require_native_provenance",
                     "fail_on_error_check", "block_on_findings", "allow_findings",
                     "require_artifact_bytes", "require_identity"):
        if bool_key in out and not isinstance(out[bool_key], bool):
            raise ValueError("%s must be a boolean" % bool_key)
    return out


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


def _check_identity(payload, claim_path, key_path, policy):
    """Is this record's repository the cluster's repository?

    Requires a *signed* claim. A claim we cannot verify is not evidence of
    identity, and an attestation with no repository cannot be tied to any
    cluster - both are reported as failures, never as a pass.
    """
    from canari.identity import normalize_repo, validate_claim
    from canari.signing import verify_signed

    repo = normalize_repo((payload.get("subject") or {}).get("repository"))
    if not repo:
        return False, ("identity required but this attestation records no publishing "
                       "repository; identity cannot be established")
    if not claim_path:
        return False, ("policy %s requires an identity claim and none was supplied "
                       "(--identity-claim PATH)" % policy.name)
    if not os.path.exists(claim_path):
        return False, "identity claim not found: %s" % claim_path
    if not key_path:
        return False, "identity claim given without a public key: signature cannot be verified"
    try:
        with open(claim_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        with open(key_path, "r", encoding="utf-8") as f:
            pub = json.load(f)
    except Exception as e:
        return False, "identity claim unreadable: %s" % str(e)[:120]
    good, claim, err = verify_signed(bundle.get("envelope") or {}, pub)
    if not good or not isinstance(claim, dict):
        return False, "identity claim signature FAILED: %s" % (err or "unknown")
    bad = validate_claim(claim)
    if bad:
        return False, "identity claim malformed: %s" % "; ".join(bad[:2])
    claimed = normalize_repo((claim.get("subject") or {}).get("repository"))
    if claimed != repo:
        return False, ("identity mismatch: attestation publishes from %s, claim covers %s"
                       % (repo, claimed))
    return True, "identity confirmed: %s" % repo


def _check_freshness(payload):
    from datetime import datetime, timezone
    expires = payload.get("expires_at", "")
    if not expires:
        # F10: an attestation with no expiry cannot be shown to be current.
        # Treating "missing" as "fresh" turned a data problem into a pass.
        return False, "no expires_at recorded (freshness cannot be established)"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if now > expires:
        return False, "attestation expired at %s (now %s)" % (expires, now)
    return True, None


def evaluate_gate(bundle_path, key_path=None, key_registry_path=None,
                  policy_name="default", policy_overrides=None, policy_file=None,
                  allow_unsigned=False, identity_claim_path=None):
    from dataclasses import replace
    if policy_file:
        file_def = load_policy_file(policy_file)
        policy_name = file_def.get("name", "file")
        file_overrides = {k: v for k, v in file_def.items() if k != "name"}
        # custom file-defined name: clone default as its base (explicit in file,
        # never silently aliased to a builtin)
        BUILTIN_POLICIES.setdefault(policy_name, replace(BUILTIN_POLICIES["default"], name=policy_name))
        policy_overrides = {**(policy_overrides or {}), **file_overrides}
    if policy_name not in BUILTIN_POLICIES:
        raise ValueError("unknown policy: %s (available: %s)" % (policy_name, list(BUILTIN_POLICIES)))
    from dataclasses import replace
    policy = replace(BUILTIN_POLICIES[policy_name])
    if policy_overrides:
        for k, v in policy_overrides.items():
            if not hasattr(policy, k):
                continue  # unknown field silently skipped
            # F8: validate EVERY field against its declared type. Previously
            # only list fields were checked, so allow_findings="false" (a truthy
            # string) silently switched a strict policy off.
            import dataclasses as _dc
            _f = {f.name: f for f in _dc.fields(GatePolicy)}.get(k)
            if _f is None:
                continue
            _type = _f.type
            if _type in (bool, "bool") and not isinstance(v, bool):
                raise ValueError("policy_overrides.%s must be a bool, got %s"
                                 % (k, type(v).__name__))
            if _type in (list, "list") and not isinstance(v, list):
                raise ValueError("policy_overrides.%s must be a list, got %s"
                                 % (k, type(v).__name__))
            if _type in (str, "str") and not isinstance(v, str):
                raise ValueError("policy_overrides.%s must be a string, got %s"
                                 % (k, type(v).__name__))
            setattr(policy, k, v)

    reasons = []
    decision = "ALLOW"

    try:
        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as e:
        return GateDecision(decision="BLOCK", reasons=["cannot read bundle: %s" % e], policy=policy_name)

    if not isinstance(bundle, dict):
        return GateDecision(decision="BLOCK",
                            reasons=["bundle is valid JSON but not an object: %s" % type(bundle).__name__],
                            policy=policy_name)
    envelope = bundle.get("envelope")
    if not envelope:
        return GateDecision(decision="BLOCK", reasons=["bundle has no envelope"], policy=policy_name)

    # ★2026-11-11 BUG-102 (signature bypass): the file carries TWO payloads -
    # the DSSE-signed one inside `envelope.payload` and an unsigned top-level
    # copy. The gate used to judge the unsigned copy while only verifying the
    # signed one, so editing the top-level verdict to "pass" produced ALLOW
    # with signature_ok=true. Decisions must come from the signed payload, and
    # any divergence must fail closed.
    from canari.signing import check_payload_integrity
    ok_integrity, integrity_reason, payload = check_payload_integrity(bundle)
    if payload is None:
        return GateDecision(decision="BLOCK",
                            reasons=["signed payload unreadable: %s" % integrity_reason],
                            policy=policy_name)
    if not ok_integrity:
        return GateDecision(decision="BLOCK",
                            reasons=["payload integrity check FAILED: %s" % integrity_reason],
                            policy=policy_name,
                            verdict=payload.get("verdict", "error"))

    verdict = payload.get("verdict", "error")
    subject = payload.get("subject", {})
    subject_name = "%s@%s (%s)" % (subject.get("name", "?"), subject.get("version", "?"), subject.get("registry", "?"))

    # ★2026-11-13 (F1) FAIL-CLOSED ON MISSING KEY.
    # evaluate_gate() used to skip signature verification entirely when
    # key_path was None, so `evaluate_gate(forged_bundle)` returned ALLOW for a
    # bundle whose verdict had been rewritten. Demonstrated: take an
    # `unsupported` record, flip the signed payload to `pass`, re-encode - gate
    # said ALLOW with no reasons. A decision that cannot be tied to a signature
    # is not a decision, so the only correct default is BLOCK.
    # Callers that genuinely want an unsigned structural check must ask for it
    # explicitly with allow_unsigned=True, and the result is REVIEW at best.
    if key_path is None and not allow_unsigned:
        return GateDecision(
            decision="BLOCK",
            reasons=["no public key supplied: the bundle's signature cannot be "
                     "verified, so its verdict cannot be trusted "
                     "(pass key_path=..., or allow_unsigned=True for a "
                     "structural-only check)"],
            policy=policy_name, verdict=verdict, subject=subject_name,
            key_valid=False)
    if not key_path:
        # explicit opt-in: never ALLOW without a signature
        reasons.append("UNVERIFIED: signature check skipped (allow_unsigned=True); "
                       "this is a structural check only, not a trust decision")
        if decision == "ALLOW":
            decision = "REVIEW"

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

    if policy.require_identity or identity_claim_path:
        ok, why = _check_identity(payload, identity_claim_path, key_path, policy)
        if not ok:
            if decision == "ALLOW":
                decision = "BLOCK"
            reasons.append(why)

    if policy.require_artifact_bytes and not has_byte_evidence(payload):
        if decision == "ALLOW":
            decision = "BLOCK"
        reasons.append(
            "policy %s requires byte-level evidence (L2.1 artifact hash or L3.1 "
            "static scan); this record only relays an upstream conclusion"
            % policy.name)

    # Strict postures (strict / paranoid / release-gate) do not accept
    # pass-with-findings; the field is explicit so policy files can override it.
    if not policy.allow_findings and verdict == "pass-with-findings":
        decision = "BLOCK"
        reasons.append("policy %s requires verdict=pass, got pass-with-findings" % policy.name)

    # F11: `fresh` must exist for every policy, not only require_fresh ones.
    fresh = True
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

    # F7: previously keyed on policy.name == "default", so a custom policy file
    # (name "corp" etc.) silently ALLOWed findings. Key it on the semantic knob.
    if verdict == "pass-with-findings" and decision == "ALLOW" and policy.review_findings:
        decision = "REVIEW"
        checks = payload.get("checks", [])
        n_find = sum(1 for c in checks if (c.get("evidence_ref") or "").startswith("finding:"))
        n_nonpass = sum(1 for c in checks if c.get("verdict") != "pass")
        reasons.append("verdict is pass-with-findings (%d finding(s), %d non-pass check(s))"
                       % (n_find, n_nonpass))

    # G1: trust-heuristic findings (evidence_ref "finding: ...")
    findings = [c for c in payload.get("checks", [])
                if (c.get("evidence_ref") or "").startswith("finding:")]
    if findings:
        kinds = " ".join((c.get("evidence_ref") or "") for c in findings)
        if policy.block_on_findings:
            if decision == "ALLOW":
                decision = "BLOCK"
            elif decision == "REVIEW":
                decision = "BLOCK"
            reasons.append("block_on_findings: %d trust finding(s)" % len(findings))
        else:
            for kind in policy.block_finding_kinds:
                if kind in kinds:
                    if decision == "ALLOW":
                        decision = "BLOCK"
                    elif decision == "REVIEW":
                        decision = "BLOCK"
                    reasons.append("blocking finding kind %r matched" % kind)
                    break

    return GateDecision(decision=decision, reasons=reasons, policy=policy_name,
                        verdict=verdict, subject=subject_name, key_valid=key_valid,
                        native_provenance_present=native_present, fresh=fresh)
