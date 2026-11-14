# -*- coding: utf-8 -*-
"""sarif_ingest.py - record ANOTHER tool's scan result as a Canari attestation.

Canari does not scan anything itself (positioning decision 2026-11-09: the
detection layer is frozen). What it does is make somebody else's verdict
durable: signed, timestamped, offline-verifiable, and preserved across rescans.

This module takes a SARIF 2.1.0 report produced by an external scanner
(NVIDIA SkillSpector, Snyk agent-scan, Tencent AI-Infra-Guard, ...) and turns
it into a Canari attestation. The attestation says, in effect:

    "tool <name> <version> scanned artifact <sha256> on <date> and concluded <verdict>"

It must never claim Canari performed the scan. Every check records the upstream
tool as `tool`, and `checker.id` names the upstream tool too. If the SARIF does
not carry an artifact digest, the caller must supply one - we do not fabricate.

Usage:
    canari-ingest-sarif --sarif skillspector.sarif \
        --name @modelcontextprotocol/server-filesystem --version 2025.1.0 \
        --registry npm --artifact-sha256 <64 hex> \
        --key out/private_key.pem --out out/attestations
"""
import datetime
import hashlib
import json
import os
import sys

from canari.signing import (
    load_or_generate_keypair,
    sign_attestation,
    payload_digest,
)

ATTESTATION_TYPE = "https://agentcheck.dev/attestation/v0.1"
SCAN_CHECK_ID = "L3.1_STATIC_SCAN"
MAX_FINDING_CHECKS = 20          # keep bundles bounded
DEFAULT_TTL_DAYS = 7


def _sha256_of_obj(obj):
    canon = json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def _tool_identity(sarif):
    """(name, version) from run[0].tool.driver, with honest fallbacks."""
    runs = sarif.get("runs") or []
    if not runs:
        return "unknown-scanner", "0"
    drv = ((runs[0].get("tool") or {}).get("driver") or {})
    name = drv.get("name") or drv.get("fullName") or "unknown-scanner"
    ver = drv.get("semanticVersion") or drv.get("version") or "0"
    return str(name), str(ver)


def _severity(result):
    """Best-effort severity for one SARIF result.

    SARIF does not mandate a severity scale. Order of preference:
      1. rule-level security-severity metadata (GitHub code scanning convention,
         a CVSS-like 0-10 number stored as a string)
      2. result.level (error / warning / note / none)
    Returns one of: critical, high, medium, low, none.
    """
    properties = result.get("properties") or {}
    raw = properties.get("security-severity")
    if raw is not None:
        try:
            score = float(raw)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            if score > 0:
                return "low"
            return "none"
    level = str(result.get("level") or "warning").lower()
    return {"error": "high", "warning": "medium",
            "note": "low", "none": "none"}.get(level, "medium")


def _location(result):
    locs = result.get("locations") or []
    if not locs:
        return ""
    phys = (locs[0].get("physicalLocation") or {})
    art = phys.get("artifactLocation") or {}
    uri = art.get("uri") or ""
    region = phys.get("region") or {}
    line = region.get("startLine")
    return ("%s:%s" % (uri, line)) if line else uri


def sarif_to_checks(sarif):
    """Map a SARIF document to (checks, verdict, tool_name, tool_version, meta).

    Returns meta with: total results, truncated count, highest severity,
    execution_successful, generated_at (if the SARIF recorded one).
    """
    runs = sarif.get("runs") or []
    tool_name, tool_version = _tool_identity(sarif)

    results = []
    generated_at = None
    execution_ok = True
    for run in runs:
        results.extend(run.get("results") or [])
        for inv in (run.get("invocations") or []):
            if inv.get("executionSuccessful") is False:
                execution_ok = False
            end = inv.get("endTimeUtc") or inv.get("startTimeUtc")
            if end and not generated_at:
                generated_at = end

    ranked = sorted(results, key=lambda r: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
        .get(_severity(r), 5)))
    highest = _severity(ranked[0]) if ranked else "none"

    checks = []
    tool_ref = "%s/%s" % (tool_name, tool_version)

    # The upstream scan itself, recorded as one check.
    if not runs:
        # No runs at all is a broken report, NOT a clean scan. Reading it as
        # "pass" would make the ledger a rubber stamp (same defect class as the
        # 346 registry-presence-only records).
        scan_verdict = "error"
        execution_ok = False
    elif not execution_ok:
        scan_verdict = "error"
    elif highest in ("critical", "high"):
        scan_verdict = "fail"
    elif results:
        scan_verdict = "pass-with-findings"
    else:
        scan_verdict = "pass"

    # NOTE: a per-check verdict may only be pass/fail/skip/unsupported/error.
    # "pass-with-findings" exists only at the attestation level. A scan that
    # ran and produced non-blocking findings is recorded as a PASSING check
    # whose evidence says "finding: ..." - the same convention Canari uses for
    # L2.5/L2.6 heuristics.
    check_verdict = {"pass-with-findings": "pass"}.get(scan_verdict, scan_verdict)
    checks.append({
        "id": SCAN_CHECK_ID,
        "verdict": check_verdict,
        "tool": tool_ref,
        "evidence_ref": ("upstream scan: no run block present - report is unusable"
                         if not runs else
                         ("finding: %d result(s), highest severity=%s"
                          % (len(results), highest) if results else
                          "upstream scan: 0 result(s), scanner reported no findings")),
    })

    # Individual findings, capped, each attributable to a rule + location.
    for r in ranked[:MAX_FINDING_CHECKS]:
        rule_id = r.get("ruleId") or (r.get("rule") or {}).get("id") or "unknown-rule"
        sev = _severity(r)
        where = _location(r)
        checks.append({
            "id": "L3.1_FINDING",
            "verdict": "fail" if sev in ("critical", "high") else "pass",
            "tool": tool_ref,
            "evidence_ref": "finding: rule=%s severity=%s%s"
                            % (rule_id, sev, (" at " + where) if where else ""),
        })

    meta = {
        "results": len(results),
        "truncated": max(0, len(results) - MAX_FINDING_CHECKS),
        "highest_severity": highest,
        "execution_successful": execution_ok,
        "generated_at": generated_at,
    }
    return checks, scan_verdict, tool_name, tool_version, meta


def build_attestation(sarif, name, registry, artifact_sha256, version="",
                      expires_in_days=DEFAULT_TTL_DAYS, now=None):
    """Build (unsigned) attestation dict from a SARIF document."""
    if not artifact_sha256:
        raise ValueError("artifact_sha256 is required: a scan result without the "
                         "scanned artifact's digest cannot be bound to anything")
    if len(artifact_sha256) != 64 or any(c not in "0123456789abcdef" for c in artifact_sha256.lower()):
        raise ValueError("artifact_sha256 must be 64 lowercase hex characters")

    checks, verdict, tool_name, tool_version, meta = sarif_to_checks(sarif)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    generated = meta["generated_at"] or now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = (now + datetime.timedelta(days=expires_in_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    scenario = _sha256_of_obj(sarif)

    return {
        "_type": ATTESTATION_TYPE,
        "subject": {
            "name": name,
            "version": version,
            "registry": registry,
            "artifact_sha256": artifact_sha256.lower(),
            "maintainers": [],
        },
        "host": {"class": "mcp", "host_version": tool_version},
        "scenario_sha256": scenario,
        "checks": checks,
        "verdict": verdict,
        "checker": {"kind": "automation", "id": "%s (ingested by canari)" % tool_name},
        "evidence_refs": ["sarif:%s:%s" % (tool_name, scenario[:16])],
        "evidence_completeness": {
            "dropped_logs": meta["truncated"],
            "missing_observers": [],
            "truncated_fields": [],
        },
        "expires_at": expires,
        "generated_at": generated,
        "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                      "payload_type": ATTESTATION_TYPE},
    }


def ingest(sarif_path, name, registry, artifact_sha256, key_path, out_dir,
           version="", expires_in_days=DEFAULT_TTL_DAYS):
    """Read SARIF, sign an attestation, write the bundle. Returns the path."""
    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif = json.load(f)
    att = build_attestation(sarif, name, registry, artifact_sha256,
                            version=version, expires_in_days=expires_in_days)
    signer, _pub, _is_new = load_or_generate_keypair(key_path)
    signed = sign_attestation(att, signer)

    os.makedirs(out_dir, exist_ok=True)
    safe = "".join(c if (c.isalnum() or c in "-._") else "_" for c in name)[:60]
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    digest = payload_digest(signed["predicate"])[:8]
    path = os.path.join(out_dir, "%s_%s_%s_%s.bundle.json"
                        % (registry, safe, ts, digest))
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"envelope": signed["envelope"], "payload": signed["payload"]},
                  f, ensure_ascii=False, indent=1)
    return path, att["verdict"]


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="canari-ingest-sarif",
        description="Record an external scanner's SARIF report as a signed, "
                    "timestamped Canari attestation.")
    ap.add_argument("--sarif", required=True, help="SARIF 2.1.0 report path")
    ap.add_argument("--name", required=True, help="component name")
    ap.add_argument("--registry", required=True,
                    help="npm | pypi | mcp-registry | dsh-registry | other")
    ap.add_argument("--artifact-sha256", required=True,
                    help="sha256 of the scanned artifact (required; not inferred)")
    ap.add_argument("--version", default="", help="component version, if known")
    ap.add_argument("--key", required=True, help="private key PEM (created if absent)")
    ap.add_argument("--out", default="out/attestations", help="output directory")
    ap.add_argument("--expires-in-days", type=int, default=DEFAULT_TTL_DAYS)
    a = ap.parse_args(argv)

    try:
        path, verdict = ingest(a.sarif, a.name, a.registry, a.artifact_sha256,
                               a.key, a.out, version=a.version,
                               expires_in_days=a.expires_in_days)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    print("%s -> %s" % (verdict, path))
    return 0


if __name__ == "__main__":
    sys.exit(main())