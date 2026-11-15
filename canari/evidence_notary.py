# -*- coding: utf-8 -*-
"""evidence_notary.py - notarize someone else's published verification export.

Several independent projects now publish daily evidence about MCP registry
entries (the {entry, version, checked_at, check, state, evidence} shape agreed
in modelcontextprotocol/registry#1715). Those exports are unsigned: a reader
cannot prove the file they hold is the file that was published, nor when.

This module turns one index document into a signed, timestamped Canari
attestation. It binds the record to the producer's published sha256 and records
the producer's identity, so the claim stays attributable to them - Canari is the
notary, not the author.

It deliberately does NOT claim to have recomputed the data file's digest.
"""
import datetime
import hashlib
import json
import os

from canari.signing import (load_or_generate_keypair, sign_attestation,
                            payload_digest)

ATTESTATION_TYPE = "https://agentcheck.dev/attestation/v0.1"
NOTARY_TOOL = "canari-notary/0.1"


def _canon_sha256(obj):
    return hashlib.sha256(
        json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def check_index_consistency(index):
    """Independent arithmetic check on the producer's own summary.

    Returns (ok, detail). This is the only thing we can verify without the data
    file, and it catches a producer whose summary does not add up.
    """
    entries = index.get("entries")
    states = index.get("states") or {}
    checks = index.get("checks") or {}
    problems = []
    if not isinstance(entries, int):
        problems.append("entries missing or not an integer")
    if states and isinstance(entries, int) and sum(states.values()) != entries:
        problems.append("states sum to %d, entries says %d"
                        % (sum(states.values()), entries))
    if checks and isinstance(entries, int) and sum(checks.values()) != entries:
        problems.append("checks sum to %d, entries says %d"
                        % (sum(checks.values()), entries))
    return (not problems), ("; ".join(problems) if problems else
                            "states and checks both sum to %d" % entries)


def build_attestation(index, expires_in_days=7, now=None):
    ok, detail = check_index_consistency(index)
    producer_sha = index.get("sha256")
    run = str(index.get("run") or "")
    dataset = str(index.get("dataset") or "unknown-dataset")
    if not producer_sha or len(producer_sha) != 64:
        raise ValueError("index has no usable sha256; refusing to notarize")
    if not run:
        raise ValueError("index has no run date; refusing to notarize")

    now = now or datetime.datetime.now(datetime.timezone.utc)
    expires = (now + datetime.timedelta(days=expires_in_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    checked_with = index.get("checked_with") or {}

    checks = [{
        "id": "DATASET_INDEX_CONSISTENT",
        "verdict": "pass" if ok else "fail",
        "tool": NOTARY_TOOL,
        "evidence_ref": "producer summary check: " + detail,
    }, {
        "id": "L2.1_ARTIFACT_HASH",
        "verdict": "unsupported",
        "tool": NOTARY_TOOL,
        "evidence_ref": ("sha256 %s is the producer's published value for %d bytes; "
                         "not recomputed by the notary"
                         % (producer_sha[:16], index.get("bytes") or 0)),
    }]

    return {
        "_type": ATTESTATION_TYPE,
        "subject": {"name": dataset, "version": run, "registry": "dataset",
                    "artifact_sha256": producer_sha, "maintainers": []},
        "host": {"class": "dataset",
                 "host_version": str(checked_with.get("client") or "unknown")},
        "scenario_sha256": _canon_sha256(index),
        "checks": checks,
        "verdict": "pass-with-findings" if ok else "fail",
        "checker": {"kind": "automation", "id": NOTARY_TOOL},
        "evidence_refs": ["index:%s:%s" % (dataset, _canon_sha256(index)[:16])],
        "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                 "truncated_fields": []},
        "expires_at": expires,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                      "payload_type": ATTESTATION_TYPE},
    }


def notarize(index_path, key_path, out_dir):
    index = json.load(open(index_path, encoding="utf-8"))
    att = build_attestation(index)
    signer, _pub, _new = load_or_generate_keypair(key_path)
    signed = sign_attestation(att, signer)
    os.makedirs(out_dir, exist_ok=True)
    safe = "".join(c if (c.isalnum() or c in "-._") else "_" for c in att["subject"]["name"])[:60]
    ts = att["subject"]["version"] or datetime.datetime.now().strftime("%Y%m%d")
    digest = payload_digest(signed["predicate"])[:8]
    path = os.path.join(out_dir, "%s_%s_%s.bundle.json" % (safe, ts, digest))
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"envelope": signed["envelope"], "payload": signed["payload"]},
                  f, ensure_ascii=False, indent=1)
    return path, att["verdict"], index