# -*- coding: utf-8 -*-
"""Fault injection against the real verification paths.

Guard against: verification that passes when its own inputs are damaged. Each case
runs the actual CLI or library call and asserts a *safe* failure - non-zero exit or
a documented degraded result, never a silent pass and never a traceback leaking to
the user.

Case D (a removed historical head) is marked xfail: the format has no link between
heads, so deletion is undetectable without an external pin. See
docs/log/SECURITY-NOTES.md.
"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = [sys.executable, "-m"]


def run(args):
    return subprocess.run(CLI + args, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", cwd=ROOT, timeout=180)


def no_traceback(text):
    return "Traceback (most recent call last)" not in (text or "")


def make_log(d, n=3, log_id="fi-log"):
    assert run(["canari.log_cli", "init", d, "--log-id", log_id,
                "--timestamp", "2026-01-01T00:00:00Z"]).returncode == 0
    recs = os.path.join(d, "recs.json")
    with open(recs, "w", encoding="utf-8") as f:
        json.dump([{"i": i} for i in range(n)], f)
    assert run(["canari.log_cli", "append", d, "--file", recs]).returncode == 0
    assert run(["canari.log_cli", "seal", d, "--timestamp", "2026-01-02T00:00:00Z"]).returncode == 0
    return d


def make_bundle(d):
    import base64
    import canari.baseline as bl
    from canari.signing import (load_or_generate_keypair, sign_attestation,
                                export_public_key)
    out = os.path.join(d, "out")
    os.makedirs(os.path.join(out, "attestations"), exist_ok=True)
    signer, pub, _ = load_or_generate_keypair(os.path.join(out, "private_key.pem"))
    meta = {"version": "1.0.0",
            "dist_integrity": "sha512-" + base64.b64encode(bytes(64)).decode(),
            "tarball": "https://example.invalid/x.tgz",
            "maintainers": ["a"], "fetch_ms": 1}
    orig = bl._download_sha256
    bl._download_sha256 = lambda url, timeout=60: "e" * 64
    try:
        att = bl.build_attestation("fixture-pkg", meta,
                                   {"description": "d", "links": {"homepage": "https://x"}},
                                   "c" * 64)
    finally:
        bl._download_sha256 = orig
    signed = sign_attestation(att, signer)
    path = os.path.join(out, "attestations", "npm_fixture-pkg.bundle.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"envelope": signed["envelope"], "payload": signed["payload"]}, f)
    key = os.path.join(out, "public_key.json")
    with open(key, "w", encoding="utf-8") as f:
        f.write(export_public_key(pub))
    return out, path, key


def test_truncated_bundle_is_rejected(tmp_path):
    out, bp, key = make_bundle(str(tmp_path))
    raw = open(bp, encoding="utf-8").read()
    open(bp, "w", encoding="utf-8").write(raw[: len(raw) // 2])
    r = run(["canari.verify_cli", bp, "--key", key])
    assert r.returncode != 0, r.stdout
    assert no_traceback(r.stderr), r.stderr


def test_tampered_payload_is_rejected(tmp_path):
    out, bp, key = make_bundle(str(tmp_path))
    b = json.load(open(bp, encoding="utf-8"))
    b["payload"]["verdict"] = "pass"
    b["payload"]["checks"] = [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "x"}]
    json.dump(b, open(bp, "w", encoding="utf-8"))
    r = run(["canari.verify_cli", bp, "--key", key])
    assert r.returncode != 0, r.stdout
    assert "ALLOW" not in r.stdout


def test_truncated_log_record_fails_audit(tmp_path):
    d = make_log(str(tmp_path / "log"))
    p = os.path.join(d, "log.jsonl")
    data = open(p, encoding="utf-8").read()
    open(p, "w", encoding="utf-8").write(data[: len(data) - 12])
    if open(p, encoding="utf-8").read().strip() == "":
        pytest.skip("truncation removed every record")
    r = run(["canari.log_cli", "audit", d])
    assert r.returncode != 0 or json.loads(r.stdout)["ok"] is False
    assert no_traceback(r.stderr)


def test_mutated_head_root_fails_audit(tmp_path):
    d = make_log(str(tmp_path / "log"))
    hp = os.path.join(d, "heads.jsonl")
    lines = [l for l in open(hp, encoding="utf-8").read().splitlines() if l.strip()]
    h = json.loads(lines[-1])
    h["body"]["root"] = "00" * 32
    lines[-1] = json.dumps(h, sort_keys=True)
    open(hp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    r = run(["canari.log_cli", "audit", d])
    assert r.returncode != 0
    assert json.loads(r.stdout)["ok"] is False


def test_removed_historical_head_is_detected(tmp_path):
    """Heads chain to their predecessor, so a deleted head breaks the chain.

    Before the `prev` field this case passed the audit: every surviving head was
    individually valid and the last one still matched log.jsonl, so removing
    heads[1] of 3 was invisible (measured 2026-11-16).
    """
    d = make_log(str(tmp_path / "log"))
    # a second and third head so there is something to delete in the middle
    for i in (2, 3):
        recs = os.path.join(d, "more%d.json" % i)
        with open(recs, "w", encoding="utf-8") as f:
            json.dump([{"i": i}], f)
        assert run(["canari.log_cli", "append", d, "--file", recs]).returncode == 0
        assert run(["canari.log_cli", "seal", d, "--timestamp",
                    "2026-01-0%dT00:00:00Z" % i]).returncode == 0
    hp = os.path.join(d, "heads.jsonl")
    lines = [l for l in open(hp, encoding="utf-8").read().splitlines() if l.strip()]
    assert len(lines) >= 3, lines
    open(hp, "w", encoding="utf-8").write("\n".join([lines[0]] + lines[2:]) + "\n")
    r = run(["canari.log_cli", "audit", d])
    out = json.loads(r.stdout)
    assert r.returncode != 0 and out["ok"] is False
    assert any("CHAIN BROKEN" in e for e in out["errors"]), out["errors"]


def test_new_heads_chain_to_their_predecessor(tmp_path):
    from canari.logstore import head_body_digest
    d = make_log(str(tmp_path / "log"))
    recs = os.path.join(d, "more.json")
    with open(recs, "w", encoding="utf-8") as f:
        json.dump([{"i": 99}], f)
    assert run(["canari.log_cli", "append", d, "--file", recs]).returncode == 0
    assert run(["canari.log_cli", "seal", d, "--timestamp",
                "2026-02-01T00:00:00Z"]).returncode == 0
    heads = [json.loads(l) for l in
             open(os.path.join(d, "heads.jsonl"), encoding="utf-8") if l.strip()]
    assert "prev" in heads[-1]["body"]
    assert heads[-1]["body"]["prev"] == head_body_digest(heads[-2]["body"])


def test_legacy_unchained_heads_still_audit(tmp_path):
    """A head written before `prev` existed must not fail the audit - it is a
    documented prefix, reported as unchained rather than treated as tampering."""
    d = make_log(str(tmp_path / "log"))
    hp = os.path.join(d, "heads.jsonl")
    lines = [l for l in open(hp, encoding="utf-8").read().splitlines() if l.strip()]
    # Re-sign each body WITHOUT prev: that is what a head written by the
    # pre-chain code looked like. Simply deleting the field would invalidate the
    # signature, which is the correct behaviour and is covered elsewhere.
    from canari.logstore import sign_head, canonical_bytes
    from canari.signing import load_or_generate_keypair
    signer = load_or_generate_keypair(os.path.join(d, "signing_key.pem"))[0]
    stripped = []
    for line in lines:
        body = dict(json.loads(line)["body"])
        body.pop("prev", None)
        stripped.append(canonical_bytes(sign_head(body, signer)).decode("utf-8"))
    open(hp, "w", encoding="utf-8").write("\n".join(stripped) + "\n")
    r = run(["canari.log_cli", "audit", d])
    out = json.loads(r.stdout)
    assert out["ok"] is True, out["errors"]
    assert out["unchained_heads"] >= 1


def test_corrupt_bundle_does_not_break_drift(tmp_path):
    out, bp, key = make_bundle(str(tmp_path))
    with open(os.path.join(out, "attestations", "garbage.bundle.json"), "w") as f:
        f.write("{not json")
    from canari.drift import compute_drift
    rep = compute_drift(out)
    assert "components" in rep


def test_empty_store_yields_empty_report(tmp_path):
    d = str(tmp_path / "store")
    os.makedirs(os.path.join(d, "attestations"), exist_ok=True)
    from canari.drift import compute_drift
    rep = compute_drift(d)
    assert rep["compared"] == 0


def test_empty_comparison_corpus_yields_no_verdict():
    from canari.typosquat import check_typosquatting
    assert check_typosquatting("some-name", set()) is None


def test_expired_attestation_does_not_gate_allow(tmp_path):
    out, bp, key = make_bundle(str(tmp_path))
    b = json.load(open(bp, encoding="utf-8"))
    b["payload"]["expires_at"] = "2000-01-01T00:00:00Z"
    json.dump(b, open(bp, "w", encoding="utf-8"))
    r = run(["canari.verify_cli", bp, "--key", key, "--gate"])
    assert "ALLOW" not in r.stdout
