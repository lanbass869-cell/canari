# -*- coding: utf-8 -*-
"""Tests added specifically to kill surviving mutants (batch-2 findings)."""
import io as _io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
V = "https://agentcheck.dev/attestation/v0.1"


def _bundle_payload(name, version, gen, checks=None, verdict="pass"):
    return {"subject": {"name": name, "version": version, "registry": "npm",
                        "artifact_sha256": "a" * 64, "maintainers": []},
            "verdict": verdict,
            "checks": checks or [{"id": "L1.1", "verdict": "pass", "tool": "t"}],
            "generated_at": gen}


class TestCadenceBurstKill:
    def test_exactly_five_in_24h_fires(self, monkeypatch):
        import canari.cadence as c
        releases = {("0.%d.0" % i): [{"upload_time_iso_8601": "2026-11-10T0%d:00:00.000000Z" % i}]
                    for i in range(5)}
        body = json.dumps({"releases": releases}).encode()
        class R(_io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False
        class Op:
            def open(self, req, timeout=None): return R(body)
        monkeypatch.setattr(c, "_opener", lambda: Op())
        f = c.analyze_release_cadence("p", "0.4.0")
        assert any("release_burst" in x["evidence_ref"] for x in f)

    def test_multifile_version_uses_earliest_upload(self, monkeypatch):
        """A version with several files must be dated by its EARLIEST upload:
        using the latest file would drop one release out of the 24h burst window."""
        import canari.cadence as c
        releases = {
            "1.0": [{"upload_time_iso_8601": "2026-11-10T11:00:00.000000Z"},
                    {"upload_time_iso_8601": "2026-12-01T00:00:00.000000Z"}],  # far future file
            "2.0": [{"upload_time_iso_8601": "2026-11-10T11:10:00.000000Z"}],
            "3.0": [{"upload_time_iso_8601": "2026-11-10T11:20:00.000000Z"}],
            "4.0": [{"upload_time_iso_8601": "2026-11-10T11:30:00.000000Z"}],
            "5.0": [{"upload_time_iso_8601": "2026-11-10T11:40:00.000000Z"}],
        }
        body = json.dumps({"releases": releases}).encode()
        class R(_io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False
        class Op:
            def open(self, req, timeout=None): return R(body)
        monkeypatch.setattr(c, "_opener", lambda: Op())
        f = c.analyze_release_cadence("p", "5.0")
        assert any("release_burst" in x["evidence_ref"] for x in f), f


def _signed_bundle_file(path, payload):
    import json as _json
    from canari.signing import generate_keypair, sign_attestation
    base = {"_type": "https://agentcheck.dev/attestation/v0.1",
            "subject": payload.get("subject", {}),
            "host": {"class": "mcp", "host_version": "t"},
            "scenario_sha256": "a" * 64,
            "checks": payload.get("checks", []),
            "checker": {"kind": "automation", "id": "t"},
            "evidence_refs": [],
            "evidence_completeness": {"dropped_logs": 0,
                                      "missing_observers": [],
                                      "truncated_fields": []},
            "expires_at": "2027-01-01T00:00:00Z",
            "supersedes": payload.get("supersedes"),
            "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                          "payload_type": ""}}
    base.update(payload)
    signer, _pub = generate_keypair()
    s = sign_attestation(base, signer)
    path.write_text(_json.dumps({"envelope": s["envelope"],
                                 "payload": s["payload"]}), encoding="utf-8")

class TestFeedKill:
    def _w(self, tmp_path, p):
        ad = tmp_path / "attestations"
        ad.mkdir(exist_ok=True)
        _signed_bundle_file(
            ad / ("%s_%s.bundle.json" % (p["subject"]["name"],
                                         p["generated_at"].replace(":", ""))), p)

    def test_two_generations_picks_newest(self, tmp_path):
        from canari.feed import build_feed
        self._w(tmp_path, _bundle_payload("p", "1.0", "2026-11-01T00:00:00Z", verdict="pass"))
        self._w(tmp_path, _bundle_payload("p", "2.0", "2026-11-02T00:00:00Z", verdict="fail"))
        f = build_feed(str(tmp_path))
        assert f["store"]["components"] == 1
        assert f["items"][0]["version"] == "2.0" and f["items"][0]["verdict"] == "fail"

    def test_corrupt_bundle_skipped_not_fatal(self, tmp_path):
        from canari.feed import build_feed
        ad = tmp_path / "attestations"
        ad.mkdir()
        (ad / "bad.bundle.json").write_text("{broken", encoding="utf-8")
        self._w(tmp_path, _bundle_payload("ok", "1", "2026-11-03T00:00:00Z"))
        f = build_feed(str(tmp_path))
        assert f["store"]["components"] == 1


class TestDeadLetterKill:
    def test_by_operation_counted(self, tmp_path):
        from canari.dead_letter import DeadLetterLog
        d = DeadLetterLog(str(tmp_path / "dl.json"))
        d.record("op_a", "t1", "e")
        d.record("op_a", "t2", "e")
        d.record("op_b", "t3", "e")
        s = d.summary()
        assert s["total"] == 3 and s["by_operation"] == {"op_a": 2, "op_b": 1}


class TestScoreKill:
    def test_sig_pass_exact_count(self, tmp_path):
        from canari.signing import generate_keypair, sign_attestation
        from canari.score import score
        signer, pub = generate_keypair()
        ad = tmp_path / "attestations"
        ad.mkdir()
        att = {"_type": V, "subject": {"name": "p", "version": "1", "registry": "npm",
                                       "artifact_sha256": "a" * 64, "maintainers": []},
               "host": {"class": "mcp", "host_version": "t"}, "scenario_sha256": "b" * 64,
               "checks": [{"id": "L1.1", "verdict": "pass", "tool": "t"}],
               "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
               "evidence_refs": [],
               "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                         "truncated_fields": []},
               "expires_at": "2026-12-30T00:00:00Z", "generated_at": "2026-11-10T00:00:00Z",
               "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": V}}
        s = sign_attestation(att, signer)
        (ad / "one.bundle.json").write_text(json.dumps({"envelope": s["envelope"],
                                                        "payload": s["payload"]}),
                                            encoding="utf-8")
        (ad / "two.bundle.json").write_text(json.dumps({"envelope": s["envelope"],
                                                       "payload": s["payload"]}),
                                           encoding="utf-8")
        out = score(str(tmp_path), public_key=pub.to_dict())
        assert out["integrity"]["sig_pass"] == 2
        # one expired attestation must be counted as expired, not fresh
        att2 = dict(att, expires_at="2020-01-01T00:00:00Z")
        s2 = sign_attestation(att2, signer)
        (ad / "old.bundle.json").write_text(json.dumps({"envelope": s2["envelope"],
                                                        "payload": s2["payload"]}),
                                            encoding="utf-8")
        out2 = score(str(tmp_path), public_key=pub.to_dict())
        assert out2["freshness"]["expired"] == 1 and out2["integrity"]["sig_pass"] == 3


class TestSigningNfcKill:
    def test_nfc_applied_deterministically(self):
        from canari.signing import generate_keypair, sign_attestation, verify_signed
        import unicodedata
        signer, pub = generate_keypair()
        weird = "\uf900"  # CJK compatibility ideograph; NFC -> U+8C48
        att = {"_type": V, "subject": {"name": weird, "version": "1", "registry": "npm",
                                       "artifact_sha256": "a" * 64, "maintainers": []},
               "host": {"class": "mcp", "host_version": "t"}, "scenario_sha256": "b" * 64,
               "checks": [{"id": "L1.1", "verdict": "pass", "tool": "t"}],
               "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
               "evidence_refs": [],
               "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                         "truncated_fields": []},
               "expires_at": "2026-12-30T00:00:00Z", "generated_at": "2026-11-10T00:00:00Z",
               "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": V}}
        s = sign_attestation(att, signer)
        ok, payload, err = verify_signed(s["envelope"], pub.to_dict())
        assert ok, err
        assert payload["subject"]["name"] == unicodedata.normalize("NFC", weird)
        assert payload["subject"]["name"] != weird


class TestStateDiffKill:
    def test_changed_detected(self, tmp_path):
        from canari.state import StateStore
        s = StateStore(str(tmp_path / "s.json"))
        s.set_component("p", "1", "old-hash", "d")
        d = s.diff({"p": {"version": "1", "sha256": "new-hash"}})
        assert d["changed"] == ["p"]


class TestScannerKill:
    def test_error_path_is_error(self):
        from canari.scanner_adapter import findings_to_checks
        checks, verdict = findings_to_checks({"error": "boom"})
        assert verdict == "error" and checks[0]["verdict"] == "error"


class TestNativeKill:
    def test_v1_failure_recorded(self, monkeypatch):
        import canari.native as nat
        monkeypatch.setattr(nat, "fetch_attestations", lambda n, v, timeout=30: {
            "attestations": [{"predicateType": "https://x/v1",
                              "bundle": {"verificationMaterial": {"certificate": {}}}}]})
        monkeypatch.setattr(nat, "verify_v1_cert", lambda b, expected_identity=None: {
            "ok": False, "identity": None, "issuer": None, "payload_type": None,
            "error": "bad sig"})
        out = nat.ingest("p", "1")
        assert out["v1_verified"] is False and out["v1_error"] == "bad sig"


class TestMcpPolicyKill:
    def test_policy_name_is_honoured(self):
        from canari.mcp_server import _handle
        r = _handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "gate_check",
                                "arguments": {"registry": "npm", "name": "nope",
                                              "policy": "paranoid"}}}, "out", None)
        payload = json.loads(r["result"]["content"][0]["text"])
        assert payload["policy"] == "paranoid"


class TestTimeoutDefaultKill:
    def test_default_returned_on_hang(self):
        import time
        from canari.baseline import _with_timeout
        assert _with_timeout(lambda: time.sleep(3), 0.2, "TIMEOUT") == "TIMEOUT"
