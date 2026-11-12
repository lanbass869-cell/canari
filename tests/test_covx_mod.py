# -*- coding: utf-8 -*-
"""Coverage (owned namespace covx): anomaly / native / pypi_native / scanner_adapter /
cadence / typosquat / drift / consumer edge branches."""
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class R(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def Op(mapping):
    class _Op:
        def open(self, req, timeout=None):
            url = getattr(req, "full_url", str(req))
            for sub, payload in mapping:
                if sub in url:
                    if isinstance(payload, Exception):
                        raise payload
                    return R(payload)
            raise OSError("no mock " + url)
    return _Op()


class TestAnomaly:
    def test_maintainer_change(self):
        from canari.anomaly import detect_metadata_anomaly
        f = detect_metadata_anomaly({"maintainers": [{"name": "bob"}]},
                                    {"maintainers": [{"name": "alice"}]})
        assert any("maintainer_identity_change" in x["evidence_ref"] for x in f)

    def test_repo_change(self):
        from canari.anomaly import detect_metadata_anomaly
        f = detect_metadata_anomaly({"homepage": "https://gitlab.com/b/p"},
                                    {"homepage": "https://github.com/a/p"})
        assert any("declared_repository_change" in x["evidence_ref"] for x in f)

    def test_same_and_missing(self):
        from canari.anomaly import detect_metadata_anomaly
        same = {"maintainers": ["a"], "homepage": "https://x"}
        assert detect_metadata_anomaly(same, same) == []
        assert detect_metadata_anomaly(None, same) == []
        assert detect_metadata_anomaly(same, None) == []

    def test_string_maintainers(self):
        from canari.anomaly import detect_metadata_anomaly
        assert detect_metadata_anomaly({"author": "Bob"}, {"maintainers": ["alice"]})

    def test_url_normalisation(self):
        from canari.anomaly import _normalize_url
        assert _normalize_url("HTTPS://GitHub.com/A/B.git/") == "https://github.com/a/b"


class TestNative:
    def test_classify(self):
        from canari.native import _classify_entries
        r = _classify_entries([
            {"predicateType": "https://slsa.dev/provenance/v1",
             "bundle": {"verificationMaterial": {"certificate": {}}}},
            {"predicateType": "https://x/v0.1",
             "bundle": {"verificationMaterial": {"publicKey": {}}}},
        ])
        assert r["present"] and len(r["v1_cert_entries"]) == 1 and len(r["v0_key_entries"]) == 1
        assert _classify_entries(None)["present"] is False
        assert _classify_entries([])["present"] is False

    def test_ingest_paths(self, monkeypatch):
        import canari.native as nat
        monkeypatch.setattr(nat, "fetch_attestations", lambda n, v, timeout=30: None)
        assert nat.ingest("p", "1") is None
        monkeypatch.setattr(nat, "fetch_attestations", lambda n, v, timeout=30: {
            "attestations": [{"predicateType": "https://x/v0.1",
                              "bundle": {"verificationMaterial": {"publicKey": {}}}}]})
        out = nat.ingest("p", "1")
        assert out["v0_presence_only"] == 1 and out["v1_verified"] is None
        monkeypatch.setattr(nat, "fetch_attestations", lambda n, v, timeout=30: {
            "attestations": [{"predicateType": "https://x/v1",
                              "bundle": {"verificationMaterial": {"certificate": {}}}}]})
        monkeypatch.setattr(nat, "verify_v1_cert",
                            lambda b, expected_identity=None: {"ok": True, "identity": "id",
                                                               "issuer": "i", "payload_type": "t",
                                                               "error": None})
        out = nat.ingest("p", "1")
        assert out["v1_verified"] is True and out["v1_identity"] == "id"


class TestPypiNative:
    def test_fetch_none(self, monkeypatch):
        import canari.pypi_native as pn
        monkeypatch.setattr(pn, "fetch_pypi_attestations", lambda p, version=None, timeout=30: None)
        assert pn.ingest_pypi("p") is None

    def test_fetch_success(self, monkeypatch):
        import canari.pypi_native as pn
        body = json.dumps({"urls": [
            {"filename": "f.whl", "digests": {"sha256": "d"},
             "attestations": [{"predicateType": "x"}]},
            {"filename": "g.whl", "digests": {"sha256": "e"}}]}).encode()
        monkeypatch.setattr(pn, "_opener", lambda: Op([("pypi.org", body)]))
        files = pn.fetch_pypi_attestations("p")
        assert files and files[0]["filename"] == "f.whl"

    def test_ingest_ok_and_error(self, monkeypatch):
        import canari.pypi_native as pn
        monkeypatch.setattr(pn, "fetch_pypi_attestations", lambda p, version=None, timeout=30: [
            {"filename": "f", "digest": "d", "attestations": [{"predicateType": "x"}]}])
        monkeypatch.setattr(pn, "convert_pep740_to_bundle", lambda a: "B")
        monkeypatch.setattr(pn, "verify_pypi_bundle",
                            lambda b, distribution_bytes=None: {"ok": True, "payload_type": "t",
                                                                "error": None})
        out = pn.ingest_pypi("p", "1")
        assert out["v1_verified"] is True
        monkeypatch.setattr(pn, "convert_pep740_to_bundle",
                            lambda a: (_ for _ in ()).throw(ValueError("bad")))
        out = pn.ingest_pypi("p")
        assert out["v1_verified"] is False and "bad" in out["v1_error"]

    def test_version_url(self, monkeypatch):
        import canari.pypi_native as pn
        seen = {}
        class _Op:
            def open(self, req, timeout=None):
                seen["url"] = req.full_url
                raise OSError("stop")
        monkeypatch.setattr(pn, "_opener", lambda: _Op())
        pn.fetch_pypi_attestations("pkg", version="2.0")
        assert "/pkg/2.0/json" in seen["url"]


class TestScanner:
    def test_source_digest(self, tmp_path):
        from canari.scanner_adapter import compute_source_digest
        (tmp_path / "a.py").write_text("x", encoding="utf-8")
        assert len(compute_source_digest(str(tmp_path))) == 64

    def test_missing_scanner(self, tmp_path):
        from canari.scanner_adapter import run_repo_forensics
        assert "error" in run_repo_forensics(str(tmp_path), scanner_root=str(tmp_path / "no"))

    def test_no_entry_point(self, tmp_path):
        from canari.scanner_adapter import run_repo_forensics
        root = tmp_path / "scanner"
        (root / "scripts").mkdir(parents=True)
        (root / "scripts" / "aggregate_json.py").write_text("", encoding="utf-8")
        assert "error" in run_repo_forensics(str(tmp_path), scanner_root=str(root))

    def test_findings_paths(self):
        from canari.scanner_adapter import findings_to_checks
        assert findings_to_checks({"error": "x"})[1] == "error"
        assert findings_to_checks({"summary": {"critical": 1, "total": 1}})[1] == "fail"
        assert findings_to_checks({"summary": {"total": 2, "medium": 2},
                                   "scanner_count": 29, "_canari_source_digest": "a" * 64})[1] == "pass-with-findings"
        # BUG-104/F5: an empty summary / no data used to be reported as "pass".
        # Absence of evidence is not evidence of safety - it is "unsupported".
        assert findings_to_checks({"summary": {}, "scanner_count": 3,
                                   "_canari_source_digest": "b" * 64})[1] == "unsupported"
        assert findings_to_checks(None)[1] == "unsupported"
        # a real scan that ran and found nothing is still a pass
        assert findings_to_checks({"summary": {"total": 0}, "scanner_count": 3,
                                   "exit_code": 0})[1] == "pass"

    def test_rule_count(self, tmp_path):
        from canari.scanner_adapter import get_rule_count
        (tmp_path / "r.py").write_text("import re\nre.compile('a')\nre.compile('b')\n",
                                       encoding="utf-8")
        assert get_rule_count(str(tmp_path)) == 2

    def test_subprocess_json_path(self, tmp_path):
        from canari.scanner_adapter import run_repo_forensics
        root = tmp_path / "sc"
        (root / "scripts").mkdir(parents=True)
        (root / "scripts" / "aggregate_json.py").write_text("", encoding="utf-8")
        (root / "scripts" / "auto_scan.py").write_text(
            "print('{\"summary\": {\"total\": 0}, \"scanner_count\": 1}')\n", encoding="utf-8")
        r = run_repo_forensics(str(tmp_path), scanner_root=str(root))
        assert r.get("summary", {}).get("total") == 0 and "_canari_source_digest" in r

    def test_subprocess_bad_json(self, tmp_path):
        from canari.scanner_adapter import run_repo_forensics
        root = tmp_path / "sc"
        (root / "scripts").mkdir(parents=True)
        (root / "scripts" / "aggregate_json.py").write_text("", encoding="utf-8")
        (root / "scripts" / "auto_scan.py").write_text("print('nope')\n", encoding="utf-8")
        assert "error" in run_repo_forensics(str(tmp_path), scanner_root=str(root))


class TestCadence:
    def test_api_error_and_missing(self, monkeypatch):
        import canari.cadence as c
        class _Op:
            def open(self, req, timeout=None): raise OSError("x")
        monkeypatch.setattr(c, "_opener", lambda: _Op())
        assert c.analyze_release_cadence("p", "1") == []
        assert c.analyze_release_cadence("", "1") == []
        assert c.analyze_release_cadence("p", "") == []

    def test_version_missing(self, monkeypatch):
        import canari.cadence as c
        body = json.dumps({"releases": {"1.0": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}]}}).encode()
        monkeypatch.setattr(c, "_opener", lambda: Op([("pypi.org", body)]))
        assert c.analyze_release_cadence("p", "9.9") == []


class TestTyposquat:
    def test_empty_and_distance(self):
        from canari.typosquat import check_typosquatting, _damerau_levenshtein
        assert check_typosquatting("", {"a"}) is None
        assert check_typosquatting("a", set()) is None
        assert _damerau_levenshtein("abcd", "abdc") == 1
        assert _damerau_levenshtein("", "abc") == 3

    def test_nfkc_fullwidth(self):
        from canari.typosquat import check_typosquatting
        fw = "\uff4d\uff43\uff50-server-fecth"
        assert check_typosquatting(fw, {"mcp-server-fetch"})


def _signed_bundle_file(path, payload):
    """Write a REAL canari bundle (DSSE envelope + mirror) for a payload."""
    import json as _json
    from canari.signing import generate_keypair, sign_attestation
    base = {"subject": payload.get("subject", {}),
            "_type": "https://agentcheck.dev/attestation/v0.1",
            "host": {"class": "mcp", "host_version": "t"},
            "scenario_sha256": "a" * 64,
            "checker": {"kind": "automation", "id": "t"},
            "evidence_refs": [],
            "expires_at": "2027-01-01T00:00:00Z",
            "signature": {"envelope": "DSSE", "keyid": "", "sig": "",
                          "payload_type": ""}}
    base.update(payload)
    signer, _pub = generate_keypair()
    s = sign_attestation(base, signer)
    path.write_text(_json.dumps({"envelope": s["envelope"],
                                 "payload": s["payload"]}), encoding="utf-8")

class TestDrift:
    def _w(self, tmp_path, name, ver, gen, checks, verdict="pass"):
        ad = tmp_path / "attestations"
        ad.mkdir(exist_ok=True)
        p = {"subject": {"name": name, "version": ver, "registry": "npm",
                         "artifact_sha256": "a" * 64,
                         "maintainers": []},
             "verdict": verdict, "checks": checks, "generated_at": gen,
             "signature": {"envelope": "DSSE", "keyid": "", "sig": ""},
             "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                       "truncated_fields": []}}
        _signed_bundle_file(ad / ("%s_%s.bundle.json" % (name, gen.replace(":", ""))), p)

    def test_version_bump_and_since(self, tmp_path):
        from canari.drift import compute_drift
        self._w(tmp_path, "pkg", "1.0", "2026-11-01T00:00:00Z", [{"id": "A", "verdict": "pass"}])
        self._w(tmp_path, "pkg", "2.0", "2026-11-02T00:00:00Z", [{"id": "A", "verdict": "pass"}])
        rep = compute_drift(str(tmp_path))
        assert len(rep["version_bumps"]) == 1
        assert compute_drift(str(tmp_path), since="2030-01-01")["compared"] == 0

    def test_findings_removed(self, tmp_path):
        from canari.drift import compute_drift
        self._w(tmp_path, "p", "1", "2026-11-01T00:00:00Z",
                [{"id": "L2.4_X", "verdict": "pass", "evidence_ref": "finding: x"}],
                verdict="pass-with-findings")
        self._w(tmp_path, "p", "1", "2026-11-02T00:00:00Z",
                [{"id": "L2.4_X", "verdict": "pass"}])
        rep = compute_drift(str(tmp_path))
        assert rep["findings_removed"]


class TestConsumer:
    def test_skips_unreadable_and_version_miss(self, tmp_path):
        from canari.consumer import iter_bundles, list_components, latest_attestation
        ad = tmp_path / "attestations"
        ad.mkdir()
        (ad / "bad.bundle.json").write_text("{oops", encoding="utf-8")
        assert list(iter_bundles(str(tmp_path))) == []
        assert list_components(str(tmp_path)) == []
        p = {"subject": {"name": "p", "version": "1", "registry": "npm"},
             "generated_at": "2026-11-10T00:00:00Z"}
        (ad / "a.bundle.json").write_text(json.dumps({"payload": p}), encoding="utf-8")
        assert latest_attestation(str(tmp_path), "npm", "p", version="9") is None

