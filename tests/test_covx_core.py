# -*- coding: utf-8 -*-
"""Coverage (owned namespace covx): baseline run()/run_multi()/metadata_scan()/
deep_scan/main, score, guard extras, mcp_server extras."""
import io as _io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import canari.baseline as bl

V = "https://agentcheck.dev/attestation/v0.1"
PACK = {"dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {"dist": {"integrity": "", "tarball": "https://r/x.tgz"}}},
        "maintainers": [{"name": "alice"}]}


class R(_io.BytesIO):
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


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setattr(bl, "enumerate_top", lambda limit=50, dedupe=True: [
        {"name": "pkg-a", "description": "d", "links": {"homepage": "h"}}])
    monkeypatch.setattr(bl, "fetch_packument", lambda name, timeout=90: PACK)
    monkeypatch.setattr(bl, "_download_sha256", lambda url, timeout=60: "e" * 64)
    monkeypatch.setattr(bl, "native_ingest", lambda n, v: None)
    monkeypatch.setattr(bl, "pypi_enumerate", lambda limit=500, cache_path=None: [])
    monkeypatch.setattr(bl, "mcp_registry_enumerate", lambda limit=500: [])
    monkeypatch.setattr(bl, "dsh_enumerate", lambda limit=500, with_security=True: [])
    monkeypatch.setattr(bl, "_runner_source_digest", lambda: "d" * 64)
    return monkeypatch


class TestHelpers:
    def test_source_digest(self):
        assert len(bl._runner_source_digest()) == 64

    def test_download_empty_and_fail(self, monkeypatch):
        assert bl._download_sha256("") is None
        class _Op:
            def open(self, req, timeout=None): raise OSError("x")
        monkeypatch.setattr(bl, "_opener", lambda: _Op())
        assert bl._download_sha256("https://x") is None

    def test_download_success(self, monkeypatch):
        import hashlib
        class _Op:
            def open(self, req, timeout=None): return R(b"abc")
        monkeypatch.setattr(bl, "_opener", lambda: _Op())
        assert bl._download_sha256("https://x") == hashlib.sha256(b"abc").hexdigest()

    def test_with_timeout(self):
        import time
        assert bl._with_timeout(lambda: 42, 5) == 42
        assert bl._with_timeout(lambda: time.sleep(3), 0.2) is None
        assert bl._with_timeout(lambda: (_ for _ in ()).throw(ValueError("x")), 5, "fb") == "fb"


class TestRunSingle:
    def test_full_path_and_chain(self, env, tmp_path):
        r = bl.run(limit=1, out_dir=str(tmp_path))
        assert r["total"] == 1
        assert list(tmp_path.joinpath("attestations").glob("*.bundle.json"))
        assert tmp_path.joinpath("baseline_report.json").exists()
        assert list(tmp_path.joinpath("feed").glob("run-feed-*.json"))
        bl.run(limit=1, out_dir=str(tmp_path))
        payloads = [json.loads(p.read_text(encoding="utf-8"))["payload"]
                    for p in tmp_path.joinpath("attestations").glob("*.bundle.json")]
        assert any(p.get("supersedes") for p in payloads)

    def test_fetch_error_degrades(self, env, tmp_path):
        env.setattr(bl, "fetch_packument",
                    lambda name, timeout=90: (_ for _ in ()).throw(OSError("boom")))
        r = bl.run(limit=1, out_dir=str(tmp_path))
        assert r["fetch_errors"] == 1

    def test_main(self, env, tmp_path):
        assert bl.main(["--limit", "1", "--out", str(tmp_path)]) == 0


class TestRunMultiAll:
    def test_all_registries(self, env, tmp_path):
        env.setattr(bl, "pypi_enumerate", lambda limit=500, cache_path=None: [
            {"name": "py-a", "version": "1.0", "artifact_sha256": "c" * 64,
             "maintainers": ["a"], "links": {"homepage": "h"}},
            {"name": "py-bad", "registry": "pypi", "error": "boom"}])
        env.setattr(bl, "pypi_native_ingest", lambda n, v=None: None)
        env.setattr(bl, "mcp_registry_enumerate", lambda limit=500: [
            {"name": "mcp/x", "version": "1.0"}])
        env.setattr(bl, "dsh_enumerate", lambda limit=500, with_security=True: [
            {"name": "dsh-ok", "version": "1", "install_verdict": "passed",
             "security_critical": 0, "security_files_scanned": 3, "security_scanner": "s"},
            {"name": "dsh-bad", "version": "1", "install_verdict": "failed"},
            {"name": "dsh-crit", "version": "1", "install_verdict": "passed",
             "security_critical": 2, "security_files_scanned": 5},
            {"name": "dsh-bare", "version": "1"}])
        r = bl.run_multi(npm_limit=1, pypi_limit=5, registry_limit=5, dsh_limit=5,
                         out_dir=str(tmp_path))
        assert r["by_registry"]["npm"] == 1 and r["by_registry"]["pypi"] == 1
        assert r["by_registry"]["mcp-registry"] == 1 and r["by_registry"]["dsh-registry"] == 4
        dl = json.loads(tmp_path.joinpath("dead_letters.json").read_text(encoding="utf-8"))
        assert any(e["target"] == "py-bad" for e in dl)
        verdicts = {}
        for f in tmp_path.joinpath("attestations").glob("dsh_*.bundle.json"):
            p = json.loads(f.read_text(encoding="utf-8"))["payload"]
            verdicts[p["subject"]["name"]] = p["verdict"]
        assert verdicts["dsh-bad"] == "fail" and verdicts["dsh-crit"] == "fail"
        # BUG-98: no install/security data -> "unsupported", never a pass
        assert verdicts["dsh-bare"] == "unsupported"
        assert list(tmp_path.joinpath("feed").glob("run-feed-*.json"))

    def test_npm_error_attestation(self, env, tmp_path):
        env.setattr(bl, "fetch_packument",
                    lambda name, timeout=90: (_ for _ in ()).throw(OSError("nope")))
        bl.run_multi(npm_limit=1, pypi_limit=0, registry_limit=0, dsh_limit=0,
                     out_dir=str(tmp_path))
        bundles = list(tmp_path.joinpath("attestations").glob("npm_*.bundle.json"))
        assert json.loads(bundles[0].read_text(encoding="utf-8"))["payload"]["verdict"] == "error"


class TestMetadataScan:
    def test_npm(self, env):
        body = json.dumps({"objects": [
            {"package": {"name": "m1", "version": "1", "date": "d",
                         "maintainers": [{"name": "a"}], "links": {"homepage": "h"}},
             "downloads": {"monthly": 5}}], "total": 1}).encode()
        env.setattr(bl, "_opener", lambda: Op([("npmjs.org", body)]))
        out = bl.metadata_scan("npm", limit=1, out_dir="x")
        assert out[0]["downloads_monthly"] == 5

    def test_pypi_cache(self, env, tmp_path):
        cache = tmp_path / "cache" / "pypi-simple.html"
        cache.parent.mkdir(parents=True)
        cache.write_text('<html>\n<a href="/x/">mcp-server-z</a>\n</html>\n', encoding="utf-8")
        out = bl.metadata_scan("pypi", limit=5, out_dir=str(tmp_path))
        assert out and out[0]["name"] == "mcp-server-z"

    def test_dsh_and_unknown(self, env):
        env.setattr(bl, "dsh_enumerate", lambda limit=500, with_security=False: [
            {"name": "d1", "registry": "dsh-registry"}])
        assert bl.metadata_scan("dsh", limit=5, out_dir="x")[0]["name"] == "d1"
        assert bl.metadata_scan("nope", limit=5, out_dir="x") == []


class TestDeepScan:
    def test_two_tier(self, env, tmp_path):
        env.setattr(bl, "metadata_scan", lambda registry="npm", limit=5000, out_dir=None: [
            {"name": "meta-1", "version": "1", "registry": registry}])
        r = bl.deep_scan_with_metadata(npm_deep=1, pypi_deep=0, npm_meta=1, pypi_meta=1,
                                       dsh_meta=1, out_dir=str(tmp_path))
        assert r["deep_scan"]["total"] >= 1 and r["metadata_scan"]["total"] == 3


class TestScore:
    def _bundle(self, d, name, verdict="pass", expires="2026-12-30T00:00:00Z", broken=False):
        from canari.signing import generate_keypair, sign_attestation
        signer, pub = generate_keypair()
        att = {"_type": V, "subject": {"name": name, "version": "1", "registry": "npm",
                                       "artifact_sha256": "a" * 64, "maintainers": []},
               "host": {"class": "mcp", "host_version": "t"},
               "scenario_sha256": "b" * 64,
               "checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t"}],
               "verdict": verdict, "checker": {"kind": "automation", "id": "t"},
               "evidence_refs": [],
               "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                         "truncated_fields": []},
               "expires_at": expires, "generated_at": "2026-11-10T00:00:00Z",
               "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": V}}
        s = sign_attestation(att, signer)
        ad = os.path.join(d, "attestations")
        os.makedirs(ad, exist_ok=True)
        fp = os.path.join(ad, name + ".bundle.json")
        if broken:
            open(fp, "w", encoding="utf-8").write("{broken")
        else:
            json.dump({"envelope": s["envelope"], "payload": s["payload"]},
                      open(fp, "w", encoding="utf-8"))
        return pub.to_dict()

    def test_mixed_store(self, tmp_path):
        from canari.score import score, format_report
        pub = self._bundle(str(tmp_path), "good")
        self._bundle(str(tmp_path), "expired", expires="2020-01-01T00:00:00Z")
        self._bundle(str(tmp_path), "broken", broken=True)
        s = score(str(tmp_path), public_key=pub)
        assert s["total_attestations"] == 3
        assert s["freshness"]["expired"] == 1
        assert "Canari Scoring Card" in format_report(s)

    def test_empty(self, tmp_path):
        from canari.score import score, format_report
        assert "error" in score(str(tmp_path))
        os.makedirs(os.path.join(str(tmp_path), "attestations"))
        assert score(str(tmp_path))["error"] == "empty attestation store"
        assert format_report({"error": "x"}).startswith("ERROR")


class TestGuardExtras:
    def test_parse_forms(self):
        from canari.guard import parse_install
        assert parse_install(["py", "-m", "pip", "install", "x"]) == [("pypi", "x", None)]
        assert parse_install(["dsh", "--profile", "web"]) == []
        assert parse_install([]) == []

    def test_unknown_executable(self, capfd):
        from canari.guard import main
        rc = main(["--store", "out", "--", "definitely-not-a-binary", "install", "x"])
        assert rc in (3, 5)

    @pytest.mark.skipif(sys.platform != "win32", reason="uses cmd.exe to run a harmless command")
    def test_review_then_execute(self, tmp_path):
        from canari.guard import main
        from canari.signing import generate_keypair, sign_attestation
        signer, pub = generate_keypair()
        att = {"_type": V, "subject": {"name": "okpkg", "version": "1", "registry": "npm",
                                       "artifact_sha256": "a" * 64, "maintainers": []},
               "host": {"class": "mcp", "host_version": "t"}, "scenario_sha256": "b" * 64,
               "checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t"}],
               "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
               "evidence_refs": [],
               "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                         "truncated_fields": []},
               "expires_at": "2026-12-30T00:00:00Z", "generated_at": "2026-11-10T00:00:00Z",
               "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": V}}
        s = sign_attestation(att, signer)
        ad = tmp_path / "attestations"
        ad.mkdir()
        (ad / "a.bundle.json").write_text(json.dumps({"envelope": s["envelope"],
                                                      "payload": s["payload"]}), encoding="utf-8")
        rc = main(["--store", str(tmp_path), "--allow-review", "--",
                   "cmd", "/c", "echo", "hi", "install", "okpkg"])
        assert rc == 0


class TestMcpExtras:
    def _mk(self, tmp_path):
        from canari.signing import generate_keypair, sign_attestation
        signer, pub = generate_keypair()
        att = {"_type": V, "subject": {"name": "p", "version": "1", "registry": "npm",
                                       "artifact_sha256": "a" * 64, "maintainers": []},
               "host": {"class": "mcp", "host_version": "t"}, "scenario_sha256": "b" * 64,
               "checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "t"}],
               "verdict": "pass", "checker": {"kind": "automation", "id": "t"},
               "evidence_refs": [],
               "evidence_completeness": {"dropped_logs": 0, "missing_observers": [],
                                         "truncated_fields": []},
               "expires_at": "2026-12-30T00:00:00Z", "generated_at": "2026-11-10T00:00:00Z",
               "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": V}}
        s = sign_attestation(att, signer)
        bp = tmp_path / "b.json"
        bp.write_text(json.dumps({"envelope": s["envelope"], "payload": s["payload"]}),
                      encoding="utf-8")
        kp = tmp_path / "k.json"
        kp.write_text(json.dumps(pub.to_dict()), encoding="utf-8")
        return str(bp), str(kp)

    def test_verify_tool_ok(self, tmp_path):
        from canari.mcp_server import _handle
        bp, kp = self._mk(tmp_path)
        r = _handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "verify_bundle",
                                "arguments": {"bundle_path": bp, "key_path": kp}}}, "out", None)
        assert json.loads(r["result"]["content"][0]["text"])["ok"] is True

    def test_verify_tool_missing(self, tmp_path):
        from canari.mcp_server import _handle
        r = _handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "verify_bundle",
                                "arguments": {"bundle_path": str(tmp_path / "no")}}}, "out", None)
        assert json.loads(r["result"]["content"][0]["text"])["ok"] is False

    def test_serve_and_main(self):
        from canari.mcp_server import serve, main
        stdin = _io.StringIO('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
        out = _io.StringIO()
        serve(stdin=stdin, stdout=out, store="out")
        assert "canari" in out.getvalue()
        with pytest.raises(SystemExit):
            main(["--help"])
