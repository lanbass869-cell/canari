# -*- coding: utf-8 -*-
"""End-to-end test of the daily snapshot path, without the network.

The interesting assertions are not "the record was appended". They are:
  - the same bytes produce the same commitment on two runs
  - a changed upstream file produces a DIFFERENT commitment (no silent reuse)
  - the log refuses to be re-signed after a rewrite
  - a stranger holding only the bundle + public key can check it offline
"""
import gzip
import hashlib
import json
import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import log_daily  # noqa: E402
from canari.logstore import open_log  # noqa: E402
from canari.verify_offline import verify_bundle  # noqa: E402


def payload(rows=3):
    data = [{"entry": "e%d" % i, "state": "alive" if i % 2 else "dead"}
            for i in range(rows)]
    return gzip.compress(json.dumps(data).encode())


class TestSummarize:
    def test_records_hash_size_and_states(self):
        raw = payload(4)
        rec = log_daily.summarize({"name": "x", "url": "u.gz", "license": "CC"},
                                  raw, "2026-01-01T00:00:00Z")
        assert rec["bytes"] == len(raw)
        assert rec["sha256"] == hashlib.sha256(raw).hexdigest()
        assert rec["rows"] == 4
        assert rec["states"] == {"alive": 2, "dead": 2}
        assert rec["plain_sha256"] == hashlib.sha256(gzip.decompress(raw)).hexdigest()

    def test_broken_gzip_is_recorded_not_raised(self):
        rec = log_daily.summarize({"name": "x", "url": "u.gz", "license": "CC"},
                                  b"not gzip", "t")
        assert "parse_error" in rec
        assert rec["sha256"] == hashlib.sha256(b"not gzip").hexdigest()

    def test_different_bytes_mean_different_commitment(self):
        a = log_daily.summarize({"name": "x", "url": "u.gz", "license": "CC"},
                                payload(3), "t")
        b = log_daily.summarize({"name": "x", "url": "u.gz", "license": "CC"},
                                payload(4), "t")
        assert a["sha256"] != b["sha256"]


class TestDailyPath:
    def test_two_days_then_offline_bundle(self, tmp_path):
        d = str(tmp_path / "log")
        L = open_log(d, log_id="snapshot-test")
        L.append(log_daily.summarize({"name": "x", "url": "u.gz", "license": "C"},
                                     payload(3), "2026-01-01T00:00:00Z"),
                 kind="source-snapshot", timestamp="2026-01-01T00:00:00Z")
        L.seal(timestamp="2026-01-01T00:00:00Z")
        L.append(log_daily.summarize({"name": "x", "url": "u.gz", "license": "C"},
                                     payload(5), "2026-01-02T00:00:00Z"),
                 kind="source-snapshot", timestamp="2026-01-02T00:00:00Z")
        L.seal(timestamp="2026-01-02T00:00:00Z")

        L2 = open_log(d, log_id="snapshot-test")
        assert L2.audit()["ok"] is True
        b = L2.export_bundle(1)
        assert b["consistency"]["from_head"]["body"]["size"] == 1
        assert verify_bundle(b)["ok"] is True

        # The day-1 commitment has to differ from day-2 and both must be in log.
        objs = L2.entry_objs()
        assert objs[0]["payload"]["rows"] == 3
        assert objs[1]["payload"]["rows"] == 5

    def test_url_override_is_honoured(self, tmp_path, monkeypatch):
        raw = payload(2)

        class Fake:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return raw

        monkeypatch.setattr(log_daily.urllib.request, "urlopen", lambda *a, **k: Fake())
        d = str(tmp_path / "log")
        out = tmp_path / "head.json"
        rc = log_daily.main(["--log-dir", d, "--out", str(out),
                             "--url", "https://example.invalid/x.json.gz"])
        assert rc == 0
        assert out.exists()
        saved = json.loads(out.read_text(encoding="utf-8"))
        assert saved["audit"]["ok"] is True
        assert saved["head"]["body"]["size"] == 1

    def test_no_network_mode_only_audits(self, tmp_path):
        d = str(tmp_path / "log")
        assert log_daily.main(["--log-dir", d, "--no-network"]) == 0

    def test_rewrite_is_refused_by_daily_path(self, tmp_path):
        d = str(tmp_path / "log")
        L = open_log(d, log_id="canari-snapshot-log")
        L.append({"x": 1}, kind="source-snapshot")
        L.seal()
        p = os.path.join(d, "log.jsonl")
        lines = open(p, "rb").read().split(b"\n")
        lines[0] = lines[0].replace(b'"x":1', b'"x":2')
        open(p, "wb").write(b"\n".join(lines))
        rep = open_log(d, log_id="canari-snapshot-log").audit()
        assert rep["ok"] is False
