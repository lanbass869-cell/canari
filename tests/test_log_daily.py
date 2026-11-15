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
                             "--url", "https://example.invalid/a.json.gz",
                             "--url", "https://example.invalid/b.json.gz"])
        assert rc == 0
        assert out.exists()
        saved = json.loads(out.read_text(encoding="utf-8"))
        assert saved["audit"]["ok"] is True
        assert saved["head"]["body"]["size"] == 2

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


class TestIdempotencyAndPublishing:
    """Two production bugs found while running this for real (2026-11-15):

    1. Re-running the daily job appended a duplicate commitment for identical
       bytes. The log then contained the same data twice, which inflates proof
       sizes and, worse, makes "how many days of history do we have" a lie.
    2. On the no-new-data path, `head` was None and head-latest.json was
       overwritten with null -- deleting the only published root a consumer
       could have pinned against.

    Both are locked down here.
    """

    @staticmethod
    def fake(raw, monkeypatch):
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

    def test_second_run_appends_nothing(self, tmp_path, monkeypatch):
        self.fake(payload(3), monkeypatch)
        d = str(tmp_path / "log")
        out = tmp_path / "h.json"
        urls = ["--url", "https://x.invalid/a.gz", "--url", "https://x.invalid/b.gz"]
        assert log_daily.main(["--log-dir", d, "--out", str(out), *urls]) == 0
        assert json.loads(out.read_text(encoding="utf-8"))["appended"] == [0, 1]
        assert log_daily.main(["--log-dir", d, "--out", str(out), *urls]) == 0
        saved = json.loads(out.read_text(encoding="utf-8"))
        assert saved["appended"] == []
        assert open(os.path.join(d, "log.jsonl"), encoding="utf-8").read().count("\n") == 2

    def test_second_run_keeps_publishing_the_last_head(self, tmp_path, monkeypatch):
        self.fake(payload(3), monkeypatch)
        d = str(tmp_path / "log")
        out = tmp_path / "h.json"
        log_daily.main(["--log-dir", d, "--out", str(out), "--url", "https://x.invalid/a.gz"])
        first = json.loads(out.read_text(encoding="utf-8"))["head"]["body"]
        log_daily.main(["--log-dir", d, "--out", str(out), "--url", "https://x.invalid/a.gz"])
        second = json.loads(out.read_text(encoding="utf-8"))["head"]["body"]
        assert second is not None
        assert second["root"] == first["root"] and second["size"] == first["size"]

    def test_changed_bytes_append_and_reseal(self, tmp_path, monkeypatch):
        d = str(tmp_path / "log")
        out = tmp_path / "h.json"
        urls = ["--url", "https://x.invalid/a.gz", "--url", "https://x.invalid/b.gz"]
        self.fake(payload(3), monkeypatch)
        log_daily.main(["--log-dir", d, "--out", str(out), *urls])
        h1 = json.loads(out.read_text(encoding="utf-8"))["head"]
        self.fake(payload(6), monkeypatch)
        log_daily.main(["--log-dir", d, "--out", str(out), *urls])
        saved = json.loads(out.read_text(encoding="utf-8"))
        assert saved["appended"] == [2, 3]
        assert saved["head"]["body"]["size"] == 4
        assert saved["head"]["body"]["root"] != h1["body"]["root"]
        assert saved["audit"]["ok"] is True


class TestCrossCheckAgainstPublisher:
    """mcpcost publishes its own sha256/bytes in latest.index.json. Comparing
    our recomputation to that claim is what catches a truncated download or a
    swapped body -- and it is the difference between "we hashed some bytes" and
    "the bytes we saw are the bytes the publisher says it published"."""

    @staticmethod
    def rec(raw, rows=3):
        return log_daily.summarize({"name": "x", "url": "u.gz", "license": "C"},
                                   raw, "2026-01-01T00:00:00Z")

    def test_matching_index_is_ok(self):
        raw = payload(3)
        r = self.rec(raw)
        idx = {"sha256": r["sha256"], "bytes": len(raw), "entries": r["rows"]}
        cc = log_daily.cross_check_index(r, idx, "i")
        assert cc["ok"] is True
        assert cc["sha256_matches_publisher"] is True
        assert cc["bytes_matches_publisher"] is True
        assert cc["rows_matches_publisher"] is True

    def test_hash_mismatch_is_a_problem(self):
        raw = payload(3)
        r = self.rec(raw)
        idx = {"sha256": "00" * 32, "bytes": len(raw), "entries": r["rows"]}
        cc = log_daily.cross_check_index(r, idx, "i")
        assert cc["ok"] is False
        assert cc["sha256_matches_publisher"] is False
        assert any("sha256 mismatch" in p for p in cc["problems"])

    def test_byte_count_mismatch_is_a_problem(self):
        raw = payload(3)
        r = self.rec(raw)
        idx = {"sha256": r["sha256"], "bytes": len(raw) + 1, "entries": r["rows"]}
        cc = log_daily.cross_check_index(r, idx, "i")
        assert cc["ok"] is False
        assert any("byte count mismatch" in p for p in cc["problems"])

    def test_row_count_mismatch_is_a_problem(self):
        raw = payload(3)
        r = self.rec(raw)
        idx = {"sha256": r["sha256"], "bytes": len(raw), "entries": r["rows"] + 10}
        cc = log_daily.cross_check_index(r, idx, "i")
        assert cc["ok"] is False
        assert any("row count mismatch" in p for p in cc["problems"])

    def test_missing_publisher_hash_fails_closed(self):
        raw = payload(3)
        r = self.rec(raw)
        cc = log_daily.cross_check_index(r, {"bytes": len(raw)}, "i")
        assert cc["ok"] is False
        assert cc["sha256_matches_publisher"] is None

    def test_unreachable_index_is_recorded_not_fatal(self, tmp_path, monkeypatch):
        class Fake:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return payload(2)

        def urlopen(req, *a, **k):
            if "index" in str(getattr(req, "full_url", req)):
                raise OSError("index down")
            return Fake()

        monkeypatch.setattr(log_daily.urllib.request, "urlopen", urlopen)
        d = str(tmp_path / "log")
        out = tmp_path / "h.json"
        rc = log_daily.main(["--log-dir", d, "--out", str(out),
                             "--url", "https://x.invalid/a.gz",
                             "--index-url", "https://x.invalid/index.json"])
        assert rc == 0
        saved = json.loads(out.read_text(encoding="utf-8"))
        assert saved["audit"]["ok"] is True
        entry = json.loads(open(os.path.join(d, "log.jsonl"), encoding="utf-8").readline())
        assert entry["payload"]["cross_check"]["ok"] is None
        assert "error" in entry["payload"]["cross_check"]


class TestGzipByMagicBytes:
    """Real bug (2026-11-15): ProtocolProbe serves gzip from a URL with no
    .gz suffix. The old suffix check took the raw branch, json.loads choked on
    gzip bytes, and the row count was silently recorded as "?" -- the hash was
    right, the human-readable summary was wrong. Decide by magic bytes."""

    def test_gzip_without_suffix_is_decompressed(self):
        raw = payload(4)
        rec = log_daily.summarize(
            {"name": "pp", "url": "https://x/api/v1/evidence", "license": "CC"},
            raw, "t")
        assert "parse_error" not in rec
        assert rec["rows"] == 4
        assert rec["plain_bytes"] > 0

    def test_plain_json_still_parses(self):
        raw = json.dumps([{"state": "alive"}, {"state": "dead"}]).encode()
        rec = log_daily.summarize(
            {"name": "p", "url": "https://x/e.json", "license": "CC"}, raw, "t")
        assert rec["rows"] == 2
        assert rec["states"] == {"alive": 1, "dead": 1}

    def test_broken_gzip_is_recorded(self):
        rec = log_daily.summarize(
            {"name": "p", "url": "https://x/e", "license": "CC"},
            b"\x1f\x8bnotreallygzip", "t")
        assert "parse_error" in rec

    def test_metadata_fields_captured(self):
        doc = {"dataset": "d", "probed_at": "P", "snapshot": "S",
               "generated_at": "G", "format": "f", "servers": 7,
               "rows": [{"state": "alive"}]}
        raw = gzip.compress(json.dumps(doc).encode())
        rec = log_daily.summarize(
            {"name": "p", "url": "https://x/e", "license": "CC"}, raw, "t")
        assert rec["source_dataset"] == "d"
        assert rec["source_probed_at"] == "P"
        assert rec["source_snapshot"] == "S"
        assert rec["source_generated_at"] == "G"
        assert rec["source_format"] == "f"
        assert rec["servers"] == 7


class TestCorrections:
    """Append-only means a published field is never edited. The honest repair
    for wrong metadata is a `correction` record, and re-running the corrector
    must be a no-op (the first version kept re-appending because it compared
    against the original value instead of the already-corrected one)."""

    def test_correction_is_appended_and_applied(self, tmp_path):
        import log_correct
        d = str(tmp_path / "log")
        L = open_log(d, log_id="canari-snapshot-log")
        L.append({"source": "x", "sha256": "ab" * 32, "rows": None}, kind="source-snapshot")
        L.seal()
        assert log_correct.main(["--log-dir", d, "--seq", "0", "--field", "rows",
                                 "--value", "63318", "--reason", "parser bug"]) == 0
        L2 = open_log(d, log_id="canari-snapshot-log")
        entries = L2.entry_objs()
        assert len(entries) == 2
        assert entries[0]["payload"]["rows"] is None          # original untouched
        assert entries[1]["payload"]["new_value"] == 63318
        assert L2.audit()["ok"] is True

    def test_rerun_is_idempotent(self, tmp_path):
        import log_correct
        d = str(tmp_path / "log")
        L = open_log(d, log_id="canari-snapshot-log")
        L.append({"source": "x", "rows": None}, kind="source-snapshot")
        L.seal()
        args = ["--log-dir", d, "--seq", "0", "--field", "rows",
                "--value", "5", "--reason", "r"]
        assert log_correct.main(args) == 0
        before = len(open(os.path.join(d, "log.jsonl"), encoding="utf-8").readlines())
        assert log_correct.main(args) == 0
        after = len(open(os.path.join(d, "log.jsonl"), encoding="utf-8").readlines())
        assert before == after

    def test_correction_out_of_range_is_usage_error(self, tmp_path):
        import log_correct
        d = str(tmp_path / "log")
        L = open_log(d, log_id="canari-snapshot-log")
        L.append({"source": "x"}, kind="source-snapshot")
        L.seal()
        assert log_correct.main(["--log-dir", d, "--seq", "99", "--field",
                                 "rows", "--value", "1", "--reason", "r"]) == 3

    def test_page_applies_correction_and_keeps_original_in_log(self, tmp_path):
        import publish_log
        d = str(tmp_path / "log")
        L = open_log(d, log_id=publish_log.LOG_ID)
        L.append({"source": "x", "rows": None}, kind="source-snapshot")
        L.seal()
        L.append({"kind": "correction", "corrects_seq": 0, "field": "rows",
                  "old_value": None, "new_value": 7, "reason": "fix"}, kind="correction")
        L.seal()
        entries, corrections = publish_log.apply_corrections(L.entry_objs())
        assert corrections and corrections[0]["new"] == 7
        assert entries[0]["payload"]["rows"] == 7
        assert L.entry_objs()[0]["payload"]["rows"] is None


class TestSingleWriterOfHeadLatest:
    """CI run 43685282965 failed at "Verify what we are about to publish" with
    root.pinned FAILED: head-latest.json still carried size 23 while the bundle
    carried size 43. Cause: head-latest.json had two writers -- log_daily.py
    wrote it, then log_verdicts.py sealed a newer head and left the pointer
    stale, so CI pinned the old root against the new bundle.

    The rule that fixes it: publish_log.py is the *only* writer of that
    pointer, and it derives it from the log itself, never from an earlier step.
    """

    def test_publish_log_is_the_only_writer(self):
        """Scan for scripts that actually OPEN the pointer for writing.

        Mentioning the filename in a docstring or in a guard that refuses to
        use it is fine (anchor_ots.py does exactly that); opening it for write
        is not.
        """
        import re
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        write_re = re.compile(r'head-latest\.json"[^)]*,\s*"w"', re.S)
        offenders = []
        for dirpath, _d, files in os.walk(os.path.join(root, "scripts")):
            for fn in files:
                if not fn.endswith(".py") or fn == "__init__.py":
                    continue
                src = open(os.path.join(dirpath, fn), encoding="utf-8").read()
                if write_re.search(src) and fn != "publish_log.py":
                    offenders.append(fn)
        assert offenders == [], (
            "publish_log.py must be the single writer of head-latest.json or "
            "the pointer goes stale: %s" % offenders)

    def test_published_pointer_matches_the_published_bundle(self, tmp_path):
        import publish_log
        d = tmp_path / "log"
        L = open_log(str(d), log_id=publish_log.LOG_ID)
        L.append({"source": "x", "rows": 1}, kind="source-snapshot")
        L.seal()
        b = publish_log.build_bundle(L, str(d / "bundle-latest.json"))
        publish_log.build_page(L, str(d / "index.html"))
        # emulate the pointer write the CLI path performs
        with open(str(d / "head-latest.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump({"appended": [], "head": L.last_head(), "audit": L.audit()}, f)
        head = json.loads((d / "head-latest.json").read_text(encoding="utf-8"))
        assert head["head"]["body"]["root"] == b["tree_head"]["body"]["root"]
        assert head["head"]["body"]["size"] == b["tree_head"]["body"]["size"]
