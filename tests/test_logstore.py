# -*- coding: utf-8 -*-
"""Adversarial tests for the append-only log and the offline verifier.

The properties that matter, in order:
  1. a bundle verifies with no network and no import of the log implementation
  2. rewriting/truncating an already-signed log CANNOT be re-signed
  3. every tamper path (entry bytes, index, head size/root, signature, proof)
     turns verification red
"""
import base64
import copy
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from canari.logstore import (LogRewritten, LogTruncated, canonical_bytes,
                             open_log, verify_head_signature)
from canari.verify_offline import verify_bundle


@pytest.fixture()
def logdir(tmp_path):
    return str(tmp_path / "log")


def make_log(logdir, n=6, log_id="test-log"):
    L = open_log(logdir, log_id=log_id)
    L.append_many([{"payload": {"i": i}} for i in range(n)])
    L.seal(timestamp="2026-01-01T00:00:00Z")
    return L


class TestAppend:
    def test_seq_is_contiguous_across_runs(self, logdir):
        make_log(logdir, 3)
        L2 = open_log(logdir, log_id="test-log")
        res = L2.append_many([{"payload": {"i": 99}}])
        assert res[0]["index"] == 3
        assert L2.size() == 4

    def test_append_is_canonical_and_reproducible(self, logdir):
        L = make_log(logdir, 1)
        raw = L.entries()[0]
        entry = json.loads(raw)
        assert raw == canonical_bytes(entry)
        assert entry["seq"] == 0 and entry["spec"].endswith("/v1")

    def test_empty_append_is_noop(self, logdir):
        L = make_log(logdir, 2)
        before = L.size()
        assert L.append_many([]) == []
        assert L.size() == before

    def test_concurrent_appends_do_not_reuse_seq(self, logdir):
        import threading
        L = open_log(logdir, log_id="test-log")
        L.append_many([{"payload": {}}])
        errs = []

        def work(n):
            try:
                open_log(logdir, log_id="test-log").append({"n": n})
            except Exception as e:  # pragma: no cover
                errs.append(e)

        ts = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert not errs
        seqs = [e["seq"] for e in open_log(logdir, log_id="test-log").entry_objs()]
        assert seqs == list(range(len(seqs)))


class TestSeal:
    def test_seal_publishes_signed_head(self, logdir):
        L = make_log(logdir, 4)
        head = L.last_head()
        assert head["body"]["size"] == 4
        assert head["body"]["log_id"] == "test-log"
        assert head["body"]["timestamp"] == "2026-01-01T00:00:00Z"
        pub = L.public_key()["key"]
        assert verify_head_signature(head, pub)

    def test_seal_is_idempotent_without_new_entries(self, logdir):
        L = make_log(logdir, 3)
        assert L.seal() is None
        assert len(L.heads()) == 1

    def test_force_reseals(self, logdir):
        L = make_log(logdir, 3)
        assert L.seal(force=True, timestamp="2026-02-02T00:00:00Z") is not None
        assert len(L.heads()) == 2

    def test_key_persists_across_instances(self, logdir):
        L = make_log(logdir, 2)
        k1 = L.public_key()["keyid"]
        L2 = open_log(logdir, log_id="test-log")
        L2.append_many([{"payload": {}}])
        L2.seal()
        assert L2.public_key()["keyid"] == k1
        for h in L2.heads():
            assert verify_head_signature(h, L2.public_key()["key"])

    def test_head_signature_does_not_verify_with_other_key(self, logdir):
        from canari.signing import generate_keypair
        L = make_log(logdir, 2)
        _, other = generate_keypair()
        assert not verify_head_signature(L.last_head(), other.to_dict())


class TestTamperDetection:
    def test_rewritten_entry_is_refused(self, logdir):
        L = make_log(logdir, 4)
        entries = L._read_entries()
        obj = json.loads(entries[1])
        obj["payload"]["i"] = 999
        entries[1] = canonical_bytes(obj)
        with open(L.entries_path, "wb") as f:
            f.write(b"\n".join(entries) + b"\n")
        with pytest.raises(LogRewritten):
            open_log(logdir, log_id="test-log").seal()

    def test_truncated_log_is_refused(self, logdir):
        L = make_log(logdir, 5)
        entries = L._read_entries()
        with open(L.entries_path, "wb") as f:
            f.write(b"\n".join(entries[:3]) + b"\n")
        with pytest.raises(LogTruncated):
            open_log(logdir, log_id="test-log").seal()

    def test_audit_reports_rewrite_without_raising(self, logdir):
        L = make_log(logdir, 4)
        entries = L._read_entries()
        entries[0] = entries[0].replace(b'"i":0', b'"i":7')
        with open(L.entries_path, "wb") as f:
            f.write(b"\n".join(entries) + b"\n")
        rep = open_log(logdir, log_id="test-log").audit()
        assert rep["ok"] is False
        assert any("REWRITTEN" in e for e in rep["errors"])

    def test_audit_reports_broken_seq(self, logdir):
        L = make_log(logdir, 3)
        entries = L._read_entries()
        obj = json.loads(entries[2])
        obj["seq"] = 7
        entries[2] = canonical_bytes(obj)
        with open(L.entries_path, "wb") as f:
            f.write(b"\n".join(entries) + b"\n")
        rep = open_log(logdir, log_id="test-log").audit()
        assert rep["ok"] is False
        assert any("seq" in e for e in rep["errors"])

    def test_resealing_after_append_is_consistent(self, logdir):
        L = make_log(logdir, 3)
        L.append_many([{"payload": {"i": i}} for i in range(3, 8)])
        L.seal(timestamp="2026-01-02T00:00:00Z")
        c = L.prove_consistency()
        from canari.merkle import verify_consistency
        assert verify_consistency(c["from_head"]["body"]["size"],
                                  c["to_head"]["body"]["size"],
                                  bytes.fromhex(c["from_head"]["body"]["root"]),
                                  bytes.fromhex(c["to_head"]["body"]["root"]),
                                  [bytes.fromhex(x) for x in c["proof"]])


class TestOfflineBundle:
    def test_bundle_passes_all_checks(self, logdir):
        L = make_log(logdir, 6)
        L.append_many([{"payload": {"i": i}} for i in range(6, 12)])
        L.seal(timestamp="2026-01-02T00:00:00Z")
        rep = verify_bundle(L.export_bundle(4))
        assert rep["ok"] is True, [c for c in rep["checks"] if not c["ok"]]
        assert {c["name"] for c in rep["checks"]} >= {
            "tree_head.signature", "entry.inclusion", "consistency.proof"}

    def test_bundle_verifies_without_importing_canari(self, logdir, tmp_path):
        """The verifier must work as a standalone script - reimplementation,
        not a call into the code that produced the bundle."""
        L = make_log(logdir, 5)
        p = tmp_path / "bundle.json"
        p.write_text(json.dumps(L.export_bundle(2)), encoding="utf-8")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "canari", "verify_offline.py"),
                            str(p)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "RESULT: OK" in r.stdout

    def test_standalone_verifier_has_no_canari_import(self):
        src = open(os.path.join(ROOT, "canari", "verify_offline.py"), encoding="utf-8").read()
        assert "from canari" not in src
        assert "import canari" not in src

    @pytest.mark.parametrize("mutate", [
        lambda b: b["entry"].__setitem__("index", 1),
        lambda b: b["tree_head"]["body"].__setitem__("size", 2),
        lambda b: b["tree_head"]["body"].__setitem__("root", "00" * 32),
        lambda b: b["tree_head"]["body"].__setitem__("log_id", "evil"),
        lambda b: b["tree_head"]["body"].__setitem__("spec", "evil/v1"),
        lambda b: b["tree_head"]["signature"].__setitem__("sig", "00" * 64),
        lambda b: b.__setitem__("inclusion_proof", []),
        lambda b: b["inclusion_proof"].__setitem__(0, "11" * 32),
        lambda b: b.__setitem__("spec", "nope"),
        lambda b: b["public_key"]["keyval"].__setitem__("public", "00" * 32),
    ])
    def test_bundle_tamper_fails(self, logdir, mutate):
        L = make_log(logdir, 8)
        b = L.export_bundle(5)
        mutate(b)
        assert verify_bundle(b)["ok"] is False

    def test_tampered_entry_bytes_fail(self, logdir):
        L = make_log(logdir, 8)
        b = L.export_bundle(5)
        raw = bytearray(base64.b64decode(b["entry"]["data_b64"]))
        raw[3] ^= 0x01
        b["entry"]["data_b64"] = base64.b64encode(bytes(raw)).decode()
        assert verify_bundle(b)["ok"] is False

    def test_seal_refuses_to_sign_a_fork(self, logdir):
        """The honest publishing path must stop before signing a rewrite."""
        L = make_log(logdir, 4)
        entries = L._read_entries()
        obj = json.loads(entries[0])
        obj["payload"]["i"] = 1000
        entries[0] = canonical_bytes(obj)
        with open(L.entries_path, "wb") as f:
            f.write(b"\n".join(entries) + b"\n")
        with pytest.raises(LogRewritten):
            L.seal(force=True)

    def test_consistency_rejects_a_re_signed_fork(self, logdir):
        """Threat model: the publisher still holds the key and simply signs a
        different history. A signature check alone cannot catch that; only the
        consistency proof can. This is the whole reason the log exists."""
        from canari.logstore import head_body, sign_head
        from canari.merkle import consistency_proof
        L = make_log(logdir, 4)
        first = copy.deepcopy(L.last_head())
        signer = L._ensure_signer()
        base = L.entries()
        forged_entries = []
        for i in range(6):
            obj = json.loads(base[i]) if i < 4 else {"spec": "canari-log-entry/v1", "seq": i,
                                                     "kind": "record", "timestamp": "t",
                                                     "payload": {"i": i}}
            obj["payload"]["i"] = 1000 + i
            forged_entries.append(canonical_bytes(obj))
        from canari.merkle import leaf_hash, merkle_root
        leaves = [leaf_hash(b) for b in forged_entries]
        forged = sign_head(head_body("test-log", 6, merkle_root(leaves).hex(),
                                     "2026-01-03T00:00:00Z"), signer)
        bundle = {
            "spec": "canari-inclusion-bundle/v1",
            "log_id": "test-log",
            "public_key": L.public_key()["key"],
            "entry": {"index": 0, "data_b64": base64.b64encode(forged_entries[0]).decode()},
            "tree_head": forged,
            "inclusion_proof": [p.hex() for p in
                                __import__("canari.merkle", fromlist=["inclusion_proof"])
                                .inclusion_proof(leaves, 0)],
            "consistency": {"from_head": first,
                            "proof": [p.hex() for p in consistency_proof(leaves, 4)]},
        }
        rep = verify_bundle(bundle)
        assert rep["ok"] is False
        assert any(c["name"] == "consistency.proof" and not c["ok"] for c in rep["checks"])

    def test_min_size_and_pinned_root(self, logdir):
        L = make_log(logdir, 5)
        b = L.export_bundle(0)
        assert verify_bundle(b, min_size=6)["ok"] is False
        assert verify_bundle(b, min_size=5)["ok"] is True
        assert verify_bundle(b, expected_root="ab" * 32)["ok"] is False
        assert verify_bundle(b, expected_root=b["tree_head"]["body"]["root"])["ok"] is True
        assert verify_bundle(b, expected_log_id="other")["ok"] is False

    def test_malformed_bundles_fail_closed(self, logdir):
        for bad in (None, {}, [], {"spec": "canari-inclusion-bundle/v1"}):
            rep = verify_bundle(bad)
            assert rep["ok"] is False

    def test_empty_log_bundle_is_impossible(self, logdir):
        L = open_log(logdir, log_id="test-log")
        L.seal()
        with pytest.raises(IndexError):
            L.prove_inclusion(0)


class TestC2SPCheckpoint:
    """Our native head format is not what the witness network speaks. These
    tests pin the c2sp.org signed-note / tlog-checkpoint emission so a witness
    can co-sign us without adopting anything of ours."""

    def test_checkpoint_note_verifies_and_matches_head(self, logdir):
        L = make_log(logdir, 6)
        note = L.checkpoint_note(origin="canari-test/log")
        rep = L.verify_checkpoint_note(note)
        assert rep["ok"] is True
        assert rep["origin"] == "canari-test/log"
        assert rep["size"] == 6
        assert rep["root"] == L.last_head()["body"]["root"]

    def test_checkpoint_is_in_the_bundle(self, logdir):
        L = make_log(logdir, 3)
        b = L.export_bundle(0)
        assert "checkpoint" in b
        assert b["checkpoint"].startswith("test-log\n") or \
            b["checkpoint"].startswith(L.log_id + "\n")

    def test_checkpoint_requires_a_head(self, logdir):
        from canari.logstore import LogError
        L = open_log(logdir, log_id="empty")
        L.append({"a": 1})
        with pytest.raises(LogError):
            L.checkpoint_note()

    def test_tampered_checkpoint_fails_own_verification(self, logdir):
        L = make_log(logdir, 4)
        note = L.checkpoint_note()
        bad = note.replace("\n4\n", "\n5\n", 1)
        assert L.verify_checkpoint_note(bad)["ok"] is False
