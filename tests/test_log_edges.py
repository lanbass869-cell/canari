# -*- coding: utf-8 -*-
"""Coverage for the offline verifier CLI and the logstore's error branches.

These exist because the failure paths are the product: a verifier that
crashes on a malformed bundle, or a seal() that raises the wrong exception,
is a broken verifier whether or not the happy path works.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from canari import logstore, verify_offline  # noqa: E402
from canari.logstore import (LogError, check_head_body, open_log,
                             verify_head_signature)
from canari.verify_offline import verify_bundle, verify_consistency  # noqa: E402


@pytest.fixture()
def log(tmp_path):
    L = open_log(str(tmp_path / "log"), log_id="cov")
    L.append_many([{"payload": {"i": i}} for i in range(4)])
    L.seal(timestamp="2026-01-01T00:00:00Z")
    return L


class TestVerifyCli:
    def test_main_pass(self, log, tmp_path, capsys):
        p = tmp_path / "b.json"
        p.write_text(json.dumps(log.export_bundle(1)), encoding="utf-8")
        assert verify_offline.main([str(p)]) == 0
        assert "RESULT: OK" in capsys.readouterr().out

    def test_main_fail(self, log, tmp_path, capsys):
        b = log.export_bundle(1)
        b["entry"]["index"] = 0
        p = tmp_path / "b.json"
        p.write_text(json.dumps(b), encoding="utf-8")
        assert verify_offline.main([str(p)]) == 2
        assert "RESULT: FAILED" in capsys.readouterr().out

    def test_main_json(self, log, tmp_path, capsys):
        p = tmp_path / "b.json"
        p.write_text(json.dumps(log.export_bundle(0)), encoding="utf-8")
        assert verify_offline.main([str(p), "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["ok"] is True

    def test_main_unreadable(self, tmp_path):
        assert verify_offline.main([str(tmp_path / "missing.json")]) == 3

    def test_main_with_pins(self, log, tmp_path, capsys):
        b = log.export_bundle(0)
        p = tmp_path / "b.json"
        p.write_text(json.dumps(b), encoding="utf-8")
        root = b["tree_head"]["body"]["root"]
        assert verify_offline.main([str(p), "--root", root, "--log-id", "cov",
                                    "--min-size", "4"]) == 0
        assert verify_offline.main([str(p), "--min-size", "9"]) == 2


class TestVerifyEdge:
    def test_non_dict_bundle(self):
        assert verify_bundle([])["ok"] is False

    def test_missing_public_key(self):
        assert verify_bundle({"spec": "canari-inclusion-bundle/v1"})["ok"] is False

    def test_missing_tree_head(self):
        rep = verify_bundle({"spec": "canari-inclusion-bundle/v1",
                             "public_key": {"keytype": "ed25519"}})
        assert rep["ok"] is False
        assert any(c["name"] == "tree_head.present" for c in rep["checks"])

    def test_bad_base64_entry(self, log):
        b = log.export_bundle(0)
        b["entry"]["data_b64"] = "!!!!"
        assert verify_bundle(b)["ok"] is False

    def test_non_int_index(self, log):
        b = log.export_bundle(0)
        b["entry"]["index"] = "0"
        assert verify_bundle(b)["ok"] is False

    def test_consistency_with_bad_from_head(self, log):
        log.append_many([{"payload": {"more": 1}}])
        log.seal()
        b = log.export_bundle(0)
        b["consistency"]["from_head"]["body"]["size"] = -1
        assert verify_bundle(b)["ok"] is False

    def test_inclusion_rejects_oversized_proof(self, log):
        b = log.export_bundle(0)
        b["inclusion_proof"] = ["00" * 32] * 65
        assert verify_bundle(b)["ok"] is False

    def test_inclusion_rejects_bad_hex(self, log):
        b = log.export_bundle(0)
        b["inclusion_proof"] = ["zz"]
        assert verify_bundle(b)["ok"] is False

    def test_consistency_trivial_cases(self):
        assert verify_consistency(0, 5, "aa" * 32, "bb" * 32, []) is True
        assert verify_consistency(3, 3, "aa" * 32, "aa" * 32, []) is True
        assert verify_consistency(3, 3, "aa" * 32, "bb" * 32, []) is False
        assert verify_consistency(5, 3, "aa" * 32, "bb" * 32, []) is False
        assert verify_consistency(1, 2, "aa" * 32, "bb" * 32, []) is False

    def test_head_rejects_wrong_keytype(self, log):
        h = log.last_head()
        k = dict(log.public_key()["key"])
        k["keytype"] = "rsa"
        assert verify_head_signature(h, k) is False

    def test_head_rejects_short_sig(self, log):
        h = json.loads(json.dumps(log.last_head()))
        h["signature"]["sig"] = "00"
        assert verify_head_signature(h, log.public_key()["key"]) is False

    def test_head_rejects_non_spec(self, log):
        h = json.loads(json.dumps(log.last_head()))
        h["body"]["spec"] = "other/v1"
        assert verify_head_signature(h, log.public_key()["key"]) is False

    def test_head_rejects_wrong_public_key(self, log):
        from canari.signing import generate_keypair
        _, other = generate_keypair()
        assert verify_head_signature(log.last_head(), other.to_dict()) is False


class TestLogStoreEdges:
    def test_check_head_body_rejects(self):
        good = {"spec": logstore.SPEC, "log_id": "l", "size": 1,
                "root": "ab" * 32, "timestamp": "t"}
        assert check_head_body(good) == ""
        assert check_head_body(None) != ""
        assert check_head_body(dict(good, spec="x")) != ""
        assert check_head_body(good, "other") != ""
        assert check_head_body(dict(good, size=-1)) != ""
        assert check_head_body(dict(good, size=True)) != ""
        assert check_head_body(dict(good, size=2 ** 41)) != ""
        assert check_head_body(dict(good, root="zz")) != ""
        assert check_head_body(dict(good, root="ab")) != ""
        assert check_head_body(dict(good, timestamp="")) != ""

    def test_corrupt_head_makes_seal_fail(self, log):
        h = json.loads(json.dumps(log.last_head()))
        h["body"]["spec"] = "broken"
        p = log.heads_path
        lines = open(p, encoding="utf-8").read().splitlines()
        lines[-1] = json.dumps(h)
        open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        with pytest.raises(LogError):
            open_log(log.dir, log_id="cov").seal(force=True)

    def test_garbage_head_json_makes_audit_noisy(self, log):
        p = log.heads_path
        open(p, "a", encoding="utf-8").write("{not json}\n")
        with pytest.raises(json.JSONDecodeError):
            open_log(log.dir, log_id="cov").heads()

    def test_prove_inclusion_requires_head(self, tmp_path):
        L = open_log(str(tmp_path / "l2"), log_id="x")
        L.append({"a": 1})
        with pytest.raises(LogError):
            L.prove_inclusion(0)

    def test_prove_consistency_requires_two_heads(self, log):
        with pytest.raises(LogError):
            log.prove_consistency()

    def test_prove_consistency_unknown_size(self, log):
        log.append_many([{"payload": {}}])
        log.seal()
        with pytest.raises(LogError):
            log.prove_consistency(first_size=99)

    def test_appended_entry_outside_head_is_not_provable(self, log):
        log.append_many([{"payload": {"later": 1}}])
        with pytest.raises(IndexError):
            log.prove_inclusion(4)

    def test_empty_bundle_has_no_consistency(self, log):
        b = log.export_bundle(0)
        assert "consistency" not in b

    def test_public_key_absent(self, tmp_path):
        assert open_log(str(tmp_path / "empty"), log_id="e").public_key() == {}

    def test_audit_on_missing_dir_is_ok(self, tmp_path):
        rep = open_log(str(tmp_path / "fresh"), log_id="f").audit()
        assert rep["ok"] is True and rep["size"] == 0

    def test_audit_detects_bad_last_head_signature(self, log):
        h = json.loads(json.dumps(log.last_head()))
        h["signature"]["sig"] = "00" * 64
        open(log.heads_path, "w", encoding="utf-8").write(json.dumps(h) + "\n")
        rep = open_log(log.dir, log_id="cov").audit()
        assert rep["ok"] is False
        assert any("signature" in e for e in rep["errors"])

    def test_audit_detects_broken_json_entry(self, log):
        with open(log.entries_path, "ab") as f:
            f.write(b"{broken\n")
        rep = open_log(log.dir, log_id="cov").audit()
        assert rep["ok"] is False

    def test_explicit_private_key_path(self, tmp_path):
        key = str(tmp_path / "k.pem")
        L = open_log(str(tmp_path / "lg"), log_id="k", private_key_path=key)
        L.append({"a": 1})
        L.seal()
        assert os.path.exists(key)

    def test_bundle_has_public_keyid(self, log):
        b = log.export_bundle(0)
        assert b["public_key"]["keyid"] == log.public_key()["keyid"]


class TestPinnedPrefix:
    """A consumer who recorded yesterday's root must be able to demand proof
    that today's head still contains it. Pinning the *current* root is a
    different check (root.pinned) and must not be conflated with it."""

    def test_pinned_prefix_pass_and_fail(self, log):
        log.append_many([{"payload": {"more": i}} for i in range(3)])
        log.seal()
        early = log.heads()[0]["body"]["root"]
        b = log.export_bundle(1)
        assert verify_bundle(b, pinned_prefix_root=early)["ok"] is True
        assert verify_bundle(b, pinned_prefix_root="cd" * 32)["ok"] is False

    def test_pinned_prefix_without_consistency_fails(self, log):
        b = log.export_bundle(0)          # single head -> no consistency block
        early = b["tree_head"]["body"]["root"]
        rep = verify_bundle(b, pinned_prefix_root=early)
        assert rep["ok"] is False
        assert any(c["name"] == "prefix.pinned" and not c["ok"] for c in rep["checks"])


class TestCRLFCheckout:
    """Real bug, 2026-11-15: a Windows git checkout converted docs/log/log.jsonl
    from LF to CRLF. Every leaf hash changed, so an intact log audited as
    REWRITTEN with a different root, while CI on Linux stayed green. Since a
    leaf commits to exact bytes, line-ending conversion attacks the log itself.

    Two defences, both tested here:
      1. .gitattributes marks docs/log/** as -text (verified by a scan)
      2. the reader drops one trailing CR and *reports* that it did, so a
         mangled checkout still verifies but the fact is not hidden
    """

    def test_crlf_checkout_still_verifies_and_is_reported(self, log):
        p = log.entries_path
        raw = open(p, "rb").read()
        open(p, "wb").write(raw.replace(b"\n", b"\r\n"))
        L2 = open_log(log.dir, log_id="cov")
        rep = L2.audit()
        assert rep["ok"] is True
        assert rep["crlf_normalized"] is True
        assert rep["root"] == log.audit()["root"]

    def test_lf_log_reports_no_normalisation(self, log):
        assert log.audit()["crlf_normalized"] is False

    def test_leaf_bytes_are_identical_under_both_line_endings(self, log):
        """The normalised leaf must equal the original leaf, not merely produce
        a consistent but different tree."""
        before = log.entry_objs()[0]
        p = log.entries_path
        raw = open(p, "rb").read()          # read first: opening "wb" truncates
        with open(p, "wb") as f:
            f.write(raw.replace(b"\n", b"\r\n"))
        after = open_log(log.dir, log_id="cov").entry_objs()[0]
        assert before == after

    def test_gitattributes_protects_evidence_files(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        text = open(os.path.join(root, ".gitattributes"), encoding="utf-8").read()
        assert "docs/log/** -text" in text, (
            "evidence files must never be EOL-converted; without this a "
            "Windows checkout reports an intact log as rewritten")
