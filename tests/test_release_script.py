# -*- coding: utf-8 -*-
"""Tests for scripts/release.py so the release path does not rot."""
import json
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import release  # noqa: E402


class TestChecksumAndSign:
    def test_signs_every_distribution(self, tmp_path, monkeypatch):
        monkeypatch.setattr(release, "DIST", str(tmp_path))
        monkeypatch.setattr(release, "REPO", str(tmp_path))
        os.makedirs(os.path.join(str(tmp_path), "out"), exist_ok=True)
        (tmp_path / "pkg-1.0-py3-none-any.whl").write_bytes(b"wheel-bytes")
        (tmp_path / "pkg-1.0.tar.gz").write_bytes(b"sdist-bytes")
        text = release.checksum_and_sign()
        assert "pkg-1.0-py3-none-any.whl" in text and "pkg-1.0.tar.gz" in text
        sig = json.loads((tmp_path / "SHA256SUMS.sig").read_text(encoding="utf-8"))
        assert sig["alg"] == "ed25519" and len(sig["sig_b64"]) > 40
        pub = json.loads((tmp_path / "release_public_key.json").read_text(encoding="utf-8"))
        assert len(pub["public_hex"]) == 64

    def test_signature_verifies(self, tmp_path, monkeypatch):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import base64
        monkeypatch.setattr(release, "DIST", str(tmp_path))
        monkeypatch.setattr(release, "REPO", str(tmp_path))
        os.makedirs(os.path.join(str(tmp_path), "out"), exist_ok=True)
        (tmp_path / "pkg-1.0.tar.gz").write_bytes(b"x")
        release.checksum_and_sign()
        pub = bytes.fromhex(json.loads(
            (tmp_path / "release_public_key.json").read_text(encoding="utf-8"))["public_hex"])
        sig = base64.b64decode(json.loads(
            (tmp_path / "SHA256SUMS.sig").read_text(encoding="utf-8"))["sig_b64"])
        Ed25519PublicKey.from_public_bytes(pub).verify(
            sig, (tmp_path / "SHA256SUMS").read_bytes())

    def test_key_is_reused_across_calls(self, tmp_path, monkeypatch):
        monkeypatch.setattr(release, "DIST", str(tmp_path))
        monkeypatch.setattr(release, "REPO", str(tmp_path))
        os.makedirs(os.path.join(str(tmp_path), "out"), exist_ok=True)
        (tmp_path / "a-1.tar.gz").write_bytes(b"a")
        release.checksum_and_sign()
        first = json.loads((tmp_path / "release_public_key.json").read_text(encoding="utf-8"))
        release.checksum_and_sign()
        second = json.loads((tmp_path / "release_public_key.json").read_text(encoding="utf-8"))
        assert first["public_hex"] == second["public_hex"]
        assert (tmp_path / "out" / "release_key.pem").exists()


class TestPypiUploadGuards:
    def test_requires_token(self, tmp_path, monkeypatch):
        monkeypatch.setattr(release, "DIST", str(tmp_path))
        (tmp_path / "a-1.tar.gz").write_bytes(b"a")
        monkeypatch.setenv("CANARI_PYPI_TOKEN_FILE", str(tmp_path / "nope.txt"))
        monkeypatch.delenv("CANARI_PYPI_TOKEN", raising=False)
        with pytest.raises(SystemExit, match="no PyPI token"):
            release.pypi_upload()

    def test_requires_distributions(self, tmp_path, monkeypatch):
        monkeypatch.setattr(release, "DIST", str(tmp_path))
        tf = tmp_path / "tok.txt"
        tf.write_text("pypi-AAAABBBB\n", encoding="utf-8")
        monkeypatch.setenv("CANARI_PYPI_TOKEN_FILE", str(tf))
        with pytest.raises(SystemExit, match="no distributions"):
            release.pypi_upload()

    def test_token_read_from_file_line(self, tmp_path, monkeypatch):
        monkeypatch.setattr(release, "DIST", str(tmp_path))
        (tmp_path / "w-1-py3-none-any.whl").write_bytes(b"w")
        tf = tmp_path / "tok.txt"
        tf.write_text("PyPI API token (scope=Entire account):\npypi-REALTOKEN\n", encoding="utf-8")
        monkeypatch.setenv("CANARI_PYPI_TOKEN_FILE", str(tf))
        captured = {}

        def fake_call(cmd, cwd=None, env=None):
            captured["env"] = env
            captured["cmd"] = cmd
            return 0
        monkeypatch.setattr(release.subprocess, "call", fake_call)
        release.pypi_upload()
        assert captured["env"]["TWINE_PASSWORD"] == "pypi-REALTOKEN"
        assert captured["env"]["PYTHONIOENCODING"] == "utf-8"  # GBK crash guard
        assert "--disable-progress-bar" in captured["cmd"]
        assert "--skip-existing" in captured["cmd"]

    def test_upload_failure_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(release, "DIST", str(tmp_path))
        (tmp_path / "w-1-py3-none-any.whl").write_bytes(b"w")
        tf = tmp_path / "tok.txt"
        tf.write_text("pypi-X\n", encoding="utf-8")
        monkeypatch.setenv("CANARI_PYPI_TOKEN_FILE", str(tf))
        monkeypatch.setattr(release.subprocess, "call", lambda *a, **k: 1)
        with pytest.raises(SystemExit, match="twine upload failed"):
            release.pypi_upload()


class TestRetryHelper:
    def test_retries_then_succeeds(self):
        calls = {"n": 0}
        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise OSError("boom")
            return "ok"
        assert release._retry(flaky, attempts=3, delay=0) == "ok"
        assert calls["n"] == 3

    def test_raises_after_exhausting(self):
        def always():
            raise OSError("nope")
        with pytest.raises(OSError):
            release._retry(always, attempts=2, delay=0)
