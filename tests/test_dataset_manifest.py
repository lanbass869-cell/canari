# -*- coding: utf-8 -*-
"""The published dataset must match its own MANIFEST.

Found 2026-11-16: dataset/attestation-v0.1.json had been updated (SARIF ingest
fields) after the digest list was generated, so 1 of 5196 digests in
dataset/MANIFEST.json no longer matched the file on disk. Every reader who
followed the README's "verify the whole snapshot with the manifest" got one
failure -- on a project whose whole claim is that its published bytes match its
published digests.

A one-file drift is exactly the kind of thing nobody notices, so it is a test
now. It walks the manifest rather than the directory: a file that exists but is
not listed is a different bug (silently unpublished), and that is checked too.
"""
import hashlib
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DS = os.path.join(ROOT, "dataset")
MANIFEST = os.path.join(DS, "MANIFEST.json")


@pytest.fixture(scope="module")
def manifest():
    with open(MANIFEST, encoding="utf-8") as f:
        return json.load(f)


class TestDatasetManifest:
    def test_every_listed_file_matches_its_digest(self, manifest):
        digests = manifest["sha256"]
        assert digests, "manifest carries no digests"
        bad = []
        for rel, want in digests.items():
            path = os.path.join(DS, rel)
            if not os.path.exists(path):
                bad.append("%s: missing" % rel)
                continue
            with open(path, "rb") as f:
                got = hashlib.sha256(f.read()).hexdigest()
            if got != want:
                bad.append("%s: %s != %s" % (rel, got[:12], want[:12]))
        assert bad == [], "dataset files do not match MANIFEST:\n  " + "\n  ".join(bad[:10])

    def test_every_published_file_is_listed(self, manifest):
        """A file in dataset/ that the manifest omits is unpublished silently."""
        listed = set(manifest["sha256"])
        on_disk = set()
        for root, _dirs, files in os.walk(DS):
            for fn in files:
                if fn == "MANIFEST.json":
                    continue
                rel = os.path.relpath(os.path.join(root, fn), DS).replace("\\", "/")
                on_disk.add(rel)
        unlisted = sorted(on_disk - listed)
        assert unlisted == [], "files present but not in MANIFEST: %s" % unlisted[:10]

    def test_counts_agree_with_disk(self, manifest):
        n = len([f for f in os.listdir(os.path.join(DS, "attestations"))
                 if f.endswith(".bundle.json")])
        assert manifest["attestations"] == n, (
            "manifest says %d attestations, disk has %d" % (manifest["attestations"], n))

    def test_license_is_declared(self, manifest):
        assert manifest.get("license") == "CC-BY-4.0"
