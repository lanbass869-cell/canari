# -*- coding: utf-8 -*-
"""Guardrails for the in-browser verifier.

The page is a single file with no build step, so nothing at runtime will notice
if someone later adds a CDN script or an analytics tag. For a verifier whose
entire claim is "nothing is uploaded and no network request is made", a single
external <script> would silently falsify that claim. These tests fail closed on
that, and pin the pieces that must not drift from the other two verifiers.
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "docs", "verify", "index.html")


@pytest.fixture(scope="module")
def html():
    with open(PAGE, encoding="utf-8") as f:
        return f.read()


class TestSelfContained:
    def test_no_external_scripts_or_styles(self, html):
        for m in re.finditer(r"<script[^>]*\ssrc=[\"']([^\"']+)[\"']", html):
            pytest.fail("external script would break the offline claim: %s" % m.group(1))
        for m in re.finditer(r"<link[^>]*\shref=[\"']([^\"']+)[\"']", html):
            pytest.fail("external stylesheet would break the offline claim: %s" % m.group(1))

    def test_no_analytics_or_remote_urls(self, html):
        # the only permitted URL is the same-origin published bundle
        remote = [
            u for u in re.findall(r"https?://[^\s\"'<>)]+", html)
            if "github.com/lanbass869-cell/canari" not in u
        ]
        assert remote == [], "page references remote URLs: %s" % remote

    def test_no_upload_path(self, html):
        for bad in ("XMLHttpRequest", "navigator.sendBeacon", "new WebSocket",
                    "method: \"POST\"", "method: 'POST'"):
            assert bad not in html, "page contains an upload path: %s" % bad


class TestAlgorithmParity:
    """The page must implement the same constants as the Python and Node
    verifiers. If one drifts, a bundle would verify in one place and not the
    other -- which is precisely the failure mode a second implementation is
    supposed to catch."""

    def test_domain_separation_constants(self, html):
        assert 'canari-tree-head/v1\\u0000' in html
        assert "new Uint8Array([0x00])" in html     # LEAF prefix
        assert "new Uint8Array([0x01])" in html     # NODE prefix

    def test_spec_strings(self, html):
        assert 'canari-append-only-log/v1' in html
        assert 'canari-inclusion-bundle/v1' in html

    def test_c2sp_constants(self, html):
        assert 'const EM_DASH = "\\u2014"' in html
        assert "const LOG_KEY_TYPE = 0x01" in html

    def test_uses_webcrypto_ed25519(self, html):
        assert 'crypto.subtle.importKey("raw", pub, { name: "Ed25519" }' in html
        assert 'crypto.subtle.verify(' in html

    def test_supports_pinned_prefix(self, html):
        assert "pinnedPrefix" in html
        assert "prefix.pinned" in html
        assert "prefix.chain" in html

    def test_fails_closed_on_malformed_input(self, html):
        assert "not a JSON object" in html
        assert "no consistency block" in html


class TestPublishedPageDiscoverable:
    def test_log_page_links_the_verifier(self):
        with open(os.path.join(ROOT, "docs", "log", "index.html"), encoding="utf-8") as f:
            page = f.read()
        assert "../verify/" in page or "../verify/index.html" in page, (
            "the published log page should link to the in-browser verifier")
