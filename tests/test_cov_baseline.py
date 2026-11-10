# -*- coding: utf-8 -*-
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_now_format():
    from canari.baseline import _now
    import re
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", _now())


def test_expiry_is_seven_days_after_now():
    from canari.baseline import _now, _expiry
    import datetime as dt
    def p(s): return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    delta = p(_expiry()) - p(_now())
    assert abs(delta.total_seconds() - 7 * 86400) < 120


def test_sha512_integrity_roundtrip():
    """The helper returns the hex of the DECODED bytes, not a re-hash of them.

    npm's integrity field already contains the digest, so decoding is the whole
    job. Asserting hashlib.sha512(raw) here would test a hash the function never
    computes.
    """
    from canari.baseline import _sha512_integrity_to_hex
    import base64
    raw = bytes(range(64))
    integ = "sha512-" + base64.b64encode(raw).decode()
    assert _sha512_integrity_to_hex(integ) == raw.hex()


def test_sha512_integrity_rejects_bad_input():
    from canari.baseline import _sha512_integrity_to_hex
    assert _sha512_integrity_to_hex(None) is None
    assert _sha512_integrity_to_hex("") is None
    assert _sha512_integrity_to_hex("sha1-abc") is None
    assert _sha512_integrity_to_hex("sha512-not-base64!!") is None
    import base64
    short = "sha512-" + base64.b64encode(b"1234").decode()   # decodes but wrong length
    assert _sha512_integrity_to_hex(short) is None


def test_runner_source_digest_is_stable_sha256():
    from canari.baseline import _runner_source_digest
    a, b = _runner_source_digest(), _runner_source_digest()
    assert a == b
    assert len(a) == 64
    int(a, 16)


def test_with_timeout_returns_value():
    from canari.baseline import _with_timeout
    assert _with_timeout(lambda: 42, 5) == 42


def test_with_timeout_uses_default_on_hang():
    from canari.baseline import _with_timeout
    import time as _t
    r = _with_timeout(lambda: (_t.sleep(5), 1)[1], 0.2, default="TIMEOUT")
    assert r == "TIMEOUT"


def test_with_timeout_swallows_exception_into_default():
    """By design _with_timeout never raises: a failing probe degrades to default
    so one bad call cannot abort the whole scan."""
    from canari.baseline import _with_timeout
    def boom():
        raise ValueError("x")
    assert _with_timeout(boom, 5, default="DEGRADED") == "DEGRADED"
    assert _with_timeout(boom, 5) is None
