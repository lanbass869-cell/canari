# -*- coding: utf-8 -*-
"""Freshness must fail loudly, not silently.

Two failures found on 2026-11-19:

1. The attestation TTL was 7 days and the scan runs weekly, so the margin was
   zero: one late or failed run and every record expired at once, and the
   default policy (require_fresh=True) turned that into a blanket BLOCK with no
   warning. The TTL is now 14 days -- two cycles -- and a still-valid record
   inside its last two days reports a warning instead of a decision.
2. `_check_freshness` had no notion of "close to the edge", so a stalled
   pipeline was indistinguishable from a healthy one until it broke.
"""
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import canari.baseline as baseline  # noqa: E402
from canari.gate import (  # noqa: E402
    EXPIRING_SOON_DAYS,
    _check_freshness,
)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _payload(days_from_now):
    now = datetime.datetime.now(datetime.timezone.utc)
    return {"expires_at": _iso(now + datetime.timedelta(days=days_from_now))}


def test_ttl_covers_more_than_one_scan_cycle():
    assert baseline.ATTESTATION_TTL_DAYS >= 14, (
        "a weekly scan with a %.0f-day TTL has no margin" % baseline.ATTESTATION_TTL_DAYS)


def test_ttl_is_what_expiry_actually_uses():
    att = baseline._expiry()
    exp = datetime.datetime.strptime(att, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    days = (exp - now).total_seconds() / 86400
    assert abs(days - baseline.ATTESTATION_TTL_DAYS) < 0.05


def test_expired_record_is_not_fresh():
    fresh, reason = _check_freshness(_payload(-1))
    assert fresh is False
    assert "expired" in reason


def test_healthy_record_is_fresh_without_a_warning():
    fresh, reason = _check_freshness(_payload(10))
    assert fresh is True
    assert reason is None


def test_near_expiry_is_fresh_but_warns():
    """Still usable, but the pipeline is visibly behind."""
    fresh, reason = _check_freshness(_payload(1))
    assert fresh is True, "a warning must not block"
    assert reason is not None
    assert "expires in" in reason


def test_missing_expiry_is_not_fresh():
    fresh, reason = _check_freshness({})
    assert fresh is False
    assert "no expires_at" in reason


def test_the_warning_window_is_shorter_than_the_ttl():
    """If the warning window were >= the TTL, every record would warn from
    birth and the warning would carry no signal."""
    assert EXPIRING_SOON_DAYS < baseline.ATTESTATION_TTL_DAYS
