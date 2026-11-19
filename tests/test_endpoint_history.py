# -*- coding: utf-8 -*-
"""The hard part of endpoint monitoring is not detecting a failure, it is
deciding when a failure is real.

A single probe is one sample. Turning it into "this entry is dead" is exactly the
mistake the measurement-capsule draft forbids, and it is the mistake a public
endpoint census already made and corrected in public: 27 of the 52 hosts that
failed at least once answered again later (registry#1692). These tests pin the
rules that keep that from happening here.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canari.endpoint_history import (  # noqa: E402
    DEFAULT_MIN_GAP_SECONDS,
    VERDICT_CONSISTENT,
    VERDICT_FLAPPING,
    VERDICT_INCONSISTENT,
    VERDICT_INSUFFICIENT,
    VERDICT_NEUTRAL_ONLY,
    VERDICT_UNAVAILABLE,
    EndpointHistory,
    classify_streak,
)


def obs(outcome, hour):
    """An observation at a known, well-spaced moment (2026-01-01 00:00 UTC)."""
    return {"outcome": outcome,
            "observed_at": "2026-01-01T%02d:00:00Z" % hour}


def test_single_failure_is_not_a_verdict():
    """One failed probe is a sample, not a death certificate."""
    got = classify_streak([obs("not_mcp", 1)])
    assert got["verdict"] == VERDICT_INSUFFICIENT
    # It is counted (we did observe one failure) but one confirmation is not a
    # verdict. Counting and confirming are different things on purpose.
    assert got["counted"] == 1
    assert got["counted"] < 2


def test_two_failures_in_the_same_window_are_one_observation():
    """Five probes a minute apart must not count as five confirmations."""
    same_minute = [
        {"outcome": "not_mcp", "observed_at": "2026-01-01T00:00:00Z"},
        {"outcome": "not_mcp", "observed_at": "2026-01-01T00:00:30Z"},
        {"outcome": "not_mcp", "observed_at": "2026-01-01T00:01:00Z"},
        {"outcome": "not_mcp", "observed_at": "2026-01-01T00:01:30Z"},
    ]
    got = classify_streak(same_minute)
    assert got["verdict"] == VERDICT_INSUFFICIENT, (
        "burst probes must not confirm anything: %r" % (got,))


def test_two_spaced_non_mcp_answers_confirm_a_wrong_declaration():
    got = classify_streak([obs("not_mcp", 1), obs("not_mcp", 12)])
    assert got["verdict"] == VERDICT_INCONSISTENT
    assert got["counted"] == 2
    assert got["span_seconds"] == 11 * 3600


def test_unreachable_is_availability_not_a_wrong_declaration():
    """The two failure classes must not be merged: one says the entry lies about
    its transport, the other says the host is down right now."""
    got = classify_streak([obs("unreachable", 1), obs("unreachable", 14)])
    assert got["verdict"] == VERDICT_UNAVAILABLE
    assert got["verdict"] != VERDICT_INCONSISTENT


def test_mixed_failure_classes_do_not_add_up():
    """not_mcp then unreachable is not two confirmations of either."""
    got = classify_streak([obs("not_mcp", 1), obs("unreachable", 14)])
    assert got["verdict"] != VERDICT_INCONSISTENT
    assert got["verdict"] != VERDICT_UNAVAILABLE
    assert got["verdict"] == VERDICT_INSUFFICIENT


def test_a_recovery_resets_the_streak():
    """Down, down, up: the current state is up."""
    got = classify_streak([obs("not_mcp", 1), obs("not_mcp", 8), obs("alive", 20)])
    assert got["verdict"] == VERDICT_CONSISTENT


def test_auth_refusals_carry_no_evidence_and_do_not_break_a_streak():
    """401 means the server is up and we are not allowed in. It is not a
    confirmation and it is not a refutation."""
    only_auth = classify_streak([obs("auth", 1), obs("auth", 12)])
    assert only_auth["verdict"] == VERDICT_NEUTRAL_ONLY
    assert only_auth["counted"] == 0

    around_auth = classify_streak(
        [obs("not_mcp", 1), obs("auth", 6), obs("not_mcp", 12)])
    assert around_auth["verdict"] == VERDICT_INCONSISTENT
    assert around_auth["counted"] == 2


def test_flapping_is_named_rather_than_rounded_to_broken():
    got = classify_streak([obs("not_mcp", 1), obs("alive", 6), obs("not_mcp", 12)])
    assert got["verdict"] == VERDICT_FLAPPING


def test_server_errors_are_not_evidence():
    got = classify_streak([obs("http_error", 1), obs("http_error", 12)])
    assert got["verdict"] == VERDICT_NEUTRAL_ONLY


def test_no_observations():
    got = classify_streak([])
    assert got["verdict"] == VERDICT_INSUFFICIENT
    assert got["observations"] == 0


def test_thresholds_are_parameters_not_constants():
    """A caller that wants three confirmations gets three."""
    two = [obs("not_mcp", 1), obs("not_mcp", 12)]
    assert classify_streak(two)["verdict"] == VERDICT_INCONSISTENT
    assert classify_streak(two, min_observations=3)["verdict"] == VERDICT_INSUFFICIENT


def test_observations_may_arrive_out_of_order():
    got = classify_streak([obs("not_mcp", 12), obs("not_mcp", 1)])
    assert got["verdict"] == VERDICT_INCONSISTENT
    assert got["counted"] == 2


def test_history_round_trips_and_survives_a_partial_file(tmp_path):
    path = str(tmp_path / "endpoint_history.json")
    h = EndpointHistory(path)
    h.record("https://a.example/mcp", {"checked_at": "2026-01-01T00:00:00Z",
                                       "outcome": "alive", "http_status": 200,
                                       "error": None})
    h.save()

    h2 = EndpointHistory(path)
    assert len(h2.observations("https://a.example/mcp")) == 1
    assert h2.verdict("https://a.example/mcp")["verdict"] == VERDICT_CONSISTENT

    with open(path, "w", encoding="utf-8") as f:
        f.write("{ truncated")
    h3 = EndpointHistory(path)
    assert h3.observations("https://a.example/mcp") == []


def test_record_stores_the_fields_a_verdict_needs(tmp_path):
    h = EndpointHistory(str(tmp_path / "h.json"))
    stored = h.record("https://b.example/mcp", {
        "checked_at": "2026-01-01T00:00:00Z", "outcome": "not_mcp",
        "http_status": 200, "error": None})
    assert stored == {"observed_at": "2026-01-01T00:00:00Z",
                      "outcome": "not_mcp", "http_status": 200, "error": None}


def test_default_gap_is_hours_not_seconds():
    """A guard on the constant itself: if someone lowers this to seconds, burst
    probes start confirming failures again."""
    assert DEFAULT_MIN_GAP_SECONDS >= 3600


def test_a_verdict_never_overrides_a_capsule_measurement_state():
    """The capsule says what one probe saw; the verdict says what repetition
    implies. Merging them would let an inference masquerade as an observation."""
    from canari.endpoint_history import degrade_capsule_state

    capsule = {"measurement_state": "CONSISTENT", "capsule_id": "abc",
               "observed": {"outcome": "alive"}}
    got = degrade_capsule_state(capsule, {
        "verdict": VERDICT_UNAVAILABLE, "observations": 5, "counted": 3,
        "span_seconds": 7200, "reason": "three spaced silences"})

    assert got["measurement_state"] == "CONSISTENT", (
        "an inference must not rewrite what was measured")
    assert got["observation_history"]["verdict"] == VERDICT_UNAVAILABLE
    assert got["observation_history"]["confirmations"] == 3
    assert "does not override" in got["observation_history"]["note"]
    assert "verdict" not in capsule, "input capsule must not be mutated"


def test_an_uncheckable_capsule_stays_uncheckable():
    from canari.endpoint_history import degrade_capsule_state
    capsule = {"measurement_state": "UNCHECKABLE", "capsule_id": "x"}
    got = degrade_capsule_state(capsule, {"verdict": VERDICT_INCONSISTENT,
                                          "observations": 4, "counted": 2,
                                          "span_seconds": 7200, "reason": "r"})
    assert got["measurement_state"] == "UNCHECKABLE"
