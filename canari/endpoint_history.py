# -*- coding: utf-8 -*-
"""endpoint_history.py - turn repeated observations into a decay verdict.

A single probe answers "what did this endpoint do at that moment". It does not
answer "is this entry dead". Treating one failed probe as a death certificate is
the exact error the measurement-capsule draft calls out, and it is also the
error the registry's own endpoint census warned about: of 52 hosts that failed
at least once in a 10-day window, 27 (51.9%) answered again at some point
(registry#1692).

So a verdict here needs three things a single probe cannot supply:

  1. **repetition** - at least `min_observations` consecutive confirmations;
  2. **spacing** - those confirmations must be separated by at least
     `min_gap`, so k probes fired in the same second are one observation;
  3. **dying forward** - a success resets the streak, because a service that
     recovered has not decayed.

Two verdicts are deliberately kept apart, because they are different claims:

  * `INCONSISTENT_CONFIRMED` - the endpoint answered, and the answers were not
    MCP. That is evidence about the *declaration*.
  * `UNAVAILABLE_CONFIRMED` - the endpoint did not answer at all. That is
    evidence about *availability*, not about whether the declaration is
    correct, and it must never be reported as "declared transport is wrong".

Everything else is a provisional state, and saying so is the point.
"""
import json
import os

# Observation outcomes, as produced by mcp_probe.probe_endpoint().
#
#   answered, not MCP          -> counts toward an inconsistency streak
#   answered, but we were refused / it errored -> no evidence either way
#   did not answer             -> counts toward an unavailability streak
#   answered correctly         -> resets every streak
ANSWERED_NOT_MCP = "not_mcp"
DID_NOT_ANSWER = ("unreachable",)
CHECKABLE_ANSWER = "alive"

# Everything that is neither a success nor counted failure. These are recorded
# and reported, but they must not accumulate into a verdict: "we could not look"
# is not "it is broken".
NEUTRAL_OUTCOMES = (
    "auth",                 # 401/403/402: the server is up, we are not allowed
    "http_error",           # 5xx and friends: says nothing about the declaration
    "unsupported_version",  # it answered; we asked for the wrong protocol
    "partial",              # answered, but the exchange did not complete
)

VERDICT_CONSISTENT = "CONSISTENT"
VERDICT_INCONSISTENT = "INCONSISTENT_CONFIRMED"
VERDICT_UNAVAILABLE = "UNAVAILABLE_CONFIRMED"
VERDICT_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
VERDICT_FLAPPING = "FLAPPING"
VERDICT_NEUTRAL_ONLY = "NEUTRAL_ONLY"

# Defaults chosen so that two runs of the weekly job cannot confirm anything on
# their own, and a single bad deploy window still cannot manufacture a verdict.
DEFAULT_MIN_OBSERVATIONS = 2
DEFAULT_MIN_GAP_SECONDS = 6 * 3600


def _ts(observation):
    """Seconds since epoch for an observation, tolerating ISO-8601 'Z' input."""
    raw = observation.get("observed_at")
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    text = str(raw).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    from datetime import datetime
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def classify_streak(observations, min_observations=DEFAULT_MIN_OBSERVATIONS,
                    min_gap_seconds=DEFAULT_MIN_GAP_SECONDS):
    """Reduce an endpoint's observations to one verdict.

    `observations` is a chronological list of dicts with at least
    `outcome` and `observed_at`. Returns a dict describing the verdict and
    the evidence for it, including why it is only provisional when it is.
    """
    if not observations:
        return {
            "verdict": VERDICT_INSUFFICIENT,
            "reason": "no observations",
            "observations": 0,
            "counted": 0,
            "span_seconds": 0,
        }

    ordered = sorted(observations, key=lambda o: (_ts(o) is None, _ts(o) or 0))
    outcomes = [o.get("outcome") for o in ordered]

    # The most recent observation is what the state is anchored to: a service
    # that was down for a week and came back is CONSISTENT today, not stale-bad.
    latest = outcomes[-1]

    if latest == CHECKABLE_ANSWER:
        # Walk back over the leading run of successes; anything before the last
        # failure is history, not current state.
        return {
            "verdict": VERDICT_CONSISTENT,
            "reason": "the most recent observation completed an MCP initialize",
            "observations": len(ordered),
            "counted": 1,
            "span_seconds": 0,
        }

    if latest not in (ANSWERED_NOT_MCP,) + DID_NOT_ANSWER:
        return {
            "verdict": VERDICT_NEUTRAL_ONLY,
            "reason": "the most recent observation was %r, which is neither a "
                      "success nor evidence of decay" % (latest,),
            "observations": len(ordered),
            "counted": 0,
            "span_seconds": 0,
        }

    # Which failure class are we testing for?
    want_inconsistent = latest == ANSWERED_NOT_MCP
    same_class = (ANSWERED_NOT_MCP,) if want_inconsistent else DID_NOT_ANSWER

    # Collect the trailing run of the same failure class, ignoring neutral
    # outcomes in between (an auth error between two not-MCP answers does not
    # make the two not-MCP answers one observation).
    run = []
    for obs in reversed(ordered):
        outcome = obs.get("outcome")
        if outcome in same_class:
            run.append(obs)
        elif outcome in NEUTRAL_OUTCOMES:
            # Neither evidence for nor against: skip it without ending the run.
            continue
        else:
            # Anything else ends the run. That includes a success (the endpoint
            # recovered, so nothing before it is current) and a failure of the
            # *other* class (not_mcp vs. unreachable are different claims).
            break
    run.reverse()

    # Spacing: keep only observations that are at least min_gap after the last
    # one kept. This is what stops "five probes in one minute" from counting as
    # five independent confirmations.
    kept = []
    for obs in run:
        when = _ts(obs)
        if when is None:
            continue
        if not kept or when - _ts(kept[-1]) >= min_gap_seconds:
            kept.append(obs)

    span = 0
    if len(kept) >= 2:
        span = int(_ts(kept[-1]) - _ts(kept[0]))

    if len(kept) >= min_observations:
        if want_inconsistent:
            return {
                "verdict": VERDICT_INCONSISTENT,
                "reason": "%d observations separated by at least %ds each saw a "
                          "non-MCP answer" % (len(kept), min_gap_seconds),
                "observations": len(ordered),
                "counted": len(kept),
                "span_seconds": span,
            }
        return {
            "verdict": VERDICT_UNAVAILABLE,
            "reason": "%d observations separated by at least %ds each got no "
                      "answer at all; this is an availability finding, not a "
                      "wrong-declaration finding" % (len(kept), min_gap_seconds),
            "observations": len(ordered),
            "counted": len(kept),
            "span_seconds": span,
        }

    # Fewer spaced confirmations than required. If the window also contains the
    # opposite outcome, the honest word for that is flapping.
    recent_window = [o for o in ordered if _ts(o) is not None]
    saw_success = any(o.get("outcome") == CHECKABLE_ANSWER for o in recent_window)
    if saw_success and run:
        return {
            "verdict": VERDICT_FLAPPING,
            "reason": "the endpoint both succeeded and failed within the record; "
                      "%d spaced confirmation(s) of the current failure, %d "
                      "required" % (len(kept), min_observations),
            "observations": len(ordered),
            "counted": len(kept),
            "span_seconds": span,
        }

    return {
        "verdict": VERDICT_INSUFFICIENT,
        "reason": "%d spaced confirmation(s) of the current failure, %d required"
                  % (len(kept), min_observations),
        "observations": len(ordered),
        "counted": len(kept),
        "span_seconds": span,
    }


class EndpointHistory:
    """Append-only, append-safe observation log keyed by endpoint URL.

    Stored as one JSON document next to the ledger so it travels with the rest
    of the state. Writes go through a temp file + os.replace, the same pattern
    StateStore uses, so a killed run cannot leave a truncated history.
    """

    def __init__(self, path):
        self.path = path
        self._data = self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    doc = json.load(f)
                if isinstance(doc, dict) and isinstance(doc.get("endpoints"), dict):
                    return doc
            except Exception:
                pass
        return {"schema": "canari.endpoint-history/1", "endpoints": {}, "scan_offset": 0}

    def record(self, url, probe):
        """Record one probe result for `url`. Returns the stored observation."""
        observation = {
            "observed_at": probe.get("checked_at"),
            "outcome": probe.get("outcome"),
            "http_status": probe.get("http_status"),
            "error": (probe.get("error") or None),
        }
        self._data.setdefault("endpoints", {}).setdefault(url, []).append(observation)
        return observation

    def scan_offset(self):
        """Where the rotating coverage cursor left off (0 for a fresh history)."""
        return int(self._data.get("scan_offset", 0) or 0)

    def set_scan_offset(self, value):
        self._data["scan_offset"] = int(value)

    def observations(self, url):
        return list(self._data.get("endpoints", {}).get(url, []))

    def verdict(self, url, **kwargs):
        return classify_streak(self.observations(url), **kwargs)

    def all_verdicts(self, **kwargs):
        return {url: classify_streak(obs, **kwargs)
                for url, obs in self._data.get("endpoints", {}).items()}

    def save(self):
        tmp = self.path + ".tmp"
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)



def degrade_capsule_state(capsule, verdict):
    """Attach the streak verdict to a single-probe capsule, without upgrading it.

    A capsule describes what one probe saw. A verdict describes what repeated
    probes imply. They are different claims and must not be silently merged:

      * a capsule that is already UNCHECKABLE never becomes a finding, no matter
        what the streak says, because the single observation it carries could not
        check the declaration;
      * a single CONSISTENT observation is not downgraded by stale history: the
        capsule is a statement about *that* moment;
      * the verdict is added as an explicit, separate member so a reader can see
        both the evidence and the inference, and is never allowed to look like
        the capsule's own measurement_state.

    Returns a new dict; the input is not modified, because capsule_id covers the
    exact document it was computed over.
    """
    allowed = (VERDICT_CONSISTENT, VERDICT_INCONSISTENT, VERDICT_UNAVAILABLE,
               VERDICT_INSUFFICIENT, VERDICT_FLAPPING, VERDICT_NEUTRAL_ONLY)
    if verdict.get("verdict") not in allowed:
        raise ValueError("unknown verdict %r" % (verdict.get("verdict"),))

    doc = dict(capsule)
    doc["observation_history"] = {
        "observations": verdict.get("observations", 0),
        "confirmations": verdict.get("counted", 0),
        "span_seconds": verdict.get("span_seconds", 0),
        "verdict": verdict["verdict"],
        "verdict_basis": verdict.get("reason"),
        "note": ("a verdict summarises repeated observations; it is not the "
                 "measurement_state of this capsule and does not override it"),
    }
    return doc
