# -*- coding: utf-8 -*-
"""capsule_emit.py - turn a registry entry + a live probe into a measurement capsule.

The comparison kind is `measurement.contract_parity`: the registry declares that
an endpoint speaks streamable HTTP MCP; the probe records what the endpoint
actually does. That is the "declared vs observed" question
draft-templeman-scitt-measurement-capsule-01 asks, and it is the strongest one
we can answer with data we actually hold (the registry publishes no protocol
version per entry, so claiming to compare one would be inventing a field).

The mapping to the draft's three states is the whole point:

    alive            -> CONSISTENT    declaration upheld
    not_mcp          -> INCONSISTENT  declared MCP, answers with something else
    auth             -> UNCHECKABLE   we were refused; that is not a finding
    http_error       -> UNCHECKABLE   a 5xx says nothing about the declaration
    unreachable      -> UNCHECKABLE   DNS/refused/timeout is not evidence of decay
    unsupported_version -> UNCHECKABLE  the server answered; we asked wrong

Collapsing the UNCHECKABLE rows into INCONSISTENT would turn "we could not look"
into "it is broken", which is the failure mode the draft exists to prevent.
"""
import hashlib

from canari import capsule as cap

KIND = "measurement.contract_parity"
CLAIM = ("the transport a registry entry declares for this endpoint equals the "
         "transport the endpoint actually speaks")

OUTCOME_TO_STATE = {
    "alive": "CONSISTENT",
    "not_mcp": "INCONSISTENT",
    "auth": "UNCHECKABLE",
    "http_error": "UNCHECKABLE",
    "unreachable": "UNCHECKABLE",
    "unsupported_version": "UNCHECKABLE",
    "partial": "UNCHECKABLE",
}


def _digest_json(obj) -> str:
    return hashlib.sha256(cap.jcs(obj)).hexdigest()


def build_parity_capsule(entry, probe, limitation=None):
    """`entry` is one registry record (the `server` object plus `_meta`), `probe`
    is the dict returned by mcp_probe.probe_endpoint()."""
    server = entry.get("server") or entry
    remotes = server.get("remotes") or []
    remote = next((r for r in remotes if r.get("url") == probe.get("url")),
                  remotes[0] if remotes else {})
    declared_transport = remote.get("type") or "unspecified"

    state = OUTCOME_TO_STATE.get(probe.get("outcome"), "UNCHECKABLE")
    observed = {"exchange": "initialize", "outcome": probe.get("outcome")}
    if probe.get("protocol_version"):
        observed["protocol_version"] = probe["protocol_version"]
    if probe.get("server_info"):
        observed["server_info"] = probe["server_info"]
    if probe.get("tool_count") is not None:
        observed["tool_count"] = probe["tool_count"]
    if probe.get("error"):
        observed["error"] = probe["error"]

    if state == "CONSISTENT":
        differential = {"differs": None,
                        "reason": "the endpoint completed an MCP initialize"}
    elif state == "INCONSISTENT":
        differential = {"differs": ["transport"],
                        "reason": "declared %s but the endpoint did not answer MCP"
                                  % declared_transport}
    else:
        differential = {"differs": None,
                        "reason": "not comparable: %s" % (probe.get("outcome") or "unknown")}

    limitations = []
    if limitation:
        limitations.append(limitation)
    limitations.append("one attempt from one location at %s" % probe.get("checked_at"))
    if state == "UNCHECKABLE":
        limitations.append("the endpoint refused or failed; this capsule records "
                           "that the declaration could not be checked, not that "
                           "it is wrong")

    doc = {
        "schema": cap.CAPSULE_SCHEMA,
        "kind": KIND,
        "subject_id": probe.get("url"),
        "claim": {"statement": CLAIM},
        "declared": {
            "surface": "registry",
            "transport": declared_transport,
            "registry_name": server.get("name"),
            "registry_version": server.get("version"),
        },
        "observed": observed,
        "differential": differential,
        "measurement_state": state,
        "observed_at": probe.get("checked_at"),
        "limitations": limitations,
        "authority_state": ("NONE: measurement only; this capsule grants and "
                            "records no execution authority"),
        "correction_pointer": None,
        "effect_reference": None,
        "sources": {
            "registry_entry": _digest_json(entry),
            "initialize_response": probe.get("initialize_response_sha256"),
        },
        # self-disclosure the draft asks for: who measured
        "measured_by": "canari-probe/0.1",
    }
    doc["capsule_id"] = cap.capsule_id(doc)
    return doc


def build_batch(capsules):
    """The batch record for a set of capsules, per the draft's batch shape."""
    ids = sorted(c["capsule_id"] for c in capsules)
    states = {}
    for c in capsules:
        states[c["measurement_state"]] = states.get(c["measurement_state"], 0) + 1
    lines = b"".join((cap.jcs(c) + b"\n") for c in
                     sorted(capsules, key=lambda x: x["capsule_id"]))
    return {
        "schema": cap.BATCH_SCHEMA,
        "kind": KIND,
        "as_of": max((c["observed_at"] for c in capsules), default=None),
        "n_capsules": len(capsules),
        "states": states,
        "merkle": ("RFC 9162 section 2.1.1 Merkle Tree Hash, SHA-256, over the "
                   "capsule_id values as 32-byte strings sorted ascending"),
        "merkle_root": cap.batch_root(ids),
        "capsules_file": {
            "format": "one JCS capsule per line, LF-terminated, sorted by capsule_id",
            "sha256": hashlib.sha256(lines).hexdigest(),
            "bytes": len(lines),
        },
        "inclusion_rule": "every endpoint probed in this run; nothing excluded",
        "excluded": {},
        "authority_state": ("NONE: measurement only; this batch grants and "
                            "records no execution authority"),
    }
