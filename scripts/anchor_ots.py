# -*- coding: utf-8 -*-
"""anchor_ots.py - anchor a published tree head to Bitcoin via OpenTimestamps.

Why: the log proves internal consistency, and GitHub proves who ran it, but both
are under our control. OpenTimestamps gives an independent "this byte string
existed before block N" claim that nobody in this project can forge, and it is
free. That is the one part of the trust story that does not depend on our
reputation.

Honesty about stages (do not blur these):
  1. SUBMIT   - a calendar accepts the SHA-256 of the head and returns a
                *pending* attestation. This proves nothing yet.
  2. UPGRADE  - the calendar aggregates its pending commitments into a Bitcoin
                transaction; the proof then carries a BitcoinBlockHeader
                attestation and is verifiable offline forever.
  3. VERIFY   - check the Bitcoin block header header hash is in the real chain
                (needs a header source; block height alone is not proof).

This script does 1 and 2. It never claims stage 2 succeeded unless the
attestation type says so.

Usage:
    python scripts/anchor_ots.py submit docs/log/head-latest.json
    python scripts/anchor_ots.py upgrade docs/log/head-latest.json
    python scripts/anchor_ots.py status docs/log/head-latest.json
"""
import argparse
import hashlib
import json
import os
import sys

CALENDARS = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
]


def _load(proof_path, digest):
    from opentimestamps.core.serialize import BytesDeserializationContext
    from opentimestamps.core.timestamp import Timestamp
    raw = open(proof_path, "rb").read()
    return Timestamp.deserialize(BytesDeserializationContext(raw), digest)


def _save(ts, proof_path):
    from opentimestamps.core.serialize import BytesSerializationContext
    ctx = BytesSerializationContext()
    ts.serialize(ctx)
    blob = ctx.getbytes()
    tmp = proof_path + ".tmp"
    open(tmp, "wb").write(blob)
    os.replace(tmp, proof_path)
    return len(blob)


def digest_of(path):
    return hashlib.sha256(open(path, "rb").read()).digest()


def check_mutable_target(path):
    """Refuse to timestamp a file whose bytes are expected to change.

    A timestamp commits to a byte string; once the file is rewritten the proof
    can never match it again, and the damage is silent (the .ots file still
    looks valid). head-latest.json is a mutable pointer and must never be a
    target; heads/<size>-<root>.json is content-addressed and write-once.
    """
    base = os.path.basename(path)
    if base in ("head-latest.json", "log.jsonl", "heads.jsonl", "index.html"):
        return ("refusing to timestamp mutable file %r: the proof would break "
                "the next time it is rewritten" % base)
    if os.path.exists(path + ".ots") and base.startswith("head-"):
        return "refusing: %s looks like a mutable pointer" % base
    return ""


def cmd_submit(a):
    from opentimestamps.calendar import RemoteCalendar
    from opentimestamps.core.timestamp import Timestamp
    bad = check_mutable_target(a.target)
    if bad:
        print(bad, file=sys.stderr)
        return 3
    digest = digest_of(a.target)
    ts = Timestamp(digest)
    ok = 0
    for url in CALENDARS:
        try:
            remote = RemoteCalendar(url).submit(digest, timeout=a.timeout)
            ts.merge(remote)
            ok += 1
            print("accepted by %s" % url)
        except Exception as e:
            print("calendar failed %s: %s: %s" % (url, type(e).__name__, e))
    if not ok:
        print("no calendar accepted the commitment", file=sys.stderr)
        return 3
    proof = a.target + ".ots"
    n = _save(ts, proof)
    print("wrote %s (%d bytes, %d calendar(s))" % (proof, n, ok))
    return 0


def cmd_upgrade(a):
    """Ask each calendar for the proof of the commitment it actually holds.

    The subtlety that broke the first version: a pending attestation does not
    hang off the file digest. It hangs off a *derived* commitment (the calendar
    applies an op, e.g. some nonce, before accepting, so the message in the
    proof tree differs from SHA-256(file)). Querying the calendar with the file
    digest therefore returned CommitmentNotFoundError for every calendar while
    the proof was perfectly healthy. We must ask each calendar about the exact
    commitment recorded in the attestation, at the URI recorded with it.
    """
    from opentimestamps.calendar import RemoteCalendar
    digest = digest_of(a.target)
    proof = a.target + ".ots"
    if not os.path.exists(proof):
        print("no proof at %s; run submit first" % proof, file=sys.stderr)
        return 3
    ts = _load(proof, digest)
    before = _stage(ts)

    targets = []
    for msg, att in ts.all_attestations():
        if type(att).__name__ == "PendingAttestation":
            uri = getattr(att, "uri", None)
            if uri:
                targets.append((uri, msg))
    if not targets:
        print(json.dumps({"stage_before": before, "stage_after": before,
                          "note": "no pending attestations to upgrade"},
                         ensure_ascii=False, indent=1))
        return 0 if before == "bitcoin" else 1

    errors = []
    upgraded = 0
    for uri, commitment in targets:
        try:
            remote_ts = RemoteCalendar(uri).get_timestamp(commitment, timeout=a.timeout)
            ts.merge(remote_ts)
            upgraded += 1
        except Exception as e:
            errors.append("%s: %s" % (uri, type(e).__name__))
    n = _save(ts, proof)
    after = _stage(ts)
    print(json.dumps({"stage_before": before, "stage_after": after,
                      "proof_bytes": n, "queried": len(targets),
                      "upgraded": upgraded, "errors": errors},
                     ensure_ascii=False, indent=1))
    return 0 if after == "bitcoin" else 1


def _stage(ts):
    """'bitcoin' | 'pending' | 'unknown' - what the proof actually proves now."""
    try:
        from opentimestamps.core.timestamp import BitcoinBlockHeaderAttestation
    except Exception:                                  # pragma: no cover
        BitcoinBlockHeaderAttestation = None
    has_pending = False
    for _msg, att in ts.all_attestations():
        if BitcoinBlockHeaderAttestation is not None and isinstance(
                att, BitcoinBlockHeaderAttestation):
            return "bitcoin"
        if type(att).__name__ == "PendingAttestation":
            has_pending = True
    return "pending" if has_pending else "unknown"


def cmd_status(a):
    digest = digest_of(a.target)
    proof = a.target + ".ots"
    if not os.path.exists(proof):
        print(json.dumps({"proof": False}, ensure_ascii=False))
        return 3
    ts = _load(proof, digest)
    stage = _stage(ts)
    atts = [type(att).__name__ for _m, att in ts.all_attestations()]
    print(json.dumps({"proof": True, "stage": stage, "attestations": atts,
                      "sha256": digest.hex()}, ensure_ascii=False, indent=1))
    return 0 if stage == "bitcoin" else 1


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["submit", "upgrade", "status"])
    ap.add_argument("target")
    ap.add_argument("--timeout", type=int, default=30)
    a = ap.parse_args(argv)
    return {"submit": cmd_submit, "upgrade": cmd_upgrade,
            "status": cmd_status}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
