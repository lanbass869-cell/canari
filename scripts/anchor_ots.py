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


def cmd_submit(a):
    from opentimestamps.calendar import RemoteCalendar
    from opentimestamps.core.timestamp import Timestamp
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
    from opentimestamps.calendar import RemoteCalendar
    digest = digest_of(a.target)
    proof = a.target + ".ots"
    if not os.path.exists(proof):
        print("no proof at %s; run submit first" % proof, file=sys.stderr)
        return 3
    ts = _load(proof, digest)
    before = _stage(ts)
    errors = []
    for url in CALENDARS:
        try:
            remote_ts = RemoteCalendar(url).get_timestamp(digest, timeout=a.timeout)
            ts.merge(remote_ts)
        except Exception as e:
            errors.append("%s: %s" % (url, type(e).__name__))
    n = _save(ts, proof)
    after = _stage(ts)
    print(json.dumps({"stage_before": before, "stage_after": after,
                      "proof_bytes": n, "errors": errors},
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
