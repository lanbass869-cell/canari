# -*- coding: utf-8 -*-
"""log_correct.py - append a correction for a previously logged entry.

The log is append-only, so a wrong field in an already-published entry MUST NOT
be fixed by editing history. The honest move is to append a `correction` record
that states, in the log itself, which sequence number was wrong and what the
correct value is. A consumer reading the log sees both the original claim and
the correction, and the consistency proofs still hold.

This exists because of a real incident (2026-11-15): entry 21 recorded
`rows: null` for protocolprobe-evidence. The bytes and sha256 were correct (the
download really was that file), but the row count was lost to a parser bug that
decided gzip by URL suffix. The commitment was never wrong; the metadata was.

Usage:
  python scripts/log_correct.py --log-dir docs/log --seq 21 \
      --field rows --value 63318 --reason "gzip detected by URL suffix; parser fixed"
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from canari.logstore import open_log  # noqa: E402

LOG_ID = "canari-snapshot-log"


def _literal(value):
    """Accept int / float / bool / null / raw string from the command line."""
    try:
        return json.loads(value)
    except Exception:
        return value


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", default=os.path.join(ROOT, "docs", "log"))
    ap.add_argument("--seq", type=int, required=True)
    ap.add_argument("--field", required=True)
    ap.add_argument("--value", required=True)
    ap.add_argument("--reason", required=True)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    L = open_log(a.log_dir, log_id=LOG_ID)
    audit = L.audit()
    if not audit["ok"]:
        print("AUDIT FAILED: %s" % "; ".join(audit["errors"]), file=sys.stderr)
        return 2

    entries = L.entry_objs()
    if not (0 <= a.seq < len(entries)):
        print("seq %d out of range (log has %d entries)" % (a.seq, len(entries)),
              file=sys.stderr)
        return 3
    target = entries[a.seq]
    payload = target.get("payload") or {}

    # Resolve the *current* value, not the original one, by replaying earlier
    # corrections. Without this a re-run reports old_value=null, appends a
    # duplicate correction, and the log fills with the same note every time.
    current = payload.get(a.field)
    already_at = None
    for i, e in enumerate(entries):
        p = e.get("payload") or {}
        if (p.get("kind") == "correction" and p.get("corrects_seq") == a.seq
                and p.get("field") == a.field):
            current = p.get("new_value")
            already_at = i
    old = current
    new = _literal(a.value)
    if old == new:
        print("no change: seq %d %s is already %r (correction at seq %s)"
              % (a.seq, a.field, new, already_at))
        return 0

    record = {
        "kind": "correction",
        "corrects_seq": a.seq,
        "corrects_source": payload.get("source", ""),
        "field": a.field,
        "old_value": old,
        "new_value": new,
        "reason": a.reason,
        "covers_sha256": payload.get("sha256", ""),
    }
    print(json.dumps({"would_append": record}, ensure_ascii=False, indent=1))
    if a.dry_run:
        return 0
    idx = L.append(record, kind="correction")["index"]
    head = L.seal()
    if head is None:
        head = L.last_head()
    print(json.dumps({"appended_seq": idx, "size": L.size(),
                      "root": head["body"]["root"],
                      "ok": L.audit()["ok"]}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
