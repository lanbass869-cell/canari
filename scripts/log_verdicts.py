# -*- coding: utf-8 -*-
"""log_verdicts.py - commit our own published verdicts into the append-only log.

Why this matters more than logging someone else's data: Canari's entire product
claim is "you can check what we said, and check that we did not quietly change
it". Publishing signed bundles is not enough -- a bundle can be re-issued with a
different verdict under a fresh signature and nothing on disk would show it.
Putting a commitment to each bundle into the append-only log makes the sequence
of our own judgements auditable by a stranger.

One log entry per bundle file: subject identity, verdict, the DSSE payload
digest, and the bundle file's sha256. The payload digest is what the signature
already covers; the file sha256 covers the wrapper too.

Re-running is idempotent: a bundle whose file sha256 is already the newest
commitment for that component is skipped.
"""
import argparse
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from canari.logstore import open_log  # noqa: E402
from canari.signing import payload_digest  # noqa: E402

LOG_ID = "canari-snapshot-log"


def bundle_commitment(path):
    raw = open(path, "rb").read()
    bundle = json.loads(raw.decode("utf-8"))
    payload = bundle.get("payload") or {}
    subject = payload.get("subject") or {}
    name = subject.get("name", "")
    version = subject.get("version", "") or ""
    registry = subject.get("registry", "") or ""
    ref = "%s:%s@%s" % (registry, name, version) if version else "%s:%s" % (registry, name)
    return {
        "kind": "verdict",
        "component": ref,
        "name": name,
        "version": version,
        "registry": registry,
        "artifact_sha256": (subject.get("artifact_sha256") or "").lower(),
        "verdict": payload.get("verdict", ""),
        "generated_at": payload.get("generated_at", ""),
        "expires_at": payload.get("expires_at", ""),
        "payload_digest": payload_digest(payload),
        "bundle_file": os.path.basename(path),
        "bundle_sha256": hashlib.sha256(raw).hexdigest(),
        "bundle_bytes": len(raw),
    }


def iter_bundles(root):
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in sorted(filenames):
            if fn.endswith(".bundle.json"):
                yield os.path.join(dirpath, fn)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", default=os.path.join(ROOT, "docs", "log"))
    ap.add_argument("--records-dir", default=os.path.join(ROOT, "docs", "scan", "records"))
    ap.add_argument("--out", default=None)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    L = open_log(a.log_dir, log_id=LOG_ID)
    audit = L.audit()
    if not audit["ok"]:
        print("AUDIT FAILED before append: %s" % "; ".join(audit["errors"]), file=sys.stderr)
        return 2

    seen = {}
    for e in L.entry_objs():
        p = e.get("payload") or {}
        if p.get("kind") == "verdict" and p.get("component"):
            seen[p["component"]] = p.get("bundle_sha256")

    paths = list(iter_bundles(a.records_dir))
    if not paths:
        print("no bundles under %s" % a.records_dir, file=sys.stderr)
        return 3

    to_add = []
    for path in paths:
        try:
            rec = bundle_commitment(path)
        except Exception as e:
            print("skip unreadable %s: %s" % (path, e), file=sys.stderr)
            continue
        if seen.get(rec["component"]) == rec["bundle_sha256"]:
            continue
        to_add.append((rec, path))

    print("bundles=%d new=%d skipped_unchanged=%d"
          % (len(paths), len(to_add), len(paths) - len(to_add)))
    if a.dry_run:
        for rec, _ in to_add:
            print("  would add %s %s %s" % (rec["component"], rec["verdict"],
                                            rec["bundle_sha256"][:16]))
        return 0
    for rec, _path in to_add:
        L.append(rec, kind="verdict")
    head = L.seal()
    if head is None:
        head = L.last_head()
    out = {"log_dir": L.dir, "added": len(to_add), "size": L.size(),
           "head": head, "audit": L.audit()}
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.write("\n")
    print(json.dumps({"added": out["added"], "size": out["size"],
                      "root": head["body"]["root"], "ok": out["audit"]["ok"]},
                     ensure_ascii=False, indent=1))
    return 0 if out["audit"]["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
