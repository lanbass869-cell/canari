# -*- coding: utf-8 -*-
"""log_cli.py - operate and verify the Canari append-only log from a shell.

  canari-log-init   DIR [--log-id ID]           create key + empty state
  canari-log-append DIR  (--file F | --stdin)   append records (JSON array/obj)
  canari-log-seal   DIR [--timestamp T]         publish a signed tree head
  canari-log-audit  DIR                         check disk vs signed heads
  canari-log-bundle DIR INDEX [-o FILE]         export an offline bundle
  canari-log-verify BUNDLE [--root HEX] ...     verify with no network
  canari-log-head   DIR                         print the latest signed head

Every command is offline; none of them contacts a registry. Exit codes:
0 ok, 2 verification/audit failed, 3 usage or I/O error.
"""
import argparse
import json
import sys

from canari.logstore import LogError, open_log
from canari.verify_offline import verify_bundle


def _read_records(args):
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = json.load(sys.stdin)
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not data:
        raise ValueError("expected a non-empty JSON object or array")
    out = []
    for item in data:
        if isinstance(item, dict) and "payload" in item and (
                "kind" not in item or isinstance(item.get("kind"), str)):
            out.append({"kind": item.get("kind", "record"),
                        "timestamp": item.get("timestamp"),
                        "payload": item["payload"]})
        else:
            out.append({"kind": "record", "payload": item})
    return out


def cmd_init(a):
    L = open_log(a.dir, log_id=a.log_id)
    L.public_key()
    head = L.seal(timestamp=a.timestamp)
    print(json.dumps({"log_dir": L.dir, "log_id": a.log_id,
                      "public_key": L.public_key(), "head": head},
                     ensure_ascii=False, indent=1, sort_keys=True))
    return 0


def cmd_append(a):
    L = open_log(a.dir, log_id=a.log_id)
    recs = _read_records(a)
    res = L.append_many(recs)
    print(json.dumps({"appended": len(res),
                      "first_index": res[0]["index"],
                      "last_index": res[-1]["index"],
                      "size": L.size()}, ensure_ascii=False))
    return 0


def cmd_seal(a):
    L = open_log(a.dir, log_id=a.log_id)
    head = L.seal(timestamp=a.timestamp, force=a.force)
    if head is None:
        print(json.dumps({"sealed": False, "reason": "no new entries"}, ensure_ascii=False))
        return 0
    print(json.dumps({"sealed": True, "head": head}, ensure_ascii=False,
                     indent=1, sort_keys=True))
    return 0


def cmd_audit(a):
    rep = open_log(a.dir, log_id=a.log_id).audit()
    print(json.dumps(rep, ensure_ascii=False, indent=1, sort_keys=True))
    return 0 if rep["ok"] else 2


def cmd_bundle(a):
    L = open_log(a.dir, log_id=a.log_id)
    b = L.export_bundle(a.index)
    text = json.dumps(b, ensure_ascii=False, indent=1, sort_keys=True)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("wrote %s (%d bytes)" % (a.out, len(text)))
    else:
        print(text)
    return 0


def cmd_verify(a):
    try:
        with open(a.bundle, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as e:
        print("cannot read bundle: %s" % e, file=sys.stderr)
        return 3
    rep = verify_bundle(bundle, a.log_id, a.root, a.min_size)
    if a.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1, sort_keys=True))
    else:
        for c in rep["checks"]:
            print("%s %s%s" % ("PASS" if c["ok"] else "FAIL", c["name"],
                               ("  (" + c["detail"] + ")") if c["detail"] else ""))
        print("RESULT: %s" % ("OK" if rep["ok"] else "FAILED"))
    return 0 if rep["ok"] else 2


def cmd_head(a):
    L = open_log(a.dir, log_id=a.log_id)
    h = L.last_head()
    if not h:
        print("no signed head", file=sys.stderr)
        return 3
    print(json.dumps(h, ensure_ascii=False, indent=1, sort_keys=True))
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="canari-log", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, need_log_id=True):
        sp.add_argument("dir")
        if need_log_id:
            sp.add_argument("--log-id", default="canari-log")

    sp = sub.add_parser("init")
    common(sp)
    sp.add_argument("--timestamp")
    sp.set_defaults(fn=cmd_init)

    sp = sub.add_parser("append")
    common(sp)
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--file")
    g.add_argument("--stdin", action="store_true")
    sp.set_defaults(fn=cmd_append)

    sp = sub.add_parser("seal")
    common(sp)
    sp.add_argument("--timestamp")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(fn=cmd_seal)

    sp = sub.add_parser("audit")
    common(sp)
    sp.set_defaults(fn=cmd_audit)

    sp = sub.add_parser("bundle")
    common(sp)
    sp.add_argument("index", type=int)
    sp.add_argument("-o", "--out")
    sp.set_defaults(fn=cmd_bundle)

    sp = sub.add_parser("head")
    common(sp)
    sp.set_defaults(fn=cmd_head)

    sp = sub.add_parser("verify")
    sp.add_argument("bundle")
    sp.add_argument("--log-id", default=None)
    sp.add_argument("--root", default=None)
    sp.add_argument("--min-size", type=int, default=0)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=cmd_verify)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        return a.fn(a)
    except LogError as e:
        print("log error: %s" % e, file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
