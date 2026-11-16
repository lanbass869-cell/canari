# -*- coding: utf-8 -*-
"""emit_capsules.py - publish measurement capsules for real MCP endpoints.

Run: python scripts/emit_capsules.py [--limit 40] [--out docs/capsules]

Every capsule here is built from two things that exist independently of us:
a record published by the official MCP registry, and the endpoint's own answer
to a read-only initialize. The capsule records the digest of each, so a reader
who fetches the same registry record can recompute the declaration side and see
that we did not paraphrase it.
"""
import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from canari import capsule as cap            # noqa: E402
from canari import capsule_emit as emit      # noqa: E402
from canari.mcp_probe import probe_endpoint  # noqa: E402

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers?limit=%d"
SEARCH = "https://registry.modelcontextprotocol.io/v0/servers?limit=100&search=%s"


def fetch_registry(limit):
    req = urllib.request.Request(REGISTRY % limit,
                                 headers={"User-Agent": "canari-probe/0.1"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.loads(r.read().decode("utf-8"))


def fetch_by_name(name):
    """Registry records whose declared name matches `name` exactly.

    Needed because the default listing is ordered and capped: a server can be
    perfectly well declared and still never appear in the first N records (the
    inbin endpoint was declared under two names and absent from the first 100,
    while only 64 of those 100 records had a unique remote URL).
    """
    url = SEARCH % urllib.parse.quote(name, safe="")
    req = urllib.request.Request(url, headers={"User-Agent": "canari-probe/0.1"})
    with urllib.request.urlopen(req, timeout=90) as r:
        data = json.loads(r.read().decode("utf-8"))
    out = []
    for s in data.get("servers") or []:
        server = s.get("server") or s
        if server.get("name") == name:
            out.append(s)
    return out


def targets(data):
    """One (entry, url) per remote, de-duplicated by url."""
    seen, out = set(), []
    for s in data.get("servers") or []:
        server = s.get("server") or s
        for rm in (server.get("remotes") or []):
            url = rm.get("url")
            if not url or url in seen:
                continue
            seen.add(url)
            out.append((s, url))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=60)
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "capsules"))
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--max-probe", type=int, default=40)
    ap.add_argument("--include", action="append", default=[],
                    metavar="REGISTRY_NAME",
                    help="also probe the endpoints declared by this registry "
                         "name (repeatable). Use it for servers that are "
                         "declared but fall outside the default listing window.")
    a = ap.parse_args(argv)

    data = fetch_registry(a.limit)
    todo = targets(data)[:a.max_probe]
    if a.include:
        seen = {u for _, u in todo}
        for name in a.include:
            found = fetch_by_name(name)
            if not found:
                print("[include] %s: no exact registry match" % name)
                continue
            added = 0
            for entry, url in targets({"servers": found}):
                if url in seen:
                    continue
                seen.add(url)
                todo.append((entry, url))
                added += 1
            print("[include] %s: %d record(s), %d new endpoint(s)"
                  % (name, len(found), added))
    print("registry entries=%d, endpoints to probe=%d"
          % (len(data.get("servers") or []), len(todo)))

    capsules, bad = [], []
    for entry, url in todo:
        probe = probe_endpoint(url, timeout=a.timeout)
        doc = emit.build_parity_capsule(entry, probe)
        problems = cap.validate_capsule(doc)
        if problems:
            bad.append({"url": url, "problems": problems})
        capsules.append(doc)
        print("  %-46s %-20s %-12s" % (url[:46], probe["outcome"],
                                       doc["measurement_state"]))
        sys.stdout.flush()
        time.sleep(0.2)          # politeness: these are other people's servers

    os.makedirs(a.out, exist_ok=True)
    lines = b"".join((cap.jcs(c) + b"\n") for c in
                     sorted(capsules, key=lambda x: x["capsule_id"]))
    caps_path = os.path.join(a.out, "capsules.jsonl")
    with open(caps_path, "wb") as f:
        f.write(lines)

    batch = emit.build_batch(capsules)
    batch_path = os.path.join(a.out, "batch.json")
    with open(batch_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(batch, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")

    print("\ncapsules=%d problems=%d" % (len(capsules), len(bad)))
    print("states=%s" % batch["states"])
    print("merkle_root=%s" % batch["merkle_root"])
    print("wrote %s (%d bytes) and %s" % (caps_path, len(lines), batch_path))
    if bad:
        for b in bad[:5]:
            print("  PROBLEM %s: %s" % (b["url"], b["problems"]))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
