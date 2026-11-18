"""Is there a real cross-ecosystem identity conflict to build on?

Question (plan line 3, decision point 2026-12-31): the same component lives in
several ecosystems (npm, PyPI, MCP Registry, dsh). Is the *name* enough to tell
them apart? This probe looks for two concrete failure shapes in the public data:

  A. one package identifier claimed by more than one MCP Registry server entry
     (same bytes, two owners)
  B. one bare name used by both npm and PyPI inside the same registry snapshot
     (same name, two different components)

Nothing is written outside this directory. Re-run: python probe.py
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
SERVERS = os.path.join(HERE, "servers.json")
UA = "canari-identity-probe/1.0 (+https://github.com/lanbass869-cell/canari)"
API = "https://registry.modelcontextprotocol.io/v0/servers"


def _get(url, timeout=60, tries=5):
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:          # transient TLS/EOF: back off and retry
            last = "%s: %s" % (type(e).__name__, e)
            time.sleep(2.0 * (attempt + 1))
    raise RuntimeError("fetch failed after %d tries: %s (%s)" % (tries, url, last))


def fetch_all():
    """Full pagination, resumable: a dropped TLS connection costs one page."""
    part = os.path.join(HERE, "servers.partial.json")
    if os.path.exists(SERVERS):
        with open(SERVERS, encoding="utf-8") as f:
            return json.load(f)
    records, cursor, pages = [], None, 0
    if os.path.exists(part):
        with open(part, encoding="utf-8") as f:
            st = json.load(f)
        records, cursor, pages = st["servers"], st["cursor"], st["pages"]
        print("resuming at page", pages, "with", len(records), "records", flush=True)
    while True:
        url = API + "?version=latest&limit=100"
        if cursor:
            url += "&cursor=" + urllib.parse.quote(cursor)
        data = _get(url)
        records.extend(data.get("servers") or [])
        cursor = (data.get("metadata") or {}).get("nextCursor")
        pages += 1
        maxp = int(os.environ.get("MAX_PAGES", "0") or 0)
        if maxp and pages >= maxp:
            print("  stopping at MAX_PAGES=%d" % maxp, flush=True)
            break
        if pages % 50 == 0:
            print("  pages", pages, "records", len(records), flush=True)
            with open(part, "w", encoding="utf-8") as f:
                json.dump({"servers": records, "cursor": cursor, "pages": pages}, f)
        if not cursor:
            break
    as_of = __import__("datetime").date.today().isoformat()
    complete = not cursor
    payload = {"as_of": as_of, "pages": pages, "servers": records,
               "complete": complete}
    if complete:
        with open(SERVERS, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        if os.path.exists(part):
            os.remove(part)
    else:
        with open(part, "w", encoding="utf-8") as f:
            json.dump({"servers": records, "cursor": cursor, "pages": pages}, f)
        print("  INCOMPLETE: %d pages, cursor saved" % pages, flush=True)
    return payload


def analyse(records):
    ident_owners = defaultdict(set)          # (reg, ident) -> {server names}
    bare_regs = defaultdict(set)             # bare name -> {reg}
    server_idents = defaultdict(set)         # server name -> {(reg, ident)}
    for rec in records:
        srv = rec.get("server") or {}
        sname = srv.get("name") or ""
        for pkg in (srv.get("packages") or []):
            reg = pkg.get("registryType") or pkg.get("registry_type") or ""
            if reg not in ("npm", "pypi"):
                continue
            ident = pkg.get("identifier") or ""
            if not ident:
                continue
            ident_owners[(reg, ident)].add(sname)
            bare_regs[ident.casefold()].add(reg)
            server_idents[sname].add((reg, ident))

    multi_owner = {("%s|%s" % k): sorted(v)
                   for k, v in ident_owners.items() if len(v) > 1}
    cross_reg = {n: sorted(r) for n, r in bare_regs.items() if len(r) > 1}
    return {
        "servers": len(records),
        "identifiers": len(ident_owners),
        "identifiers_claimed_by_multiple_servers": len(multi_owner),
        "bare_names_in_both_npm_and_pypi": len(cross_reg),
        "multi_owner_examples": dict(sorted(multi_owner.items())[:10]),
        "cross_registry_examples": dict(sorted(cross_reg.items())[:10]),
        "_multi_owner": multi_owner,
        "_cross_reg": cross_reg,
    }


if __name__ == "__main__":
    print("fetching the full registry snapshot ...", flush=True)
    snap = fetch_all()
    res = analyse(snap["servers"])
    n = res.pop("_multi_owner")
    c = res.pop("_cross_reg")
    out = dict(res, as_of=snap["as_of"], pages=snap["pages"],
               complete=snap.get("complete", True),
               all_multi_owner=n, all_cross_registry=c)
    with open(os.path.join(HERE, "result.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in res.items() if not k.endswith("_examples")},
                     ensure_ascii=False, indent=1))
