#!/usr/bin/env python3
"""Probe endpoints for SEP-2127 self-identification.

card     GET <remote-url>/server-card  -> JSON with (server-card media type)
         or ($schema + name + remotes)
catalog  GET https://<host>/.well-known/ai-catalog.json -> JSON with entries
         or specVersion

Error bodies (`{"error": ...}`) do not count.
"""
import concurrent.futures
import json
import random
import ssl
import sys
import urllib.error
import urllib.request

CARD = "application/mcp-server-card+json"
CTX = ssl.create_default_context()
HDR = {"User-Agent": "canari-research/0.1 (+server-card-adoption)",
       "Accept": "application/mcp-server-card+json, application/ai-catalog+json, "
                 "application/json, */*"}


def fetch(url, timeout=8):
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, headers=HDR),
                                   timeout=timeout, context=CTX)
        return r.status, r.headers.get("Content-Type") or "", r.read(120000)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.headers.get("Content-Type") or "", e.read(20000)
        except Exception:
            return e.code, "", b""
    except Exception:
        return None, "", b""


def _json(body):
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return None


def probe(rec):
    base = (rec.get("url") or "").split("?")[0].rstrip("/")
    host = rec["host"]
    out = {"name": rec["name"], "host": host, "cat": rec["cat"], "grp": rec["grp"]}

    st, ct, body = fetch(base + "/server-card")
    out["card"] = False
    if st == 200 and body:
        j = _json(body)
        if isinstance(j, dict):
            keys = j.keys()
            if CARD in (ct or "").lower() or ("remotes" in keys and "name" in keys):
                out["card"] = True
                out["card_name"] = j.get("name")

    st2, _, body2 = fetch("https://" + host + "/.well-known/ai-catalog.json")
    out["catalog"] = False
    if st2 == 200 and body2:
        j = _json(body2)
        out["catalog"] = isinstance(j, dict) and ("entries" in j or "specVersion" in j)
    return out


def main(src="domain_binding.json", out="probe.json", seed=20261116):
    recs = json.load(open(src, encoding="utf-8"))
    gap = [r for r in recs if r["cat"] in ("mismatch", "partial")
           and not r["name"].startswith("io.github.") and r.get("host")]
    exact = [r for r in recs if r["cat"] == "exact" and r.get("host")]
    gh = [r for r in recs if r["name"].startswith("io.github.") and r.get("host")]
    rnd = random.Random(seed)
    work = ([dict(r, grp="gap") for r in gap]
            + [dict(r, grp="exact-sample") for r in rnd.sample(exact, min(600, len(exact)))]
            + [dict(r, grp="github-sample") for r in rnd.sample(gh, min(600, len(gh)))])
    seen, dedup = set(), []
    for r in work:
        k = (r["grp"], r["host"])
        if k not in seen:
            seen.add(k)
            dedup.append(r)

    res = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as ex:
        for i, o in enumerate(ex.map(probe, dedup)):
            res.append(o)
            if (i + 1) % 400 == 0:
                print("  %d/%d" % (i + 1, len(dedup)), file=sys.stderr, flush=True)
    json.dump(res, open(out, "w", encoding="utf-8"), indent=1)

    for g in ("gap", "exact-sample", "github-sample"):
        sub = [r for r in res if r["grp"] == g]
        if sub:
            k = sum(1 for r in sub if r["card"] or r["catalog"])
            print("%-14s n=%5d self-described=%4d (%.2f%%)"
                  % (g, len(sub), k, 100.0 * k / len(sub)), file=sys.stderr)


if __name__ == "__main__":
    main(*(sys.argv[1:] or []))
