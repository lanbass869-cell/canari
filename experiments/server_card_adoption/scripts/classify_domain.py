#!/usr/bin/env python3
"""Classify each remote endpoint host against the domain its registry name claims.

    ac.inference.sh/mcp -> {inference.sh, ac.inference.sh}
    ai.ankra/platform   -> {ankra.ai, ai.ankra}
    io.github.user/repo -> {user.github.io}

exact    host equals a candidate, or is a subdomain of one
partial  same last-two-labels suffix, not a subdomain
mismatch neither
"""
import json
import sys
import urllib.parse
from collections import Counter


def candidates(name):
    if "/" not in name:
        return []
    parts = name.split("/")[0].split(".")
    out = {".".join(reversed(parts))}
    for i in range(len(parts)):
        out.add(".".join(parts[i:]))
    if len(parts) == 3 and parts[:2] == ["io", "github"]:
        out.add(parts[2] + ".github.io")
    return [c for c in out if c]


def _reg(h):
    p = h.split(".")
    return ".".join(p[-2:]) if len(p) >= 2 else h


def classify(name, host):
    host = (host or "").lower().rstrip(".")
    cands = candidates(name)
    if not cands:
        return "no-namespace"
    for c in cands:
        if host == c.lower() or host.endswith("." + c.lower()):
            return "exact"
    for c in cands:
        if _reg(c.lower()) == _reg(host):
            return "partial"
    return "mismatch"


def main(src="latest.json", out="domain_binding.json"):
    rows = json.load(open(src, encoding="utf-8"))
    recs = []
    for x in rows:
        s = x.get("server") or {}
        name = s.get("name") or ""
        remotes = s.get("remotes") or []
        if not remotes:
            recs.append({"name": name, "host": None, "url": None, "cat": "no-remote"})
            continue
        url = remotes[0].get("url") or ""
        host = urllib.parse.urlsplit(url).hostname
        recs.append({"name": name, "host": host, "url": url,
                     "cat": classify(name, host) if host else "bad-url"})
    json.dump(recs, open(out, "w", encoding="utf-8"))
    counts = Counter(r["cat"] for r in recs)
    print(dict(counts), file=sys.stderr)
    for kind, pred in (("reverse_dns", lambda n: not n.startswith("io.github.")),
                       ("github", lambda n: n.startswith("io.github."))):
        sub = [r for r in recs if r["cat"] != "no-remote" and pred(r["name"])]
        c = Counter(r["cat"] for r in sub)
        print("%s total=%d %s" % (kind, len(sub), dict(c)), file=sys.stderr)


if __name__ == "__main__":
    main(*(sys.argv[1:] or []))
