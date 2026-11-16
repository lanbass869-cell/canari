#!/usr/bin/env python3
"""Classify each remote endpoint host against the domains its registry name implies.

Auth rule (internal/api/handlers/v0/auth/common.go, BuildPermissions): a verified
domain D grants the reverse namespace reverse(D); a subdomain grant extends it by
labels. So namespace N is legitimate if some domain D has reverse(D) as a PREFIX
of N, i.e. D = reverse(n1..ni) for some prefix length i.

A single label is a TLD and not ownable, so i >= 2.

    com.example/server   -> example.com
    ac.inference.sh/mcp  -> inference.ac, sh.inference.ac
    io.github.user/repo  -> github.io (GitHub auth), user.github.io

exact    host equals one of those domains or is a subdomain of one
mismatch otherwise
"""
import json
import sys
import urllib.parse
from collections import Counter


def domains_for(namespace):
    labels = namespace.split(".")
    return {".".join(reversed(labels[:i])) for i in range(2, len(labels) + 1)}


def classify(namespace, host):
    host = (host or "").lower().rstrip(".")
    for d in domains_for(namespace):
        d = d.lower()
        if host == d or host.endswith("." + d):
            return "exact"
    return "mismatch"


def kind(name):
    return "github" if name.split("/")[0].startswith("io.github.") else "reverse_dns"


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
                     "cat": classify(name.split("/")[0], host) if host else "bad-url"})
    json.dump(recs, open(out, "w", encoding="utf-8"))
    print(dict(Counter(r["cat"] for r in recs)), file=sys.stderr)
    for k in ("reverse_dns", "github"):
        sub = [r for r in recs if r["cat"] != "no-remote" and kind(r["name"]) == k]
        c = Counter(r["cat"] for r in sub)
        print("%-11s total=%6d exact=%6d (%.2f%%) mismatch=%6d (%.2f%%)"
              % (k, len(sub), c.get("exact", 0), 100.0 * c.get("exact", 0) / len(sub),
                 c.get("mismatch", 0), 100.0 * c.get("mismatch", 0) / len(sub)),
              file=sys.stderr)


if __name__ == "__main__":
    main(*(sys.argv[1:] or []))
