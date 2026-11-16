#!/usr/bin/env python3
"""Full pagination of the official MCP registry, latest version per server.

Writes every latest record to `latest.json`. 2026-11-16: 654 pages / 65,340 records.
"""
import json
import ssl
import sys
import time
import urllib.request

API = "https://registry.modelcontextprotocol.io/v0/servers"
CTX = ssl.create_default_context()
HDR = {"User-Agent": "canari-research/0.1 (+server-card-adoption)"}


def get(url, timeout=45, tries=3):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=HDR)
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
                return json.loads(r.read())
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(1.5 * (i + 1))


def main(out="latest.json", cap=700):
    cursor, rows, pages = None, [], 0
    while True:
        url = API + "?version=latest&limit=100" + (("&cursor=" + cursor) if cursor else "")
        d = get(url)
        rows.extend(d.get("servers", []))
        pages += 1
        cursor = (d.get("metadata") or {}).get("nextCursor")
        if pages % 10 == 0:
            print("page %d rows %d" % (pages, len(rows)), file=sys.stderr, flush=True)
        if not cursor or pages >= cap:
            break
    json.dump(rows, open(out, "w", encoding="utf-8"))
    print("pages=%d rows=%d" % (pages, len(rows)), file=sys.stderr)


if __name__ == "__main__":
    main(*(sys.argv[1:] or []))
