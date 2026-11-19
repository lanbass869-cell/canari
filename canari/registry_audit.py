# -*- coding: utf-8 -*-
"""registry_audit.py - canari-registry-audit: does a listed package still exist?

The registry validates a package version when it is published. Nothing re-checks it
afterwards, so an entry can keep advertising a version that npm or PyPI has since
unpublished. This measures that drift and writes a dated snapshot.

Usage:
  canari-registry-audit --out docs/audit/package-existence
  canari-registry-audit --out /tmp/a --max-pages 20 --workers 16   # smoke test

Output, all into --out:
  index.html            human-readable page for the latest run
  latest.json           machine-readable, with denominators and exclusions
  latest.csv            one row per reference that cannot be installed
  history/<date>.json   immutable per-run snapshot

Design notes
------------
* Two jobs are kept apart: `collect_refs` (pure) and `check_refs` (network). Only the
  first is unit-tested; the second is exercised by the scheduled run.
* A reference is "missing" only after retries. A network failure is never counted as
  missing -- it is retried, and anything still unresolved is reported separately
  rather than folded into the defect count.
* `version: latest` is reported in its own bucket, not as a missing version: it is a
  different defect (a reserved string) and it is a historic one, not a drift.
"""
import argparse
import csv
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

REGISTRY_API = "https://registry.modelcontextprotocol.io/v0/servers"
NPM_API = "https://registry.npmjs.org/"
PYPI_API = "https://pypi.org/pypi/%s/json"
UA = "canari-registry-audit/1.0 (+https://github.com/lanbass869-cell/canari)"
RESERVED_TAGS = {"latest", "next", "beta", "alpha", "canary", "stable", "current"}

CTX = ssl.create_default_context()


# ---------------------------------------------------------------- pure

def collect_refs(records):
    """records -> {(registry, identifier, version): sorted[server names]}.

    Only npm and pypi are collected: they expose a version list we can check against
    with a single request, unlike oci/nuget/cargo whose existence check has a different
    shape and is out of scope for this audit.
    """
    refs = defaultdict(set)
    for rec in records:
        server = rec.get("server") or {}
        name = server.get("name") or ""
        for pkg in (server.get("packages") or []):
            reg = pkg.get("registryType") or pkg.get("registry_type") or ""
            if reg not in ("npm", "pypi"):
                continue
            ident = pkg.get("identifier") or ""
            if not ident:
                continue
            refs[(reg, ident, pkg.get("version") or "")].add(name)
    return {k: sorted(v) for k, v in refs.items()}


def classify(version, http_status, version_present):
    """Turn a raw check result into one bucket.

    ok              the exact version resolves
    reserved-tag    version is a dist-tag like "latest", not a version
    package-gone    the package itself returns 404
    version-absent  the package exists but that version is not published
    unknown         could not be determined (network); never counted as missing
    """
    v = (version or "").strip().lower()
    if v in RESERVED_TAGS:
        return "reserved-tag"
    if http_status == 404:
        return "package-gone"
    if http_status == 200:
        return "ok" if version_present else "version-absent"
    return "unknown"


def summarize(rows):
    """rows -> the numbers the page and the JSON report quote."""
    buckets = Counter(r["status"] for r in rows)
    checked = len(rows)
    missing = buckets.get("package-gone", 0) + buckets.get("version-absent", 0)
    servers = {n for r in rows if r["status"] in ("package-gone", "version-absent")
               for n in r["servers"]}
    return {
        "checked": checked,
        "ok": buckets.get("ok", 0),
        "package_gone": buckets.get("package-gone", 0),
        "version_absent": buckets.get("version-absent", 0),
        "reserved_tag": buckets.get("reserved-tag", 0),
        "unknown": buckets.get("unknown", 0),
        "missing": missing,
        "missing_rate": (missing / checked) if checked else 0.0,
        "affected_servers": len(servers),
        "by_registry": dict(Counter(r["registry"] for r in rows
                                    if r["status"] in ("package-gone", "version-absent"))),
    }


def rank_namespaces(rows, limit=10):
    """Which publishers account for most of the affected entries.

    A publisher with 40 broken entries out of 40 is a different problem from one with 6
    out of 166, so the share of that namespace's own entries is reported alongside the
    count. Returns the top `limit` namespaces by affected entry count.
    """
    servers_by_ns = defaultdict(set)
    refs_by_ns = Counter()
    for r in rows:
        if r["status"] not in ("package-gone", "version-absent"):
            continue
        for name in r["servers"]:
            ns = name.split("/")[0] if "/" in name else name
            servers_by_ns[ns].add(name)
            refs_by_ns[ns] += 1
    total = sum(len(v) for v in servers_by_ns.values())
    ranked = sorted(servers_by_ns.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:limit]
    return [{"namespace": ns, "entries": len(sv), "refs": refs_by_ns[ns],
             "share": (len(sv) / total) if total else 0.0} for ns, sv in ranked]


def namespace_totals(records):
    """How many entries each namespace has in total, so a ratio can be quoted."""
    counts = Counter()
    for rec in records:
        name = (rec.get("server") or {}).get("name") or ""
        if "/" in name:
            counts[name.split("/")[0]] += 1
    return counts


# ---------------------------------------------------------------- network

def _get(url, timeout=20, tries=3):
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, None
        except Exception as e:            # network hiccup: retry, then report unknown
            last = type(e).__name__
            time.sleep(1.5 * (attempt + 1))
    return None, {"_err": last}


def fetch_registry(max_pages=None, sleep=0.0):
    """Full pagination of the latest snapshot."""
    records, cursor, pages = [], None, 0
    while True:
        url = REGISTRY_API + "?version=latest&limit=100"
        if cursor:
            url += "&cursor=" + urllib.parse.quote(cursor)
        status, data = _get(url, timeout=60)
        if status != 200 or not isinstance(data, dict):
            raise RuntimeError("registry fetch failed: %s %s" % (status, data))
        records.extend(data.get("servers") or [])
        cursor = (data.get("metadata") or {}).get("nextCursor")
        pages += 1
        if sleep:
            time.sleep(sleep)
        if not cursor or (max_pages and pages >= max_pages):
            break
    return records, pages


def check_one(item):
    (reg, ident, version), names = item
    if reg == "npm":
        url = NPM_API + urllib.parse.quote(ident, safe="@")
    else:
        url = PYPI_API % urllib.parse.quote(ident)
    status, data = _get(url, timeout=15)
    present = False
    if status == 200 and isinstance(data, dict):
        if reg == "npm":
            versions = data.get("versions") or {}
            present = version in versions
            # ★2026-11-19: an unpublished unscoped npm package keeps a tombstone -
            # GET returns 200 with an empty `versions` map and a `time.unpublished`
            # object. Treating that as "package exists, version missing" is wrong:
            # the package is gone and no version can be published under that name.
            if not versions or (data.get("time") or {}).get("unpublished"):
                return {
                    "registry": reg, "identifier": ident, "version": version,
                    "status": "package-gone", "http": status, "servers": names,
                }
        else:
            releases = data.get("releases") or {}
            present = bool(releases.get(version))     # a version with no files is not installable
            if not present:
                # ★2026-11-19: PyPI keys releases by PEP 440 normal form. A registry
                # entry declaring "0.2.0-rc.3" or "v0.1.1" is installable (pip normalises
                # it) but the raw string is not a key, so the audit counted it as
                # missing. Six such false positives were found by re-running the real
                # install; compare the normalised form before calling it absent.
                try:
                    from packaging.version import Version, InvalidVersion
                    norm = None
                    try:
                        norm = str(Version(version))
                    except InvalidVersion:
                        norm = None
                    if norm and norm != version:
                        present = bool(releases.get(norm))
                except ImportError:      # packaging missing: keep the raw comparison
                    pass
    return {
        "registry": reg, "identifier": ident, "version": version,
        "status": classify(version, status, present),
        "http": status, "servers": names,
    }


def check_refs(refs, workers=32):
    items = sorted(refs.items())
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(check_one, items))


# ---------------------------------------------------------------- output

def render_page(summary, rows, as_of, pages, ranking=None, ns_totals=None):
    """Build the page with explicit placeholder substitution.

    Not %-formatting: the stylesheet contains literal percent signs, which would
    collide with the format operator.
    """
    pct = summary["missing_rate"] * 100
    ok_pct = 100.0 * summary["ok"] / max(1, summary["checked"])
    body_rows = "".join(
        "<tr><td class=mono>%s</td><td class=mono>%s</td><td class=mono>%s</td><td>%s</td>"
        "<td class=mono>%s</td></tr>"
        % (r["registry"], r["identifier"], r["version"], r["status"],
           "<br>".join(r["servers"][:4]))
        for r in sorted(rows, key=lambda x: (x["registry"], x["identifier"]))[:400]
    )
    more = ""
    if len(rows) > 400:
        more = ("<p class=sub>This page lists the first 400 rows; the full list is in "
                "<code>latest.csv</code>.</p>")
    rank_html = ""
    if ranking:
        ns_totals = ns_totals or {}
        rows_html = "".join(
            "<tr><td class=mono>%s</td><td class=mono>%d</td><td class=mono>%d/%s</td>"
            "<td class=mono>%.0f%%</td></tr>"
            % (r["namespace"], r["entries"], r["entries"], ns_totals.get(r["namespace"], "?"),
               100.0 * r["share"])
            for r in ranking
        )
        rank_html = ("<table><thead><tr><th>namespace</th><th>affected entries</th>"
                     "<th>of that namespace</th><th>share of all affected</th></tr></thead>"
                     "<tbody>" + rows_html + "</tbody></table>")
    template = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Canari - package existence audit</title>
<style>
:root{--bg:#0a1210;--fg:#dfe9e4;--dim:#8ba39a;--line:#1e2f2a;--ok:#3ddc97;--warn:#f0c14b;--bad:#ff6b6b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;padding:40px 20px}
main{max-width:980px;margin:0 auto}h1{font-size:25px;margin:0 0 6px}h2{font-size:17px;margin:30px 0 10px}
.sub{color:var(--dim);margin:0 0 22px}
.note{border-left:3px solid var(--warn);background:#121d19;padding:14px 16px;margin:0 0 24px;color:#cfdcd6;font-size:14px}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;color:var(--dim);font-weight:500;border-bottom:1px solid var(--line);padding:8px 10px}
td{border-bottom:1px solid var(--line);padding:8px 10px;vertical-align:top}
.mono{font-family:ui-monospace,Consolas,monospace}
.ok{color:var(--ok)}.bad{color:var(--bad)}
code{background:#101a17;padding:2px 6px;border-radius:4px;font-family:ui-monospace,Consolas,monospace;font-size:13px}
nav{margin:0 0 20px;color:var(--dim);font-size:14px}a{color:#7fd1ff;text-decoration:none}a:hover{text-decoration:underline}
footer{margin-top:32px;color:var(--dim);font-size:13px;border-top:1px solid var(--line);padding-top:16px}
</style></head><body><main>
<nav><a href="/canari/">Canari</a> &middot; <a href="/canari/research/">Research</a> &middot; <a href="/canari/research/package-existence-audit-20261117.md">First report</a></nav>
<h1>Package existence audit</h1>
<p class=sub>Snapshot @@ASOF@@ &middot; @@PAGES@@ registry pages &middot; generated by <code>canari-registry-audit</code></p>

<div class=note>
<b>What this measures.</b> The registry checks a package version when it is published and
does not check it again. This resolves every npm/PyPI package reference in the latest
snapshot against the publisher's own registry, one request per package, and lists the ones
that cannot be installed today. A removed package is usually an unpublish, rename, yank or
abandonment &mdash; this is not a security report, and a missing version is not evidence of
malice. Entries using a dist-tag such as <code>latest</code> are counted separately, not as
missing versions.
</div>

<h2>Result</h2>
<table><tbody>
<tr><td>references checked</td><td class=mono>@@CHECKED@@</td></tr>
<tr><td class=ok>version resolves</td><td class=mono>@@OK@@ (@@OKPCT@@)</td></tr>
<tr><td class=bad>package no longer exists</td><td class=mono>@@GONE@@</td></tr>
<tr><td class=bad>version not published</td><td class=mono>@@ABSENT@@</td></tr>
<tr><td class=bad><b>cannot be installed</b></td><td class=mono><b>@@MISSING@@ (@@PCT@@)</b></td></tr>
<tr><td>entries affected</td><td class=mono>@@SERVERS@@</td></tr>
<tr><td>dist-tag instead of a version</td><td class=mono>@@TAGS@@</td></tr>
<tr><td>unresolved after retries</td><td class=mono>@@UNKNOWN@@</td></tr>
</tbody></table>

<h2>Where to start</h2>
<p class=sub>The affected entries are spread thinly: most publishers have one or two. These
namespaces account for the largest shares, so fixing them moves the total most.</p>
@@RANKING@@

<h2>Cannot be installed</h2>
@@MORE@@
<table><thead><tr><th>registry</th><th>identifier</th><th>version</th><th>status</th><th>listed as</th></tr></thead>
<tbody>@@ROWS@@</tbody></table>

<footer>Data CC BY 4.0. Regenerated by a scheduled run; earlier snapshots stay in
<code>history/</code>. If a number here is wrong it should be corrected with a note, not
silently replaced.</footer>
</main></body></html>"""
    repl = {
        "@@ASOF@@": as_of, "@@PAGES@@": str(pages),
        "@@CHECKED@@": str(summary["checked"]), "@@OK@@": str(summary["ok"]),
        "@@OKPCT@@": "%.2f%%" % ok_pct,
        "@@GONE@@": str(summary["package_gone"]),
        "@@ABSENT@@": str(summary["version_absent"]),
        "@@MISSING@@": str(summary["missing"]), "@@PCT@@": "%.2f%%" % pct,
        "@@SERVERS@@": str(summary["affected_servers"]),
        "@@TAGS@@": str(summary["reserved_tag"]),
        "@@UNKNOWN@@": str(summary["unknown"]),
        "@@MORE@@": more, "@@ROWS@@": body_rows, "@@RANKING@@": rank_html,
    }
    for k, v in repl.items():
        template = template.replace(k, v)
    return template


def write_outputs(out_dir, summary, rows, as_of, pages, ranking=None, ns_totals=None):
    os.makedirs(os.path.join(out_dir, "history"), exist_ok=True)
    missing = [r for r in rows if r["status"] in ("package-gone", "version-absent")]
    doc = {"as_of": as_of, "pages": pages, "summary": summary,
           "excluded_reserved_tag": summary["reserved_tag"],
           "ranking": ranking or [],
           "ranking_denominators": {r["namespace"]: (ns_totals or {}).get(r["namespace"])
                                    for r in (ranking or [])},
           "rows": missing}
    with open(os.path.join(out_dir, "latest.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    with open(os.path.join(out_dir, "history", "%s.json" % as_of), "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    with open(os.path.join(out_dir, "latest.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["registry", "identifier", "version", "status",
                                          "servers"])
        w.writeheader()
        for r in missing:
            w.writerow({"registry": r["registry"], "identifier": r["identifier"],
                        "version": r["version"], "status": r["status"],
                        "servers": ";".join(r["servers"])})
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(render_page(summary, missing, as_of, pages, ranking, ns_totals))
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(prog="canari-registry-audit",
                                description="Check that every listed npm/PyPI package version still exists.")
    ap.add_argument("--out", default="docs/audit/package-existence", help="output directory")
    ap.add_argument("--max-pages", type=int, default=None, help="stop early (smoke tests)")
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--as-of", default=None, help="YYYY-MM-DD (default: today, UTC)")
    a = ap.parse_args(argv)

    as_of = a.as_of or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    records, pages = fetch_registry(max_pages=a.max_pages)
    refs = collect_refs(records)
    print("registry records: %d (%d pages); distinct npm/pypi refs: %d"
          % (len(records), pages, len(refs)), file=sys.stderr)
    rows = check_refs(refs, workers=a.workers)
    summary = summarize(rows)
    ranking = rank_namespaces(rows)
    doc = write_outputs(a.out, summary, rows, as_of, pages, ranking, namespace_totals(records))
    print(json.dumps(summary, indent=1), file=sys.stderr)
    print("wrote %s" % os.path.join(a.out, "latest.json"), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
