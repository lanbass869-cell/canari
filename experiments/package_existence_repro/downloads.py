"""Do the broken entries have real users? Monthly download counts.

npm  : https://api.npmjs.org/downloads/point/last-month/<pkg>
PyPI : https://pypistats.org/api/packages/<pkg>/recent

A 404 from the download API is itself informative for package-gone entries.
"""
import json, os, statistics, sys, urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = r"E:\Temp\tbdig\canari"
STALE = os.path.join(ROOT, "experiments", "package_existence_repro", "staleness.json")
OUT = os.path.join(ROOT, "experiments", "package_existence_repro", "downloads.json")
UA = "canari-probe/1.0"

entries = json.load(open(STALE, encoding="utf-8"))["entries"]
uniq = sorted({(e["registry"], e["identifier"]) for e in entries})
print("unique (registry, package) pairs:", len(uniq))


def fetch(item):
    reg, name = item
    try:
        if reg == "npm":
            url = "https://api.npmjs.org/downloads/point/last-month/" + urllib.parse.quote(name, safe="@")
            d = json.loads(urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": UA}), timeout=30).read().decode())
            return reg, name, d.get("downloads"), None
        url = "https://pypistats.org/api/packages/%s/recent" % urllib.parse.quote(name)
        d = json.loads(urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent": UA}), timeout=30).read().decode())
        return reg, name, (d.get("data") or {}).get("last_month"), None
    except urllib.error.HTTPError as e:
        return reg, name, None, "HTTP %s" % e.code
    except Exception as e:
        return reg, name, None, type(e).__name__


import urllib.parse  # noqa: E402  (used above)

with ThreadPoolExecutor(max_workers=8) as ex:
    rows = list(ex.map(fetch, uniq))

got = [r for r in rows if r[2] is not None]
vals = sorted(r[2] for r in got)
print("download stats obtained:", len(got), "/", len(rows))
if vals:
    print("monthly downloads: median %d  mean %.1f  p90 %d  max %d"
          % (statistics.median(vals), sum(vals) / len(vals),
             vals[int(len(vals) * 0.9)], vals[-1]))
    print("packages with >0 downloads: %d (%.1f%%)"
          % (sum(1 for v in vals if v > 0), 100.0 * sum(1 for v in vals if v > 0) / len(vals)))
    print("packages with >=100 downloads/month: %d" % sum(1 for v in vals if v >= 100))
top = sorted(got, key=lambda r: -r[2])[:8]
for r in top:
    print("  top:", r[0], r[1], r[2])
errs = {}
for r in rows:
    if r[3]:
        errs[r[3]] = errs.get(r[3], 0) + 1
print("errors:", errs)

json.dump({"unique_packages": len(uniq), "stats_obtained": len(got),
           "median_monthly": statistics.median(vals) if vals else None,
           "p90_monthly": vals[int(len(vals) * 0.9)] if vals else None,
           "max_monthly": vals[-1] if vals else None,
           "with_any_downloads": sum(1 for v in vals if v > 0),
           "errors": errs, "rows": [{"registry": r[0], "package": r[1],
                                     "monthly": r[2], "error": r[3]} for r in rows]},
          open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("wrote", OUT)
