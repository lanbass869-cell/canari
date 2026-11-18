"""Retry the PyPI download stats that hit 429, sequentially with a delay."""
import json, os, statistics, sys, time, urllib.error, urllib.request, urllib.parse
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = r"E:\Temp\tbdig\canari"
PATH = os.path.join(ROOT, "experiments", "package_existence_repro", "downloads.json")
UA = "canari-probe/1.0 (mailto:noreply@example.com)"
d = json.load(open(PATH, encoding="utf-8"))
rows = d["rows"]
todo = [r for r in rows if r.get("error") == "HTTP 429"]
print("retrying", len(todo))
fixed = 0
for r in todo:
    if r["registry"] != "pypi":
        continue
    u = "https://pypistats.org/api/packages/%s/recent" % urllib.parse.quote(r["package"])
    for attempt in range(3):
        try:
            j = json.loads(urllib.request.urlopen(
                urllib.request.Request(u, headers={"User-Agent": UA}), timeout=30).read().decode())
            r["monthly"] = (j.get("data") or {}).get("last_month")
            r["error"] = None
            fixed += 1
            break
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(3 * (attempt + 1))
                continue
            r["error"] = "HTTP %s" % e.code
            break
        except Exception as e:
            r["error"] = type(e).__name__
            break
    time.sleep(0.9)
vals = sorted(r["monthly"] for r in rows if r.get("monthly") is not None)
print("fixed", fixed, "| stats now", len(vals))
if vals:
    print("median %d  mean %.1f  p90 %d  max %d  >=100/mo: %d"
          % (statistics.median(vals), sum(vals)/len(vals), vals[int(len(vals)*0.9)],
             vals[-1], sum(1 for v in vals if v >= 100)))
d["stats_obtained"] = len(vals)
d["median_monthly"] = statistics.median(vals) if vals else None
d["p90_monthly"] = vals[int(len(vals) * 0.9)] if vals else None
d["max_monthly"] = vals[-1] if vals else None
d["with_any_downloads"] = sum(1 for v in vals if v > 0)
d["rows"] = rows
json.dump(d, open(PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("updated", PATH)
