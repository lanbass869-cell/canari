import json, os, statistics, sys, time, urllib.error, urllib.request, urllib.parse
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
PATH = r"E:\Temp\tbdig\canari\experiments\package_existence_repro\downloads.json"
UA = "canari-probe/1.0"
d = json.load(open(PATH, encoding="utf-8"))
rows = d["rows"]
todo = [r for r in rows if r["registry"] == "npm" and r.get("error") == "HTTP 429"]
print("retrying npm", len(todo))
fixed = 0
for r in todo:
    u = "https://api.npmjs.org/downloads/point/last-month/" + urllib.parse.quote(r["package"], safe="@")
    for attempt in range(4):
        try:
            j = json.loads(urllib.request.urlopen(
                urllib.request.Request(u, headers={"User-Agent": UA}), timeout=30).read().decode())
            r["monthly"] = j.get("downloads")
            r["error"] = None
            fixed += 1
            break
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(2 * (attempt + 1)); continue
            r["error"] = "HTTP %s" % e.code; break
        except Exception as e:
            r["error"] = type(e).__name__; break
    time.sleep(0.45)
vals = sorted(r["monthly"] for r in rows if r.get("monthly") is not None)
bynpm = sorted(r["monthly"] for r in rows if r["registry"] == "npm" and r.get("monthly") is not None)
bypypi = sorted(r["monthly"] for r in rows if r["registry"] == "pypi" and r.get("monthly") is not None)
print("fixed", fixed, "| total stats", len(vals))
for label, v in (("npm", bynpm), ("pypi", bypypi), ("all", vals)):
    if v:
        print("%-5s n=%-3d median=%d mean=%.0f p90=%d max=%d >=100/mo=%d"
              % (label, len(v), statistics.median(v), sum(v)/len(v),
                 v[int(len(v)*0.9)], v[-1], sum(1 for x in v if x >= 100)))
d["stats_obtained"] = len(vals)
d["median_monthly"] = statistics.median(vals) if vals else None
d["max_monthly"] = vals[-1] if vals else None
d["with_any_downloads"] = sum(1 for v in vals if v > 0)
d["by_registry"] = {"npm": {"n": len(bynpm), "median": statistics.median(bynpm) if bynpm else None,
                            "max": bynpm[-1] if bynpm else None},
                    "pypi": {"n": len(bypypi), "median": statistics.median(bypypi) if bypypi else None,
                             "max": bypypi[-1] if bypypi else None}}
d["rows"] = rows
json.dump(d, open(PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("updated")
