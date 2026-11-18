"""How many of the 274 broken references have been fixed since the snapshot?

Re-resolves every reference today with the corrected (PEP 440-normalised) checker.
Answers the reviewer question: 'is anyone actually fixing these?'
"""
import csv, json, os, sys
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, r"E:\Temp\tbdig\canari")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import canari.registry_audit as ra

CSV = r"E:\Temp\tbdig\canari\docs\research\data\package-existence-20261117.csv"
OUT = r"E:\Temp\tbdig\canari\experiments\package_existence_repro\recovery.json"
rows = list(csv.DictReader(open(CSV, encoding="utf-8")))
print("references:", len(rows))

items = []
for r in rows:
    items.append(((r["registry"], r["identifier"], r["version"]), []))

with ThreadPoolExecutor(max_workers=16) as ex:
    res = list(ex.map(ra.check_one, items))

still = [x for x in res if x["status"] in ("package-gone", "version-absent")]
recovered = [x for x in res if x["status"] == "ok"]
unknown = [x for x in res if x["status"] == "unknown"]
other = [x for x in res if x["status"] not in ("package-gone", "version-absent", "ok", "unknown")]
print("still broken: %d  recovered: %d  unknown: %d  other: %d"
      % (len(still), len(recovered), len(unknown), len(other)))
for x in recovered[:10]:
    print("  recovered:", x["registry"], x["identifier"], x["version"])
for x in unknown[:5]:
    print("  unknown:", x["registry"], x["identifier"], x["version"], x.get("http"))
json.dump({"checked": len(rows), "still_broken": len(still), "recovered": len(recovered),
           "unknown": len(unknown),
           "recovered_list": [{"registry": x["registry"], "identifier": x["identifier"],
                               "version": x["version"]} for x in recovered]},
          open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("wrote", OUT)
