"""Week 2: how old are the registry entries whose install is dead?

Join the published broken-reference list against the 2026-11-18 registry snapshot
(experiments/identity_conflict/servers.json) to get each entry's _meta.publishedAt,
then report the age distribution.

Caveat stated in the output: an entry's publishedAt is when the registry published
that entry, not when the upstream package disappeared. So age is an UPPER BOUND on
how long the install has been broken, not the break duration itself.
"""
import csv, json, os, sys
from collections import defaultdict
from datetime import datetime, timezone

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = r"E:\Temp\tbdig\canari"
CSV_PATH = os.path.join(ROOT, "docs", "research", "data", "package-existence-20261117.csv")
SNAP = os.path.join(ROOT, "experiments", "identity_conflict", "servers.json")
OUT = os.path.join(ROOT, "experiments", "package_existence_repro", "staleness.json")

rows = list(csv.DictReader(open(CSV_PATH, encoding="utf-8")))
print("broken references:", len(rows))

snap = json.load(open(SNAP, encoding="utf-8"))
servers = snap.get("servers") or []
print("registry snapshot records:", len(servers), "as_of", snap.get("as_of"))

idx = defaultdict(list)
for rec in servers:
    srv = rec.get("server") or {}
    name = srv.get("name") or ""
    # _meta lives on the RECORD, under the registry's official namespace.
    meta = rec.get("_meta") or {}
    official = meta.get("io.modelcontextprotocol.registry/official") or {}
    pub = official.get("publishedAt") or ""
    for pkg in (srv.get("packages") or []):
        reg = pkg.get("registryType") or pkg.get("registry_type") or ""
        ident = pkg.get("identifier") or ""
        ver = (pkg.get("version") or "")
        if reg and ident:
            idx[(reg, ident, ver)].append({"server": name, "publishedAt": pub})

now = datetime.now(timezone.utc)
matched, unmatched = [], 0
for r in rows:
    key = (r["registry"], r["identifier"], r["version"])
    hits = idx.get(key) or []
    if not hits:
        # fall back to ignoring the version (registry may omit it)
        hits = [h for k, v in idx.items()
                if k[0] == r["registry"] and k[1] == r["identifier"] for h in v]
    if not hits:
        unmatched += 1
        continue
    for h in hits:
        try:
            dt = datetime.fromisoformat(h["publishedAt"].replace("Z", "+00:00"))
        except Exception:
            continue
        matched.append({"registry": r["registry"], "identifier": r["identifier"],
                        "version": r["version"], "status": r["status"],
                        "server": h["server"], "publishedAt": h["publishedAt"],
                        "age_days": round((now - dt).total_seconds() / 86400.0, 1)})

ages = sorted(x["age_days"] for x in matched)
def pct(p):
    return ages[min(len(ages) - 1, int(len(ages) * p))] if ages else None
print("matched entries:", len(matched), "unmatched references:", unmatched)
if ages:
    print("age days  min %.1f  p25 %.1f  median %.1f  p75 %.1f  p90 %.1f  max %.1f"
          % (ages[0], pct(.25), pct(.5), pct(.75), pct(.9), ages[-1]))
    print("entries older than 30d: %d (%.1f%%)"
          % (sum(1 for a in ages if a > 30), 100.0 * sum(1 for a in ages if a > 30) / len(ages)))
    print("entries older than 90d: %d (%.1f%%)"
          % (sum(1 for a in ages if a > 90), 100.0 * sum(1 for a in ages if a > 90) / len(ages)))

json.dump({"as_of": snap.get("as_of"), "broken_refs": len(rows),
           "matched": len(matched), "unmatched": unmatched,
           "ages_days": {"min": ages[0] if ages else None,
                         "median": pct(.5), "p90": pct(.9),
                         "max": ages[-1] if ages else None},
           "entries": matched}, open(OUT, "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
print("wrote", OUT)
