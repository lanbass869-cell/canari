"""Week 1 of the package-existence subproblem: does the install really fail?

Takes 20 package-gone and 20 version-absent references from the published CSV and
runs the real install command for each, recording exit code and error class.

  npm  : npm install <name>@<ver> --dry-run --ignore-scripts --no-audit --no-fund
  pypi : pip download <name>==<ver> --no-deps -d <tmp>
"""
import csv, json, os, re, subprocess, sys, tempfile
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CSV_PATH = r"E:\Temp\tbdig\canari\docs\research\data\package-existence-20261117.csv"
PY = r"E:\Temp\tbdig\_venv_pr_a\Scripts\python.exe"
OUT = r"E:\Temp\tbdig\canari\experiments\package_existence_repro\result.json"
rows = list(csv.DictReader(open(CSV_PATH, encoding="utf-8")))


def spread(items, n):
    if len(items) <= n:
        return items
    step = len(items) / n
    return [items[int(i * step)] for i in range(n)]


gone = spread([r for r in rows if r["status"] == "package-gone"], 20)
absent = spread([r for r in rows if r["status"] == "version-absent"], 20)


def npm_test(name, ver):
    d = tempfile.mkdtemp(prefix="npmrepro_")
    npm_exe = r"C:\Program Files\nodejs\npm.cmd"
    p = subprocess.run([npm_exe, "install", "%s@%s" % (name, ver), "--dry-run",
                        "--ignore-scripts", "--no-audit", "--no-fund",
                        "--prefix", d],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=180, shell=False)
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0:
        if re.search(r"\b404\b", out):
            return False, "404 not found"
        if "ETARGET" in out or "notarget" in out:
            return False, "ETARGET no matching version"
        return False, "other error"
    return True, "INSTALLED (unexpected)"


def pip_test(name, ver):
    d = tempfile.mkdtemp(prefix="piprepro_")
    p = subprocess.run([PY, "-m", "pip", "download", "%s==%s" % (name, ver),
                        "--no-deps", "--disable-pip-version-check", "-d", d],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=180, shell=False)
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0:
        if "No matching distribution" in out or "Could not find a version" in out:
            return False, "no matching distribution"
        return False, "other error"
    return True, "DOWNLOADED (unexpected)"


results = []
for label, batch in (("package-gone", gone), ("version-absent", absent)):
    for r in batch:
        reg = r["registry"]
        try:
            installed, msg = (npm_test if reg == "npm" else pip_test)(r["identifier"], r["version"])
        except Exception as e:
            installed, msg = None, "%s: %s" % (type(e).__name__, str(e)[:60])
        results.append({"expected": label, "registry": reg, "identifier": r["identifier"],
                        "version": r["version"], "installed_unexpectedly": installed,
                        "error": msg})
        print("%-14s %-5s %-42s %s" % (label, reg, r["identifier"][:42],
                                       "OK predicted failure" if installed is False else msg),
              flush=True)

summary = {}
for label in ("package-gone", "version-absent"):
    sub = [x for x in results if x["expected"] == label]
    reproduced = sum(1 for x in sub if x["installed_unexpectedly"] is False
                     and x["error"] != "other error")
    summary[label] = {"n": len(sub), "reproduced": reproduced,
                      "rate": round(reproduced / len(sub), 3) if sub else 0,
                      "unexpected_installs": sum(1 for x in sub if x["installed_unexpectedly"])}
os.makedirs(os.path.dirname(OUT), exist_ok=True)
json.dump({"csv": CSV_PATH, "summary": summary, "results": results},
          open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("\nSUMMARY", json.dumps(summary, ensure_ascii=False))
