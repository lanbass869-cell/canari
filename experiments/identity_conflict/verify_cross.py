"""For each bare name that exists on both npm and PyPI, ask whether the two
packages are the same project. The repository URL is the strongest cheap signal:
same repo = same component, different repos = two unrelated projects wearing the
same name.

    python verify_cross.py [N]

Writes cross_registry.json. Read-only network calls, no installs.
"""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
UA = "canari-identity-probe/1.0 (+https://github.com/lanbass869-cell/canari)"


def _get(url, timeout=25, tries=3):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:
            last = "%s: %s" % (type(e).__name__, e)
            time.sleep(1.5 * (i + 1))
    return {"_err": last}


def _norm_repo(url):
    if not url:
        return None
    u = str(url).strip().lower()
    u = re.sub(r"^git\+", "", u)
    u = u.replace("git://", "https://").replace("ssh://git@", "https://")
    u = re.sub(r"^git@([^:]+):", r"https://\1/", u)
    u = re.sub(r"\.git$", "", u)
    u = u.rstrip("/")
    m = re.search(r"(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)/"
                  r"([^/]+)/([^/#?]+)", u)
    if m:
        return "%s/%s/%s" % (m.group(1), m.group(2), m.group(3))
    return u or None


def probe(name):
    npm = _get("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
    pypi = _get("https://pypi.org/pypi/%s/json" % urllib.parse.quote(name))
    out = {"name": name}
    if "_err" in npm or not isinstance(npm, dict) or "dist-tags" not in npm:
        out["npm_ok"] = False
    else:
        out["npm_ok"] = True
        latest = (npm.get("dist-tags") or {}).get("latest")
        out["npm_version"] = latest
        out["npm_repo"] = _norm_repo(((npm.get("repository") or {}) or {}).get("url")
                                     if isinstance(npm.get("repository"), dict)
                                     else npm.get("repository"))
        out["npm_repo_field"] = (npm.get("repository") if isinstance(npm.get("repository"), dict)
                                 else {"url": npm.get("repository")})
        out["npm_maintainers"] = [m.get("name") for m in (npm.get("maintainers") or [])
                                  if isinstance(m, dict)]
    if "_err" in pypi or not isinstance(pypi, dict) or "info" not in pypi:
        out["pypi_ok"] = False
    else:
        out["pypi_ok"] = True
        info = pypi.get("info") or {}
        out["pypi_version"] = info.get("version")
        proj = info.get("project_urls") or {}
        repo = ""
        for k, v in proj.items():
            if "repo" in (k or "").lower() or "source" in (k or "").lower() or "code" in (k or "").lower():
                repo = v or repo
        out["pypi_repo"] = _norm_repo(repo)
        out["pypi_repo_field"] = {"project_urls": proj,
                                  "home_page": info.get("home_page")}
        out["pypi_author"] = info.get("author") or info.get("author_email") or ""
    return out


def classify(row):
    if not row.get("npm_ok") or not row.get("pypi_ok"):
        return "not-both-live"
    a, b = row.get("npm_repo"), row.get("pypi_repo")
    if not a or not b:
        return "no-repo-url"
    return "same-repo" if a == b else "different-repo"


if __name__ == "__main__":
    res = json.load(open(os.path.join(HERE, "result.json"), encoding="utf-8"))
    names = sorted(res["all_cross_registry"])
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    if limit:
        names = names[:limit]
    print("probing", len(names), "names ...", flush=True)
    with ThreadPoolExecutor(max_workers=8) as ex:
        rows = list(ex.map(probe, names))
    for r in rows:
        r["class"] = classify(r)
    counts = {}
    for r in rows:
        counts[r["class"]] = counts.get(r["class"], 0) + 1
    out = {"as_of": res["as_of"], "probed": len(rows), "class_counts": counts,
           "rows": rows}
    with open(os.path.join(HERE, "cross_registry.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps(counts, indent=1))
    for r in rows[:12]:
        print(" -", r["name"], r["class"], r.get("npm_repo"), "|", r.get("pypi_repo"))
