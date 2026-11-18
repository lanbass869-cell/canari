"""What fraction of MCP-ish packages publish a repository?

Metadata-only: one packument / PyPI JSON per package, no tarball download, no
hashing. That is the cheap way to answer the coverage question the identity layer
depends on - if a package publishes no repository, no identity claim can ever
cover it.

    python repo_coverage.py [N]
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

from canari.baseline import repo_from_npm_packument, repo_from_pypi_doc  # noqa: E402
from canari.identity import build_clusters, find_conflicts, normalize_repo  # noqa: E402
from canari.npm_enum import UA, enumerate_top, pypi_enumerate  # noqa: E402

CACHE = os.path.join(ROOT, "out", "cache", "pypi-simple.html")


def _get(url, timeout=30, tries=3):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:
            last = "%s: %s" % (type(e).__name__, e)
            time.sleep(1.0 * (i + 1))
    return {"_err": last}


def npm_repo(name):
    return repo_from_npm_packument(
        _get("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")))


def pypi_repo(name):
    return repo_from_pypi_doc(
        _get("https://pypi.org/pypi/%s/json" % urllib.parse.quote(name)))


def run(n=200):
    t0 = time.time()
    print("enumerating npm ...", flush=True)
    npm = [p["name"] for p in enumerate_top(limit=n)]
    print("  npm candidates", len(npm), flush=True)
    print("enumerating pypi (cached simple index if present) ...", flush=True)
    cache = CACHE if os.path.exists(CACHE) else None
    pypi_rows = pypi_enumerate(limit=n, cache_path=cache)
    pypi = [(r.get("name") if isinstance(r, dict) else r) for r in pypi_rows]
    print("  pypi candidates", len(pypi), flush=True)

    with ThreadPoolExecutor(max_workers=8) as ex:
        npm_repos = list(ex.map(npm_repo, npm))
        pypi_repos = list(ex.map(pypi_repo, pypi))

    rows = []
    for reg, names, repos in (("npm", npm, npm_repos), ("pypi", pypi, pypi_repos)):
        for name, repo in zip(names, repos):
            rows.append({"registry": reg, "name": name, "repository": repo})

    def rate(reg):
        sub = [r for r in rows if r["registry"] == reg]
        have = [r for r in sub if r["repository"]]
        return {"candidates": len(sub), "with_repository": len(have),
                "rate": (len(have) / len(sub)) if sub else 0.0}

    records = [{"subject": {"registry": r["registry"], "name": r["name"],
                            "version": "", "repository": r["repository"]}}
               for r in rows if r["repository"]]
    built = build_clusters(records)
    conf = find_conflicts(records)
    out = {
        "as_of": time.strftime("%Y-%m-%d"),
        "requested": n,
        "elapsed_s": round(time.time() - t0, 1),
        "npm": rate("npm"), "pypi": rate("pypi"),
        "clusters": len(built["clusters"]),
        "monorepo_clusters": sum(1 for c in built["clusters"] if c["kind"] == "monorepo"),
        "cross_registry_clusters": sum(1 for c in built["clusters"]
                                       if len(c["registries"]) > 1),
        "name_collision": len(conf["name_collision"]),
        "repo_changed": len(conf["repo_changed"]),
        "without_repository_examples": [r["name"] for r in rows if not r["repository"]][:15],
        "rows": rows,
    }
    with open(os.path.join(HERE, "repo_coverage.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in out.items() if k != "rows"}, ensure_ascii=False,
                     indent=1))


if __name__ == "__main__":
    run(int(sys.argv[1]) if len(sys.argv) > 1 else 200)
