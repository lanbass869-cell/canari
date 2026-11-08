# -*- coding: utf-8 -*-
"""npm_enum.py - M0 task 3: Top-50 MCP server enumeration from npm search.

API per docs/research/lineE (all first-hand verified there):
  GET https://registry.npmjs.org/-/v1/search?text=<query>&size=250&from=0
  - qualifiers go INSIDE text: "keywords:mcp-server", "scope:modelcontextprotocol"
  - size max 250
  - politeness: weekly cadence, unique UA, far below the 5M/month threshold

Local HTTP calls on this machine MUST bypass the system proxy (handover
section 4: default proxy 9480 returns 502). We use ProxyHandler({}) - the
stdlib way to force direct connection.
"""
import json
import urllib.request

UA = "canari-m0/0.1 (research enumeration; contact: repo issues)"
SEARCH_URL = "https://registry.npmjs.org/-/v1/search"

# npm MCP discovery queries (lineE section 1.1)
QUERIES = [
    "keywords:mcp-server",
    "keywords:model-context-protocol",
    "scope:modelcontextprotocol",
]


def _opener():
    # direct connection, bypass system proxy (handover env pitfall)
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def npm_search(text: str, size: int = 250, from_offset: int = 0, timeout: int = 30) -> dict:
    """One npm search call. Returns parsed JSON. Raises urllib errors."""
    url = "%s?text=%s&size=%d&from=%d" % (
        SEARCH_URL, urllib.parse.quote(text), size, from_offset)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with _opener().open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def enumerate_top(limit: int = 50, dedupe=True) -> list:
    """Enumerate MCP-related npm packages ranked by downloads (popularity).

    Returns list of dicts with the fields we need for a baseline meta scan:
      name, version, description, date, maintainers, downloads_monthly,
      links(npm/repo), score_detail.
    Sorted by downloads.desc per M0 task 3.
    """
    import urllib.parse  # noqa: F401 (used in npm_search)
    seen = {}
    for q in QUERIES:
        offset = 0
        while True:
            data = npm_search(q, size=250, from_offset=offset)
            objects = data.get("objects", [])
            if not objects:
                break
            for obj in objects:
                pkg = obj.get("package", {})
                name = pkg.get("name")
                if not name:
                    continue
                if dedupe and name in seen:
                    continue
                seen[name] = {
                    "name": name,
                    "version": pkg.get("version", ""),
                    "description": (pkg.get("description") or "")[:200],
                    "date": pkg.get("date", ""),
                    "maintainers": [m.get("name", "") for m in pkg.get("maintainers", [])],
                    "publisher": (pkg.get("publisher") or {}).get("username", ""),
                    "downloads_monthly": (obj.get("searchScore") and 0) or 0,
                    "score": obj.get("score", {}),
                    "downloads": obj.get("downloads", {}),
                    "links": pkg.get("links", {}),
                    "query_hit": q,
                }
            total = data.get("total", 0)
            offset += len(objects)
            if offset >= total or len(seen) >= limit * 3:
                break
    # rank by downloads (npm search returns objects sorted by searchScore which
    # folds in popularity; we re-rank explicitly by monthly downloads desc)
    ranked = sorted(seen.values(),
                    key=lambda x: -(x.get("downloads") or {}).get("monthly", 0))
    return ranked[:limit]


def fetch_packument(name: str, timeout: int = 90) -> dict:
    """Full packument (all versions metadata) for one package.
    Used to resolve dist.integrity (sha512) -> artifact_sha256 base."""
    url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="")
    # full packument (NOT abbreviated install-v1): abbreviated drops maintainers
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with _opener().open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def latest_version_info(packument: dict) -> dict:
    """Extract latest version's meta: dist.integrity (sha512), tarball, maintainers."""
    latest = (packument.get("dist-tags") or {}).get("latest", "")
    versions = packument.get("versions", {})
    v = versions.get(latest, {})
    return {
        "version": latest,
        "dist_integrity": (v.get("dist") or {}).get("integrity", ""),
        "tarball": (v.get("dist") or {}).get("tarball", ""),
        "maintainers": packument.get("maintainers", []),
        "deprecated": bool(v.get("deprecated")),
    }

