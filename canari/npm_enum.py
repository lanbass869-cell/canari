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


def npm_search_orig(text: str, size: int = 250, from_offset: int = 0, timeout: int = 30) -> dict:
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


def npm_search(text, size=250, from_offset=0, timeout=30, retries=3):
    import time
    for attempt in range(retries):
        try:
            return npm_search_orig(text, size, from_offset, timeout)
        except (urllib.error.HTTPError, TimeoutError, OSError) as e:
            if attempt < retries - 1:
                wait = 5 * (3 ** attempt)
                print("[npm] retry", attempt+1, "/", retries)
                time.sleep(wait)
            else:
                raise


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


# ============================================================
# PyPI adapter
# ============================================================
PYPI_SIMPLE = "https://pypi.org/simple"
PYPI_JSON = "https://pypi.org/pypi"

def pypi_enumerate(prefix="mcp-server-", limit=500):
    if limit <= 0:
        return []
    import re as _re
    url = PYPI_SIMPLE + "/"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    html = None
    for _attempt in range(3):
        try:
            with _opener().open(req, timeout=300) as r:
                html = r.read().decode("utf-8", errors="replace")
            break
        except (TimeoutError, OSError) as _e:
            if _attempt == 2:
                print("[pypi] simple index download failed after 3 attempts:", str(_e)[:80])
                return []  # failure is data, not crash
    if html is None:
        return []
    names = _re.findall(r'>(.*?)</a>', html)
    matched = [n for n in names if n.lower().startswith(prefix.lower())][:limit]
    results = []
    for name in matched:
        try:
            import time as _t
            _t.sleep(0.3)  # rate limit: ~200 req/min stays well under PyPI's threshold
            jurl = PYPI_JSON + "/" + urllib.parse.quote(name, safe="") + "/json"
            jreq = urllib.request.Request(jurl, headers={"User-Agent": UA})
            with _opener().open(jreq, timeout=30) as r2:
                d2 = json.loads(r2.read().decode("utf-8"))
            info = d2.get("info", {})
            dists = d2.get("urls", [])
            sha256 = dists[0]["digests"]["sha256"] if dists else ""
            results.append({"name": name, "version": info.get("version", ""),
                            "description": (info.get("summary") or "")[:200],
                            "registry": "pypi", "artifact_sha256": sha256,
                            "tarball": dists[0]["url"] if dists else "",
                            "maintainers": [info.get("author", "") or info.get("author_email", "")],
                            "links": {"homepage": info.get("home_page", "")}})
        except Exception as e:
            results.append({"name": name, "registry": "pypi", "error": str(e)[:100]})
    return results

# ============================================================
# MCP Registry adapter
# ============================================================
MCP_REGISTRY = "https://registry.modelcontextprotocol.io"

def mcp_registry_enumerate(limit=500):
    results = []
    cursor = ""
    while len(results) < limit:
        url = MCP_REGISTRY + "/v0/servers?limit=100"
        if cursor:
            url += "&cursor=" + urllib.parse.quote(cursor)
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with _opener().open(req, timeout=30) as r:
                d = json.loads(r.read().decode("utf-8"))
        except Exception as e:
            print("[registry] error:", str(e)[:80])
            break
        servers = d.get("servers", [])
        if not servers:
            break
        for s in servers:
            sname = s.get("name", "")
            if not sname:  # skip entries with no name (schema requires minLength=1)
                continue
            results.append({"name": sname, "version": s.get("version", ""),
                            "registry": "mcp-registry", "homepage": s.get("homepage", "")})
        cursor = d.get("next_cursor") or d.get("nextCursor") or ""
        if not cursor:
            break
    return results[:limit]

# ============================================================
# dsh.so adapter (reference conclusions, not re-scan)
# ============================================================
DSH_MARKET_INDEX = "https://cdn.dsh.so/market/index.json"
DSH_INSTALL_FMT = "https://dsh.so/data/install/@{author}/{name}.json"
DSH_SECURITY_FMT = "https://dsh.so/artifact/@{author}/{name}.json"


def dsh_enumerate(limit=500, with_security=True):
    if limit <= 0:
        return []
    """Enumerate DSH plugins from dsh.so market index (10K+).
    References existing L1-L5 conclusions, does not re-scan."""
    req = urllib.request.Request(DSH_MARKET_INDEX, headers={"User-Agent": UA})
    with _opener().open(req, timeout=60) as r:
        d = json.loads(r.read().decode("utf-8"))
    plugins = d.get("plugins", [])[:limit]
    results = []
    for p in plugins:
        name = p.get("name", "")
        if not name:  # skip entries with no name (schema requires minLength=1)
            continue
        author = p.get("author", "")
        versions = p.get("versions") or {}
        entry = {
            "name": name,
            "author": author,
            "version": versions.get("latest", "") if isinstance(versions, dict) else "",
            "registry": "dsh-registry",
            "repository": p.get("repository", ""),
        }
        if with_security and author and name:
            import time as _t
            _t.sleep(0.2)  # rate limit per-plugin calls
            try:
                iurl = DSH_INSTALL_FMT.format(author=author, name=name)
                ireq = urllib.request.Request(iurl, headers={"User-Agent": UA})
                with _opener().open(ireq, timeout=15) as r2:
                    idata = json.loads(r2.read().decode("utf-8"))
                it = idata.get("installTest", {})
                entry["install_level"] = it.get("level", "")
                entry["install_verdict"] = it.get("verdict", "")
                entry["install_state"] = it.get("state", "")
            except Exception:
                pass
            try:
                surl = DSH_SECURITY_FMT.format(author=author, name=name)
                sreq = urllib.request.Request(surl, headers={"User-Agent": UA})
                with _opener().open(sreq, timeout=15) as r3:
                    sdata = json.loads(r3.read().decode("utf-8"))
                entry["security_critical"] = (sdata.get("counts") or {}).get("critical", 0)
                entry["security_files_scanned"] = sdata.get("filesScanned", 0)
                entry["security_scanner"] = sdata.get("scannerVersion", "")
            except Exception:
                pass
        results.append(entry)
    return results


def propagate_revocation(revoked_name, revoked_author, all_components):
    from difflib import SequenceMatcher
    related = []
    for comp in all_components:
        cname = comp.get('name', '')
        if cname == revoked_name:
            continue
        if revoked_author and revoked_author in (comp.get('maintainers') or []):
            related.append({'name': cname, 'relation': 'same-author'})
            continue
        ratio = SequenceMatcher(None, revoked_name.lower(), cname.lower()).ratio()
        if ratio >= 0.85 and len(revoked_name) > 4:
            related.append({'name': cname, 'relation': 'name-variant'})
    return related
