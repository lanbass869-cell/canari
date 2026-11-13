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
import urllib.error
import urllib.parse
import urllib.request

UA = "canari-m0/0.1 (research enumeration; contact: repo issues)"
SEARCH_URL = "https://registry.npmjs.org/-/v1/search"

# npm MCP discovery queries.
#
# NOTE (2026-11-12, measured): npm's search backend does NOT implement the
# "scope:" qualifier - `scope:modelcontextprotocol` returns total=0, so this
# query had been silently contributing nothing while the official head packages
# (@modelcontextprotocol/server-filesystem, .../server-everything, .../server)
# were missing from the ledger entirely. Searching the bare scope string works
# (total=4493) and surfaces them. Queries are cumulative: a package found by any
# query is kept.
QUERIES = [
    "keywords:mcp-server",
    "keywords:model-context-protocol",
    "@modelcontextprotocol",
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
                    "downloads_monthly": (obj.get("downloads") or {}).get("monthly", 0),
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
TOP_PYPI_JSON = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
PYPI_JSON = "https://pypi.org/pypi"

def fetch_simple_index(cache_path=None, ttl_hours=24, max_bytes=80 * 1024 * 1024,
                       timeout=120, total_budget_s=120):
    """Return the PyPI simple index HTML, or None.

    Cache policy (changed 2026-11-13 after measuring the real failure):
      - fresh cache  -> use it, no network
      - stale cache  -> try to refresh ONCE with a SHORT budget, and if the
                        refresh fails fall back to the stale file. The index is
                        only used to enumerate project NAMES; a day-old name list
                        is far more useful than a 10-minute stall followed by a
                        fallback to a 8K popularity slice.
      - no cache     -> try once, then return None so callers use the fallback.

    Measured on this machine: pypi.org/simple is ~49MB and a full read took
    >600s repeatedly (throttled link), which previously burned 10 minutes at
    the start of EVERY scan before silently degrading.
    """
    import os as _os
    import time as _t

    stale = None
    fresh = False
    if cache_path:
        try:
            if _os.path.exists(cache_path):
                with open(cache_path, "r", encoding="utf-8", errors="replace") as f:
                    stale = f.read()
                age_h = (_t.time() - _os.path.getmtime(cache_path)) / 3600.0
                fresh = age_h < ttl_hours
                if fresh:
                    print("[pypi] simple index from cache (%.1fh old): %s" % (age_h, cache_path))
                    return stale
                print("[pypi] cached index is %.1fh old; refreshing with a %ds budget"
                      % (age_h, total_budget_s))
        except OSError:
            stale = None

    html = None
    over_cap = False
    deadline = _t.time() + total_budget_s
    for attempt in range(2):
        try:
            req = urllib.request.Request(PYPI_SIMPLE + "/", headers={"User-Agent": UA})
            with _opener().open(req, timeout=timeout) as r:
                chunks, size = [], 0
                while True:
                    if _t.time() > deadline:
                        raise TimeoutError("simple index read exceeded %ds budget" % total_budget_s)
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    # NOTE: do NOT stop at max_bytes. A truncated simple index
                    # loses the alphabetical tail, which is exactly the bug we
                    # are fixing (mcp-server-fetch was beyond the cut). The cap
                    # only guards against runaway streams, so we keep draining
                    # until EOF and report if we exceeded it.
                    if size >= max_bytes:
                        over_cap = True
                html = b"".join(chunks).decode("utf-8", errors="replace")
            break
        except Exception as e:
            if attempt == 1:
                print("[pypi] simple index refresh failed:", str(e)[:80])

    if html is not None:
        if cache_path:
            try:
                _os.makedirs(_os.path.dirname(cache_path) or ".", exist_ok=True)
                with open(cache_path, "w", encoding="utf-8") as f:
                    f.write(html)
            except OSError:
                pass
        if over_cap:
            print("[pypi] simple index exceeded the %d-byte cap (%d bytes read); "
                  "keeping the whole body so the name list stays complete"
                  % (max_bytes, len(html)))
        return html

    if stale is not None:
        print("[pypi] falling back to the STALE cached index (%d bytes) - "
              "enumeration stays possible, freshness is degraded" % len(stale))
        return stale
    return None


def _stratified_pick(sorted_names, limit, what=""):
    """Pick `limit` items spread across the WHOLE sorted list, deterministically.

    Why not sorted_names[:limit]: PyPI's simple index is alphabetical, so a
    plain prefix truncation systematically keeps 'a...' packages and silently
    drops the rest. Measured 2026-11-12: 620 packages match "mcp-server-", the
    old code kept the first 100 (stopping at mcp-server-dagster) and
    mcp-server-fetch - position 177 - had never been scanned. That is a coverage
    bug hidden behind a "sample" story, so:
      - selection is evenly spaced across the full alphabet (deterministic,
        reproducible, no random seed needed)
      - the number dropped is always printed, never silent
    """
    n = len(sorted_names)
    if limit <= 0:
        return []
    if n <= limit:
        # Full coverage: every matching package is scanned. The limit is a
        # safety cap, not a target - the old behaviour treated it as a target
        # and silently cut the alphabetical tail.
        return list(sorted_names)
    step = n / float(limit)
    picked = [sorted_names[int(i * step)] for i in range(limit)]
    # de-dup while preserving order (int() can collide on tiny n/limit ratios)
    seen, out = set(), []
    for x in picked:
        if x not in seen:
            seen.add(x)
            out.append(x)
    print("[%s] %d candidates, keeping %d spread across the alphabet, dropping %d"
          % (what or "pick", n, len(out), n - len(out)))
    return out


PYPI_META_WORKERS = 8


def _fetch_one_pypi_meta(name, retries=2):
    """Fetch one project's JSON metadata. Returns a result dict; never raises.

    Retries on transport failures only. A 404 is a real answer (the project is
    gone / renamed) and is returned as an error without retrying - otherwise
    every delisted name would cost 3x the timeout.
    """
    uri = PYPI_JSON + "/" + urllib.parse.quote(name, safe="") + "/json"
    last = None
    for attempt in range(max(1, retries)):
        try:
            jreq = urllib.request.Request(uri, headers={"User-Agent": UA})
            with _opener().open(jreq, timeout=60) as r2:
                d2 = json.loads(r2.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"name": name, "registry": "pypi",
                        "error": "HTTP 404: project not found"}
            last = e
            if attempt + 1 < retries:
                import time as _t
                _t.sleep(2 + attempt * 3)
        except Exception as e:                                # noqa: BLE001
            last = e
            if attempt + 1 < retries:
                import time as _t
                _t.sleep(2 + attempt * 3)
    else:
        return {"name": name, "registry": "pypi", "error": str(last)[:100]}
    try:
        info = d2.get("info", {})
        dists = d2.get("urls", [])
        sha256 = dists[0]["digests"]["sha256"] if dists else ""
        return {"name": name, "version": info.get("version", ""),
                "description": (info.get("summary") or "")[:200],
                "registry": "pypi", "artifact_sha256": sha256,
                "tarball": dists[0]["url"] if dists else "",
                "maintainers": [info.get("author", "") or info.get("author_email", "")],
                "links": {"homepage": info.get("home_page", "")},
                "_json": d2}
    except Exception as e:                                    # noqa: BLE001
        return {"name": name, "registry": "pypi", "error": str(e)[:100]}


def _fetch_pypi_meta_bulk(names, workers=None):
    """Fetch PyPI metadata for many projects with bounded concurrency.

    The per-project request takes 12-50s on this link. Strictly serial, that is
    620 x ~30s = 5+ hours for the mcp-server-* cohort - measured 2026-11-13.
    With 8 workers it is ~40 minutes, still far below PyPI's documented rate
    limits (their guidance is about sustained load, not concurrency per se; each
    worker issues one request at a time with no retry storm).

    `workers=1` reproduces the old serial behaviour, which the tests use.
    """
    w = max(1, int(workers if workers is not None else PYPI_META_WORKERS))
    if w == 1 or len(names) <= 1:
        out = []
        for n in names:
            out.append(_fetch_one_pypi_meta(n))
        return out
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=w) as pool:
        return list(pool.map(_fetch_one_pypi_meta, names))


def pypi_enumerate(prefix="mcp-server-", limit=5000, cache_path=None):
    if limit <= 0:
        return []
    import re as _re
    html = fetch_simple_index(cache_path=cache_path)
    if html is None:
        # fallback: static top-pypi-packages dataset (top 8K by downloads).
        # Failure is still data, never a crash.
        try:
            fb = urllib.request.Request(TOP_PYPI_JSON, headers={"User-Agent": UA})
            with _opener().open(fb, timeout=60) as r:
                data = json.loads(r.read().decode("utf-8"))
            rows = data.get("rows", data) if isinstance(data, dict) else data
            names = [row.get("project", "") for row in rows if isinstance(row, dict)]
            cand = [n for n in names if n and n.lower().startswith(prefix.lower())]
            if not cand:
                cand = [n for n in names if n]
            # top-pypi-packages is already ordered by downloads desc, so the
            # head of this list is the most-used subset - truncation is honest.
            if len(cand) > limit:
                print("[pypi] fallback dataset: keeping top %d of %d by download rank"
                      % (limit, len(cand)))
            matched = cand[:limit]
            results = []
            for name in matched:
                try:
                    import time as _t
                    _t.sleep(0.2)
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
                                    "links": {"homepage": info.get("home_page") or ""}})
                except Exception as e:
                    results.append({"name": name, "registry": "pypi", "error": str(e)[:100]})
            print("[pypi] fallback dataset produced %d candidates" % len(results))
            return results
        except Exception as _e2:
            print("[pypi] fallback dataset failed too:", str(_e2)[:80])
            return []
    names = _re.findall(r'>(.*?)</a>', html)
    all_matched = sorted({n for n in names if n.lower().startswith(prefix.lower())})
    matched = _stratified_pick(all_matched, limit, what="pypi:" + prefix)
    return _fetch_pypi_meta_bulk(matched)

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
            server = s.get("server", s)  # real API nests under "server" key; fallback for flat
            sname = server.get("name", "")
            if not sname:  # skip entries with no name (schema requires minLength=1)
                continue
            results.append({"name": sname, "version": server.get("version", ""),
                            "registry": "mcp-registry", "homepage": server.get("homepage", "")})
        cursor = (d.get("metadata") or {}).get("nextCursor") or d.get("next_cursor") or d.get("nextCursor") or ""
        if not cursor:
            break
    # BUG-78: registry pages contain one record per server VERSION. The ledger
    # tracks components, so keep the highest version per name (last seen wins on
    # unparseable versions) instead of emitting N bundles for the same component.
    best = {}
    for r in results:
        key = r["name"]
        prev = best.get(key)
        if prev is None or _version_key(r.get("version", "")) >= _version_key(prev.get("version", "")):
            best[key] = r
    return list(best.values())[:limit]


def _version_key(v):
    import re as _re
    parts = _re.findall(r"\d+", v or "")
    return tuple(int(x) for x in parts[:6]) if parts else (-1,)

# ============================================================
# dsh.so adapter (reference conclusions, not re-scan)
# ============================================================
DSH_MARKET_INDEX = "https://cdn.dsh.so/market/index.json"
DSH_INSTALL_FMT = "https://dsh.so/data/install/@{author}/{name}.json"
DSH_SECURITY_FMT = "https://dsh.so/artifact/@{author}/{name}.json"


def dsh_enumerate(limit=500, with_security=True, names=None):
    """Enumerate DSH plugins from dsh.so market index (10K+).
    References existing L1-L5 conclusions, does not re-scan.

    limit : take the first ``limit`` entries of the index (rank order).
    names : when given, ignore ``limit`` and return only these exact names.
            This is what the weekly refresh uses - it re-checks the components
            already in our ledger instead of a shifting prefix of the index.
    """
    if not names and limit <= 0:
        return []
    req = urllib.request.Request(DSH_MARKET_INDEX, headers={"User-Agent": UA})
    with _opener().open(req, timeout=60) as r:
        d = json.loads(r.read().decode("utf-8"))
    plugins = d.get("plugins", [])
    if names:
        wanted = set(names)
        plugins = [p for p in plugins if p.get("name") in wanted]
    else:
        plugins = plugins[:limit]
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
        if ratio >= 0.90 and len(revoked_name) > 4:
            related.append({'name': cname, 'relation': 'name-variant'})
    return related
