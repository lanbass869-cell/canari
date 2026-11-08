# -*- coding: utf-8 -*-
"""baseline.py - M0 task 3: Top-50 baseline scan -> 50 signed attestations + feed.

One run produces:
  attestations/<n>_<safe-name>.bundle.json   (signed DSSE bundle)
  feed/feed-<date>.json                      (public machine-readable feed)
  baseline_report.json                       (run summary incl. failure counts)

L-level per plan section 5.2: this baseline is META-ONLY (L1/L2).
META-ONLY = no code execution. Tarball DOWNLOAD for hash computation is
byte-level fetch (not execution) and is required for schema-valid
artifact_sha256 binding. L3+ behavioral checks stay out of M0.
  L1.1_REGISTRY_PRESENT      - packument fetchable
  L1.2_VERSION_RESOLVED      - dist-tags.latest exists
  L2.1_ARTIFACT_HASH         - dist.integrity present (sha512 -> record; sha256 field
                               stays empty unless we download the tarball, which M0
                               does NOT do - honesty: unsupported, not pass)
  L2.2_MAINTAINER_SET        - maintainers non-empty
  L2.3_MANIFEST_FIELDS       - description/homepage present
Checks that REQUIRE running the package are NOT in this baseline (M1).
"""
import datetime
import hashlib
import json
import os
import sys

from canari.schema import _PREDICATE_TYPE
from canari.signing import generate_keypair, sign_attestation, export_public_key
from canari.state import FileLock, StateStore
from canari.npm_enum import (enumerate_top, fetch_packument, latest_version_info,
                            pypi_enumerate, mcp_registry_enumerate, dsh_enumerate)

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(HERE, "out")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _expiry():
    return (datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha512_integrity_to_hex(integrity: str):
    """npm integrity format: 'sha512-<base64>'. Return hex digest or None."""
    if not integrity or not integrity.startswith("sha512-"):
        return None
    import base64
    try:
        raw = base64.b64decode(integrity.split("-", 1)[1], validate=True)
        h = raw.hex()
        return h if len(h) == 128 else None
    except Exception:
        return None




def _download_sha256(tarball_url: str, timeout: int = 60):
    """Download tarball bytes and compute sha256. NO code execution - this is
    byte-level fetch (same trust class as sentinel audit-install's fetch step).
    Returns hex digest or None. Failure is data, not crash."""
    if not tarball_url:
        return None
    try:
        import urllib.request
        req = urllib.request.Request(tarball_url, headers={"User-Agent": UA_CONST})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as r:
            h = hashlib.sha256()
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


UA_CONST = "canari-m0/0.1 (research; repo issues)"


def build_attestation(name: str, meta: dict, search_meta: dict, scenario_sha256: str) -> dict:
    """Build one meta-only attestation for one component."""
    checks = []
    # L1.1 packument fetchable = we got here
    checks.append({"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass",
                   "tool": "canari-meta/0.1", "duration_ms": meta.get("fetch_ms", 0)})
    # L1.2 version resolved
    if meta.get("version"):
        checks.append({"id": "L1.2_VERSION_RESOLVED", "verdict": "pass",
                       "tool": "canari-meta/0.1"})
    else:
        checks.append({"id": "L1.2_VERSION_RESOLVED", "verdict": "fail",
                       "tool": "canari-meta/0.1"})
    # L2.1 artifact hash: download the tarball (byte fetch, NO execution) and
    # compute sha256. Schema REQUIRES a valid 64-hex artifact_sha256, and an
    # attestation that does not bind to exact bytes is worthless anyway.
    # Cross-check: our sha256 vs npm's published sha512 - if npm's integrity
    # exists we also record it as corroborating evidence.
    sha512_hex = _sha512_integrity_to_hex(meta.get("dist_integrity", ""))
    sha256_hex = None
    for _dl in range(2):  # CDN throttle: one retry after brief pause
        sha256_hex = _download_sha256(meta.get("tarball", ""), timeout=120)
        if sha256_hex:
            break
        import time as _t
        _t.sleep(2)
    if sha256_hex:
        ev = "sha256 computed from tarball download"
        if sha512_hex:
            ev += "; npm packument sha512:" + sha512_hex[:16] + "..."
        checks.append({"id": "L2.1_ARTIFACT_HASH", "verdict": "pass",
                       "tool": "canari-meta/0.1", "evidence_ref": ev})
    elif sha512_hex:
        # download failed but npm publishes integrity - we cannot confirm
        # sha256 ourselves; schema forbids empty/invalid, so this check fails
        checks.append({"id": "L2.1_ARTIFACT_HASH", "verdict": "fail",
                       "tool": "canari-meta/0.1",
                       "evidence_ref": "tarball download failed; npm sha512:" + sha512_hex[:16]})
    else:
        checks.append({"id": "L2.1_ARTIFACT_HASH", "verdict": "fail",
                       "tool": "canari-meta/0.1",
                       "evidence_ref": "no dist.integrity in packument and download failed"})
    # L2.2 maintainers
    if meta.get("maintainers"):
        checks.append({"id": "L2.2_MAINTAINER_SET", "verdict": "pass",
                       "tool": "canari-meta/0.1"})
    else:
        checks.append({"id": "L2.2_MAINTAINER_SET", "verdict": "fail",
                       "tool": "canari-meta/0.1"})
    has_desc = bool(search_meta.get("description"))
    # L2.3 manifest fields - check-level enum has no 'pass-with-findings';
    # a missing description is a finding recorded via evidence_ref, check
    # stays pass, and the RUN verdict becomes pass-with-findings.
    if has_desc:
        checks.append({"id": "L2.3_MANIFEST_FIELDS", "verdict": "pass",
                       "tool": "canari-meta/0.1"})
    else:
        checks.append({"id": "L2.3_MANIFEST_FIELDS", "verdict": "pass",
                       "tool": "canari-meta/0.1",
                       "evidence_ref": "finding: description empty"})

    n_fail = sum(1 for c in checks if c["verdict"] == "fail")
    n_unsup = sum(1 for c in checks if c["verdict"] == "unsupported")
    n_fail = sum(1 for c in checks if c["verdict"] == "fail")
    n_unsup = sum(1 for c in checks if c["verdict"] == "unsupported")
    if n_fail:
        verdict = "fail"
    elif n_unsup == len(checks):
        verdict = "unsupported"
    else:
        has_findings = any(
            c["verdict"] != "pass" or (c.get("evidence_ref") or "").startswith("finding:")
            for c in checks)
        verdict = "pass-with-findings" if has_findings else "pass"

    return {
        "_type": _PREDICATE_TYPE,
        "subject": {
            "name": name,
            "version": meta.get("version", ""),
            "registry": "npm",
            "artifact_sha256": sha256_hex or "0" * 64,  # schema requires valid hex; all-zero = download failed (check FAIL records it)
            "homepage": (search_meta.get("links") or {}).get("homepage", ""),
            "maintainers": meta.get("maintainers", []),
        },
        "host": {"class": "mcp", "host_version": "registry-meta-v1"},
        "scenario_sha256": scenario_sha256,
        "checks": checks,
        "verdict": verdict,
        "checker": {"kind": "automation", "id": "canari-m0", "tools": ["canari-meta/0.1"]},
        "evidence_refs": ["npm-packument:" + name],
        "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
        "expires_at": _expiry(),
        "generated_at": _now(),
        "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": _PREDICATE_TYPE},
    }


def run(limit: int = 50, signer=None, pub_key=None, out_dir: str = None) -> dict:
    """Full M0 baseline run. Returns summary dict."""
    out_dir = out_dir or OUT_DIR
    att_dir = os.path.join(out_dir, "attestations")
    feed_dir = os.path.join(out_dir, "feed")
    os.makedirs(att_dir, exist_ok=True)
    os.makedirs(feed_dir, exist_ok=True)
    lock = FileLock(os.path.join(out_dir, "run"))
    lock.__enter__()
    state = StateStore(os.path.join(out_dir, "state.json"))

    if signer is None:
        signer, pub_key = generate_keypair()

    # scenario hash: the check-list definition itself (L1.1..L2.3 meta-only)
    scenario_def = json.dumps({
        "level": "L1-L2-meta-only",
        "checks": ["L1.1_REGISTRY_PRESENT", "L1.2_VERSION_RESOLVED",
                   "L2.1_ARTIFACT_HASH", "L2.2_MAINTAINER_SET", "L2.3_MANIFEST_FIELDS"],
        "runner": "canari-m0/0.1",
    }, sort_keys=True).encode("utf-8")
    scenario_sha256 = hashlib.sha256(scenario_def).hexdigest()

    print("[baseline] enumerating npm MCP packages (limit=%d)..." % limit)
    top = enumerate_top(limit=limit)
    print("[baseline] got %d candidates" % len(top))

    results = []
    n_err = n_skip = 0
    for i, pkg in enumerate(top):
        name = pkg["name"]
        safe = name.replace("/", "_").replace("@", "")
        pack = None
        for attempt in range(3):
            try:
                pack = fetch_packument(name)
                break
            except Exception as e2:
                if attempt == 2:
                    raise
        try:
            lv = latest_version_info(pack)
            meta = {"version": lv["version"], "dist_integrity": lv["dist_integrity"],
                    "tarball": lv["tarball"],
                    "maintainers": [m.get("name", "") for m in (lv["maintainers"] or [])]
                    if isinstance(lv["maintainers"], list) else [],
                    "fetch_ms": 0}
        except Exception as e:
            # failure is DATA (dead-letter audit), never silent
            n_err += 1
            print("  [%02d] %-44s FETCH-ERROR %s" % (i + 1, name, str(e)[:60]))
            results.append({"name": name, "status": "fetch_error", "error": str(e)[:200]})
            continue
        import time as _t
        _t.sleep(1)  # politeness: npm CDN throttles rapid sequential tarball fetches
        att = build_attestation(name, meta, pkg, scenario_sha256)
        signed = sign_attestation(att, signer)
        bundle_path = os.path.join(att_dir, "%02d_%s.bundle.json" % (i + 1, safe))
        with open(bundle_path, "w", encoding="utf-8") as f:
            json.dump({"envelope": signed["envelope"], "payload": signed["payload"]},
                      f, ensure_ascii=False, indent=1)
        results.append({"name": name, "version": meta.get("version", ""),
                        "verdict": att["verdict"], "bundle": bundle_path})
        print("  [%02d] %-44s %-18s %s" % (i + 1, name, meta.get("version", "?"), att["verdict"]))

    # public feed
    feed = {
        "feed_version": 1,
        "generated_at": _now(),
        "scenario_sha256": scenario_sha256,
        "count": len([r for r in results if r.get("status") != "fetch_error"]),
        "fetch_errors": n_err,
        "verdicts": {v: sum(1 for r in results if r.get("verdict") == v)
                     for v in ("pass", "pass-with-findings", "fail", "unsupported")},
        "items": [{"name": r["name"], "version": r.get("version", ""),
                   "verdict": r.get("verdict"), "status": r.get("status", "ok"),
                   "bundle_file": os.path.basename(r["bundle"]) if r.get("bundle") else None}
                  for r in results],
    }
    feed_path = os.path.join(feed_dir, "feed-%s.json"
                             % datetime.date.today().strftime("%Y%m%d"))
    with open(feed_path, "w", encoding="utf-8") as f:
        json.dump(feed, f, ensure_ascii=False, indent=1)

    # public key export - ALWAYS overwrite: the keypair regenerates per run,
    # a stale key file would make every bundle verify as FAIL (found in the
    # real M0 run: run-2 bundles vs run-1 key -> UnverifiedSignatureError).
    # Operator persistence = copy this file elsewhere, not rely on skip-if-exists.
    key_path = os.path.join(out_dir, "public_key.json")
    with open(key_path, "w", encoding="utf-8") as f:
        f.write(export_public_key(pub_key))

    # diff vs previous run + persist state
    current_snapshot = {}
    for r in results:
        if r.get("bundle") and r.get("status") != "fetch_error":
            bp = json.load(open(r["bundle"], encoding="utf-8"))
            sha = bp["payload"]["subject"].get("artifact_sha256", "")
            current_snapshot[r["name"]] = {"version": r.get("version", ""), "sha256": sha}

    diff = state.diff(current_snapshot)
    print("[diff] new=%d changed=%d unchanged=%d removed=%d" % (
        len(diff["new"]), len(diff["changed"]), len(diff["unchanged"]), len(diff["removed"])))

    for r in results:
        if r.get("bundle"):
            bp = json.load(open(r["bundle"], encoding="utf-8"))
            state.set_component(r["name"], r.get("version", ""),
                                bp["payload"]["subject"].get("artifact_sha256", ""), r["bundle"])
    state.save()
    lock.__exit__()

    summary = {"total": len(results), "diff": diff, "run_number": state.run_count,
               "fetch_errors": n_err, "skipped": n_skip,
               "feed": feed_path, "key": key_path, "results": results}
    report_path = os.path.join(out_dir, "baseline_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print("[baseline] done: %d attested, %d fetch-errors | feed=%s" % (
        len(results) - n_err, n_err, feed_path))
    return summary


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="canari-baseline",
                                 description="M0 Top-50 npm MCP baseline scan")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--out", default=None, help="output dir (default: <repo>/out)")
    a = ap.parse_args(argv)
    run(limit=a.limit, out_dir=a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())




def run_multi(npm_limit=200, pypi_limit=200, registry_limit=200, dsh_limit=100,
              signer=None, pub_key=None, out_dir=None):
    """Multi-registry scan: npm + PyPI + MCP Registry + dsh.so -> unified attestations + feed."""
    out_dir = out_dir or OUT_DIR
    att_dir = os.path.join(out_dir, "attestations")
    feed_dir = os.path.join(out_dir, "feed")
    os.makedirs(att_dir, exist_ok=True)
    os.makedirs(feed_dir, exist_ok=True)
    if signer is None:
        signer, pub_key = generate_keypair()

    scenario_def = json.dumps({"level": "L1-L2-multi-registry",
                               "registries": ["npm", "pypi", "mcp-registry", "dsh-registry"]},
                              sort_keys=True).encode("utf-8")
    scenario_sha256 = hashlib.sha256(scenario_def).hexdigest()
    all_results = []
    total_errors = 0

    def _make_att(name, version, registry, sha, host_class, checks, verdict, tools, ev_refs):
        return {"_type": _PREDICATE_TYPE,
                "subject": {"name": name, "version": version, "registry": registry,
                            "artifact_sha256": sha or "0" * 64, "maintainers": []},
                "host": {"class": host_class, "host_version": "registry-meta-v1"},
                "scenario_sha256": scenario_sha256, "checks": checks, "verdict": verdict,
                "checker": {"kind": "automation", "id": "canari-m1", "tools": tools},
                "evidence_refs": ev_refs,
                "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
                "expires_at": _expiry(), "generated_at": _now(),
                "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": _PREDICATE_TYPE}}

    def _save_att(att, prefix, name):
        signed = sign_attestation(att, signer)
        safe = name.replace("/", "_").replace("@", "")
        bpath = os.path.join(att_dir, "%s_%s.bundle.json" % (prefix, safe))
        with open(bpath, "w", encoding="utf-8") as f:
            json.dump({"envelope": signed["envelope"], "payload": signed["payload"]}, f, ensure_ascii=False)
        return bpath

    # npm
    print("[multi] npm (%d)..." % npm_limit)
    for pkg in enumerate_top(limit=npm_limit):
        name = pkg["name"]
        try:
            pack = fetch_packument(name)
            lv = latest_version_info(pack)
            sha = _download_sha256(lv["tarball"], timeout=120)
            checks = [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "canari-m1/0.1"},
                      {"id": "L2.1_ARTIFACT_HASH", "verdict": "pass" if sha else "fail", "tool": "canari-m1/0.1"}]
            verdict = "pass" if sha else "fail"
            att = _make_att(name, lv["version"], "npm", sha, "mcp", checks, verdict,
                            ["canari-m1/0.1"], ["npm-packument:" + name])
            bpath = _save_att(att, "npm", name)
            all_results.append({"name": name, "registry": "npm", "version": lv["version"],
                                "verdict": verdict, "bundle": bpath})
        except Exception as e:
            total_errors += 1
            all_results.append({"name": name, "registry": "npm", "status": "error"})

    # PyPI
    print("[multi] PyPI (%d)..." % pypi_limit)
    for pkg in pypi_enumerate(limit=pypi_limit):
        name = pkg["name"]
        if "error" in pkg:
            total_errors += 1
            continue
        sha = pkg.get("artifact_sha256", "")
        checks = [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "canari-m1/0.1"},
                  {"id": "L2.1_ARTIFACT_HASH", "verdict": "pass" if sha else "fail", "tool": "canari-m1/0.1"}]
        att = _make_att(name, pkg.get("version", ""), "pypi", sha, "mcp", checks,
                        "pass" if sha else "fail", ["canari-m1/0.1"], ["pypi-json:" + name])
        bpath = _save_att(att, "pypi", name)
        all_results.append({"name": name, "registry": "pypi", "version": pkg.get("version", ""),
                            "verdict": att["verdict"], "bundle": bpath})

    # MCP Registry
    print("[multi] MCP Registry (%d)..." % registry_limit)
    for pkg in mcp_registry_enumerate(limit=registry_limit):
        name = pkg["name"]
        att = _make_att(name, pkg.get("version", ""), "npm", "", "mcp",
                        [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "canari-m1/0.1"}],
                        "pass-with-findings", ["canari-m1/0.1"], ["mcp-registry:" + name])
        bpath = _save_att(att, "mcpreg", name)
        all_results.append({"name": name, "registry": "mcp-registry", "version": pkg.get("version", ""),
                            "verdict": "pass-with-findings", "bundle": bpath})

    # dsh.so (reference, not re-scan)
    print("[multi] dsh.so (%d)..." % dsh_limit)
    for pkg in dsh_enumerate(limit=dsh_limit):
        name = pkg.get("name", "")
        att = _make_att(name, pkg.get("version", ""), "dsh-registry", "", "dsh-plugin",
                        [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "dsh-so-ref/0.1"}],
                        "pass-with-findings", ["dsh-so-referenced"], ["dsh-so:" + name])
        bpath = _save_att(att, "dsh", name)
        all_results.append({"name": name, "registry": "dsh-registry", "version": pkg.get("version", ""),
                            "verdict": "pass-with-findings", "bundle": bpath})

    # unified feed
    by_reg, by_verdict = {}, {}
    for r in all_results:
        by_reg[r.get("registry", "?")] = by_reg.get(r.get("registry", "?"), 0) + 1
        v = r.get("verdict", "error")
        by_verdict[v] = by_verdict.get(v, 0) + 1
    feed = {"feed_version": 2, "generated_at": _now(), "scenario_sha256": scenario_sha256,
            "total": len(all_results), "errors": total_errors,
            "by_registry": by_reg, "by_verdict": by_verdict,
            "items": [{"name": r["name"], "registry": r.get("registry", ""),
                       "version": r.get("version", ""), "verdict": r.get("verdict", "error")}
                      for r in all_results]}
    feed_path = os.path.join(feed_dir, "feed-multi-%s.json" % datetime.date.today().strftime("%Y%m%d"))
    with open(feed_path, "w", encoding="utf-8") as f:
        json.dump(feed, f, ensure_ascii=False, indent=1)
    key_path = os.path.join(out_dir, "public_key.json")
    with open(key_path, "w", encoding="utf-8") as f:
        f.write(export_public_key(pub_key))
    print("[multi] done: %d total, %d errors | by_registry: %s" % (len(all_results), total_errors, by_reg))
    return {"total": len(all_results), "errors": total_errors, "feed": feed_path,
            "by_registry": by_reg, "results": all_results}

def metadata_scan(registry="npm", limit=5000, out_dir=None):
    """Lightweight metadata-only scan: NO tarball download, NO hash computation.
    Records name/version/author/maintainer changes into the ledger.
    This covers the full ecosystem at near-zero cost.
    
    Returns list of metadata records (not full attestations - those are
    only for deep_scan targets). Metadata records go into state.json
    for diff tracking, and into the feed.
    """
    out_dir = out_dir or OUT_DIR
    results = []

    if registry == "npm":
        import urllib.parse
        for q in ["keywords:mcp-server", "keywords:model-context-protocol", "keywords:mcp"]:
            offset = 0
            while len(results) < limit:
                url = "https://registry.npmjs.org/-/v1/search?text=%s&size=250&from=%d" % (
                    urllib.parse.quote(q), offset)
                req = urllib.request.Request(url, headers={"User-Agent": UA})
                try:
                    with _opener().open(req, timeout=30) as r:
                        d = json.loads(r.read().decode("utf-8"))
                except Exception as e:
                    break
                objects = d.get("objects", [])
                if not objects:
                    break
                for obj in objects:
                    pkg = obj.get("package", {})
                    name = pkg.get("name", "")
                    if not name:
                        continue
                    results.append({
                        "name": name,
                        "version": pkg.get("version", ""),
                        "registry": "npm",
                        "date": pkg.get("date", ""),
                        "maintainers": [m.get("name", "") for m in pkg.get("maintainers", [])],
                        "downloads_monthly": (obj.get("downloads") or {}).get("monthly", 0),
                        "links": pkg.get("links", {}),
                    })
                offset += len(objects)
                if offset >= d.get("total", 0):
                    break
                import time
                time.sleep(0.3)

    elif registry == "pypi":
        # PyPI Simple API: get full list, filter for MCP-related names
        import re as _re
        url = "https://pypi.org/simple/"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with _opener().open(req, timeout=120) as r:
            html = r.read().decode("utf-8", errors="replace")
        names = _re.findall(r'>(.*?)</a>', html)
        mcp_names = [n for n in names if "mcp" in n.lower()]
        for name in mcp_names[:limit]:
            results.append({
                "name": name,
                "version": "",
                "registry": "pypi",
                "date": "",
                "maintainers": [],
                "links": {},
            })

    elif registry == "dsh":
        # DSH: pull market index (10K+), no per-plugin calls needed for metadata
        results = dsh_enumerate(limit=limit, with_security=False)

    return results


def deep_scan_with_metadata(npm_deep=200, pypi_deep=100, npm_meta=5000,
                            pypi_meta=5000, dsh_meta=10000,
                            signer=None, pub_key=None, out_dir=None):
    """Two-tier scan: deep attestation for top packages, metadata for all.
    
    Tier 1 (deep): download tarball + sha256 + signed attestation
    Tier 2 (metadata): name/version/author/maintainer recorded, no download
    
    This is the M1/M2 production pipeline entry point.
    """
    out_dir = out_dir or OUT_DIR
    lock = FileLock(os.path.join(out_dir, "run"))
    lock.__enter__()
    state = StateStore(os.path.join(out_dir, "state.json"))

    # Tier 1: deep scan (existing run_multi logic, reduced limits)
    deep_result = run_multi(npm_limit=npm_deep, pypi_limit=pypi_deep,
                            registry_limit=100, dsh_limit=0,
                            signer=signer, pub_key=pub_key, out_dir=out_dir)

    # Tier 2: metadata scan (fast, no downloads for npm/pypi)
    print("[meta] npm metadata scan (up to %d)..." % npm_meta)
    npm_meta_results = metadata_scan("npm", limit=npm_meta, out_dir=out_dir)
    print("[meta] npm metadata: %d packages" % len(npm_meta_results))

    print("[meta] PyPI metadata scan (up to %d)..." % pypi_meta)
    pypi_meta_results = metadata_scan("pypi", limit=pypi_meta, out_dir=out_dir)
    print("[meta] PyPI metadata: %d packages" % len(pypi_meta_results))

    print("[meta] dsh.so metadata scan (up to %d)..." % dsh_meta)
    dsh_meta_results = metadata_scan("dsh", limit=dsh_meta, out_dir=out_dir)
    print("[meta] dsh.so metadata: %d packages" % len(dsh_meta_results))

    # Combine all metadata into unified ledger
    all_meta = npm_meta_results + pypi_meta_results + dsh_meta_results

    # Diff metadata vs previous state
    meta_snapshot = {r["name"]: {"version": r.get("version", ""), "sha256": ""}
                     for r in all_meta}
    meta_diff = state.diff(meta_snapshot)
    print("[meta diff] new=%d changed=%d unchanged=%d removed=%d" % (
        len(meta_diff["new"]), len(meta_diff["changed"]),
        len(meta_diff["unchanged"]), len(meta_diff["removed"])))

    # Save metadata into state (separate from deep-scan state)
    for r in all_meta:
        state.set_component(r["name"], r.get("version", ""), "", "")
    state.save()
    lock.__exit__()

    # Build combined feed
    feed_dir = os.path.join(out_dir, "feed")
    os.makedirs(feed_dir, exist_ok=True)
    feed = {
        "feed_version": 3,
        "generated_at": _now(),
        "two_tier": True,
        "deep_scan": {
            "total": deep_result.get("total", 0),
            "errors": deep_result.get("errors", 0),
            "by_registry": deep_result.get("by_registry", {}),
        },
        "metadata_scan": {
            "npm": len(npm_meta_results),
            "pypi": len(pypi_meta_results),
            "dsh": len(dsh_meta_results),
            "total": len(all_meta),
        },
        "diff": meta_diff,
        "items": deep_result.get("results", []),
    }
    feed_path = os.path.join(feed_dir, "feed-%s.json" % datetime.date.today().strftime("%Y%m%d"))
    with open(feed_path, "w", encoding="utf-8") as f:
        json.dump(feed, f, ensure_ascii=False, indent=1)

    print("[two-tier] done: deep=%d, metadata=%d total=%d" % (
        deep_result.get("total", 0), len(all_meta),
        deep_result.get("total", 0) + len(all_meta)))
    return feed


def propagate_revocation(revoked_name, revoked_author, all_components):
    from canari.npm_enum import propagate_revocation as _prop
    return _prop(revoked_name, revoked_author, all_components)
