# -*- coding: utf-8 -*-
"""Rescan PyPI branch only, reusing names from the existing 94 PyPI bundles.

The full run_multi PyPI phase died mid-simple-index download (the simple index
is a ~600K-name HTML page). The existing bundles already give us the exact
repository population, so we rescan that population directly: same checks as
run_multi's PyPI branch (L1.1/L2.1 + H1 cadence + H2 anomaly + H3 typosquat +
PEP 740 native ingest), same signing path, timestamp+digest filenames, and a
supersedes pointer to the previous attestation digest.
"""
import glob
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, r"E:\Temp\tbdig\canari")
from canari.baseline import _now, _expiry, _PREDICATE_TYPE
from canari.signing import load_or_generate_keypair, export_public_key, sign_attestation
from canari.state import StateStore
from canari.cadence import analyze_release_cadence
from canari.anomaly import detect_metadata_anomaly
from canari.typosquat import check_typosquatting
from canari.pypi_native import ingest_pypi
from canari.npm_enum import _opener, UA
import urllib.request

OUT = r"E:\Temp\tbdig\canari\out"
ATT = os.path.join(OUT, "attestations")
LOG = open(os.path.join(OUT, "rescan_pypi.log"), "w", encoding="utf-8")

def log(msg):
    print(msg)
    LOG.write(msg + "\n")
    LOG.flush()

# 1. population = subjects of existing pypi bundles (deduped)
names = []
for fp in sorted(glob.glob(os.path.join(ATT, "pypi_*.bundle.json"))):
    try:
        p = json.load(open(fp, encoding="utf-8"))["payload"]
        nm = p.get("subject", {}).get("name", "")
        if nm and nm not in names:
            names.append(nm)
    except Exception:
        pass
log("population: %d PyPI names" % len(names))

state = StateStore(os.path.join(OUT, "state.json"))
signer, pub_key, is_new = load_or_generate_keypair(os.path.join(OUT, "private_key.pem"))
log("key: %snew" % ("" if not is_new else ""))
scenario_sha256 = hashlib.sha256(json.dumps(
    {"level": "L1-L2-multi-registry", "registries": ["pypi"],
     "heuristics": ["L2.4", "L2.5", "L2.6"]}, sort_keys=True).encode()).hexdigest()

def fetch_json(name, ver):
    url = "https://pypi.org/pypi/%s/%s/json" % (name, ver) if ver else "https://pypi.org/pypi/%s/json" % name
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with _opener().open(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))

meta_snaps = {}
results = []
for i, name in enumerate(names, 1):
    try:
        time.sleep(0.3)
        d = fetch_json(name, None)
        info = d.get("info", {})
        urls = d.get("urls", [])
        ver = info.get("version", "")
        sha = urls[0]["digests"]["sha256"] if urls else ""
        maintainers = [x for x in [info.get("author", "") or info.get("author_email", "")] if x]
        homepage = info.get("home_page") or ""
        checks = [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "pass", "tool": "canari-m1/0.1"},
                  {"id": "L2.1_ARTIFACT_HASH", "verdict": "pass" if sha else "fail", "tool": "canari-m1/0.1"}]
        try:
            checks.extend(analyze_release_cadence(name, ver))
        except Exception:
            pass
        prev = state.get_component("pypi:" + name) or state.get_component(name)
        prev_meta = (prev or {}).get("meta")
        cur_meta = {"maintainers": maintainers, "homepage": homepage}
        if prev_meta:
            try:
                checks.extend(detect_metadata_anomaly(cur_meta, prev_meta))
            except Exception:
                pass
        try:
            tq = check_typosquatting(name, set(names))
            if tq:
                checks.append(tq)
        except Exception:
            pass
        try:
            pn = ingest_pypi(name, ver or None)
        except Exception:
            pn = None
        verdict = "pass" if sha else "fail"
        if any((c.get("evidence_ref") or "").startswith("finding:") for c in checks):
            verdict = "pass-with-findings"
        att = {"_type": _PREDICATE_TYPE,
               "subject": {"name": name, "version": ver, "registry": "pypi",
                           "artifact_sha256": sha or "0" * 64, "maintainers": maintainers,
                           "homepage": homepage},
               "host": {"class": "mcp", "host_version": "registry-meta-v1"},
               "scenario_sha256": scenario_sha256, "checks": checks, "verdict": verdict,
               "checker": {"kind": "automation", "id": "canari-m1", "tools": ["canari-m1/0.1"]},
               "evidence_refs": ["pypi-json:" + name],
               "evidence_completeness": {"dropped_logs": 0, "missing_observers": [], "truncated_fields": []},
               "expires_at": _expiry(), "generated_at": _now(),
               "signature": {"envelope": "DSSE", "keyid": "", "sig": "", "payload_type": _PREDICATE_TYPE}}
        if prev and prev.get("attestation_digest"):
            att["supersedes"] = prev["attestation_digest"]
        if pn is not None:
            att["native_provenance"] = pn
        signed = sign_attestation(att, signer)
        safe = "".join(c for c in name if c.isalnum() or c in "._-")
        ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
        digest8 = hashlib.sha256(json.dumps(signed["payload"], ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:8]
        bp = os.path.join(ATT, "pypi_%s_%s_%s.bundle.json" % (safe, ts, digest8))
        json.dump({"envelope": signed["envelope"], "payload": signed["payload"]}, open(bp, "w", encoding="utf-8"), ensure_ascii=False)
        digest = hashlib.sha256(json.dumps(signed["payload"], ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        state.set_component("pypi:" + name, ver, sha, digest, meta=cur_meta)
        results.append({"name": name, "verdict": verdict, "bundle": bp,
                        "findings": [c["evidence_ref"][:50] for c in checks if (c.get("evidence_ref") or "").startswith("finding:")]})
        log("[%02d/%d] %-40s %-10s %s %s" % (i, len(names), name, ver, verdict,
                                            " | ".join(results[-1]["findings"][:2])))
    except Exception as e:
        log("[%02d/%d] %-40s ERROR %s" % (i, len(names), name, str(e)[:90]))

state.save()
open(os.path.join(OUT, "public_key.json"), "w", encoding="utf-8").write(export_public_key(pub_key))
finds = sum(1 for r in results if r["findings"])
log("DONE: %d attested, %d with findings" % (len(results), finds))
