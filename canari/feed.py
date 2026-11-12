# -*- coding: utf-8 -*-
"""feed.py - canonical component-level feed rebuilt from the attestation store.

run_multi writes a run-level feed (what this run produced). Consumers need the
*store* view (latest attestation per component, with findings and supersedes),
so the weekly job rebuilds this canonical feed after every scan.
"""
import datetime
import json
import os


def build_feed(out_dir):
    att_dir = os.path.join(out_dir, "attestations")
    latest, total = {}, 0
    for fn in sorted(os.listdir(att_dir)):
        if not fn.endswith(".bundle.json"):
            continue
        fp = os.path.join(att_dir, fn)
        try:
            # BUG-102/F2: the public feed must publish what was signed, and a
            # file with no DSSE envelope has nothing signed to publish.
            from canari.signing import read_signed_payload
            _b = json.load(open(fp, encoding="utf-8"))
            if not isinstance(_b, dict) or not isinstance(_b.get("envelope"), dict):
                continue
            _p, _err = read_signed_payload(_b)
            if _p is None:
                continue
            p = _p
        except Exception:
            continue
        s = p.get("subject", {})
        key = (s.get("registry", "?"), s.get("name", "?"))
        gen = p.get("generated_at", "")
        if key not in latest or gen > latest[key][0]:
            latest[key] = (gen, fp, p)
        total += 1

    items, by_reg, by_verdict, findings = [], {}, {}, {}
    for (reg, name), (gen, fp, p) in sorted(latest.items()):
        # 2026-11-10 BUG: this loop reused the leftover s from the scan above,
        # so every component reported the LAST bundle version/sha256.
        s = p.get("subject", {})
        by_reg[reg] = by_reg.get(reg, 0) + 1
        v = p.get("verdict", "error")
        by_verdict[v] = by_verdict.get(v, 0) + 1
        fs = [c["id"] for c in p.get("checks", [])
              if (c.get("evidence_ref") or "").startswith("finding:")]
        for x in fs:
            findings[x] = findings.get(x, 0) + 1
        items.append({"name": name, "registry": reg,
                      "version": s.get("version", ""), "verdict": v,
                      "artifact_sha256": s.get("artifact_sha256", ""),
                      "generated_at": gen, "supersedes": p.get("supersedes"),
                      "findings": fs, "bundle_file": os.path.basename(fp)})
    return {"feed_version": 3,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "store": {"bundle_files": total, "components": len(latest)},
            "by_registry": by_reg, "by_verdict": by_verdict,
            "findings_by_check": findings,
            "items": items}


def write_feed(out_dir):
    feed = build_feed(out_dir)
    fdir = os.path.join(out_dir, "feed")
    os.makedirs(fdir, exist_ok=True)
    fp = os.path.join(fdir, "feed-multi-%s.json" % datetime.date.today().strftime("%Y%m%d"))
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(feed, f, ensure_ascii=False, indent=1)
    return fp
