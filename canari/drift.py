# -*- coding: utf-8 -*-
"""drift.py - drift report: what changed between scan generations, per component.

This is the "make drift measurable/actionable" layer the positioning calls for:
for each component with >= 2 attestations, compare consecutive generations and
classify the change. The interesting classes are NOT version bumps:

  verdict_flip   - the run verdict changed (e.g. pass -> pass-with-findings)
  silent_change  - SAME version but different artifact hash or check outcomes
                   (the silent-drift failure mode measured by 2608.00997/2609.14119)
  findings_delta - trust-heuristic findings appeared or disappeared

All from signed bundles on disk; no network, no LLM.
"""
import json
import os


def _checks_map(payload):
    out = {}
    for c in payload.get("checks", []) or []:
        out[c.get("id", "?")] = c.get("verdict", "?")
    return out


def _findings(payload):
    return sorted(c.get("id", "?") for c in payload.get("checks", []) or []
                  if (c.get("evidence_ref") or "").startswith("finding:"))


def _load_bundles(store_dir):
    att_dir = os.path.join(store_dir, "attestations")
    if not os.path.isdir(att_dir):
        return []
    out = []
    for fn in sorted(os.listdir(att_dir)):
        if not fn.endswith(".bundle.json"):
            continue
        fp = os.path.join(att_dir, fn)
        try:
            with open(fp, "r", encoding="utf-8") as f:
                _b = json.load(f)
            # BUG-102/F2: only bundles that actually carry a signed payload.
            from canari.signing import read_signed_payload
            if not isinstance(_b, dict) or not isinstance(_b.get("envelope"), dict):
                continue
            p, _err = read_signed_payload(_b)
            if p is None:
                continue
            s = p.get("subject", {})
            out.append({"path": fp, "payload": p,
                        "registry": s.get("registry", "?"),
                        "name": s.get("name", "?"),
                        "version": s.get("version", ""),
                        "generated_at": p.get("generated_at", "")})
        except Exception:
            continue
    return out


def compute_drift(store_dir, since=None, max_items=200):
    """Compare the newest attestation of each component against the previous one.

    since: optional ISO timestamp; components whose newest attestation is older
           are skipped (use for weekly reports).
    """
    bundles = _load_bundles(store_dir)
    groups = {}
    for b in bundles:
        groups.setdefault((b["registry"], b["name"]), []).append(b)

    report = {"components": len(groups), "compared": 0,
              "verdict_flips": [], "silent_changes": [],
              "findings_added": [], "findings_removed": [],
              "version_bumps": [], "check_changes": []}

    for (reg, name), items in sorted(groups.items()):
        items.sort(key=lambda x: x["generated_at"])
        if len(items) < 2:
            continue
        new, old = items[-1], items[-2]
        if since and new["generated_at"] < since:
            continue
        report["compared"] += 1
        # _load_bundles already resolved the SIGNED payload into ["payload"];
        # reading it back through read_signed_payload() would see a wrapper with
        # no envelope and (since the F1 fallback removal) fail.
        np_, op = new["payload"], old["payload"]
        nv, ov = np_.get("verdict", "?"), op.get("verdict", "?")
        nh = np_.get("subject", {}).get("artifact_sha256", "")
        oh = op.get("subject", {}).get("artifact_sha256", "")
        nc, oc = _checks_map(np_), _checks_map(op)
        nf, of = _findings(np_), _findings(op)
        ref = {"registry": reg, "name": name, "old_version": old["version"],
               "new_version": new["version"], "old_generated_at": old["generated_at"],
               "new_generated_at": new["generated_at"]}

        if nv != ov:
            report["verdict_flips"].append(dict(ref, old_verdict=ov, new_verdict=nv,
                                                same_version=new["version"] == old["version"]))
        if new["version"] == old["version"] and (nh != oh or nc != oc) and nv == ov:
            detail = dict(ref, same_version=True)
            if nh != oh:
                detail["hash_changed"] = True
            changed = {k: (oc.get(k), nc.get(k)) for k in set(oc) | set(nc)
                       if oc.get(k) != nc.get(k)}
            if changed:
                detail["checks_changed"] = changed
            report["silent_changes"].append(detail)
        added = sorted(set(nf) - set(of))
        removed = sorted(set(of) - set(nf))
        if added:
            report["findings_added"].append(dict(ref, checks=added))
        if removed:
            report["findings_removed"].append(dict(ref, checks=removed))
        if new["version"] != old["version"]:
            report["version_bumps"].append(ref)
        else:
            changed = {k: (oc.get(k), nc.get(k)) for k in set(oc) | set(nc)
                       if oc.get(k) != nc.get(k)}
            if changed and nv == ov and nh == oh:
                report["check_changes"].append(dict(ref, checks=changed))

    for key in ("verdict_flips", "silent_changes", "findings_added",
                "findings_removed", "version_bumps", "check_changes"):
        report[key] = report[key][:max_items]
    return report


def format_report(rep):
    lines = ["=" * 62, "Canari Drift Report", "=" * 62,
             "components: %d | compared (>=2 generations): %d" % (
                 rep["components"], rep["compared"])]
    def section(title, items, fmt):
        lines.append("")
        lines.append("%s: %d" % (title, len(items)))
        for it in items[:20]:
            lines.append("  - " + fmt(it))
    section("verdict flips", rep["verdict_flips"],
            lambda i: "%s:%s %s -> %s (v%s -> v%s)" % (
                i["registry"], i["name"], i["old_verdict"], i["new_verdict"],
                i["old_version"] or "-", i["new_version"] or "-"))
    section("silent changes (same version)", rep["silent_changes"],
            lambda i: "%s:%s v%s %s" % (
                i["registry"], i["name"], i["new_version"] or "-",
                "hash+checks" if i.get("hash_changed") and i.get("checks_changed")
                else ("hash" if i.get("hash_changed") else "checks")))
    section("findings added", rep["findings_added"],
            lambda i: "%s:%s %s" % (i["registry"], i["name"], ",".join(i["checks"])))
    section("findings removed", rep["findings_removed"],
            lambda i: "%s:%s %s" % (i["registry"], i["name"], ",".join(i["checks"])))
    section("version bumps", rep["version_bumps"],
            lambda i: "%s:%s %s -> %s" % (
                i["registry"], i["name"], i["old_version"] or "-", i["new_version"] or "-"))
    lines.append("=" * 62)
    return "\n".join(lines)
