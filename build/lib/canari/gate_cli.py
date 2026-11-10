# -*- coding: utf-8 -*-
"""gate_cli.py - canari-gate: resolve a component in the store and decide.

Usage:
  canari-gate --store out --registry npm --name express
  canari-gate --store out --registry pypi --name mcp-server-fetch --policy strict --json
  canari-gate --store out --list

Exit codes: 0 ALLOW, 5 BLOCK, 6 REVIEW, 3 usage/lookup error.
"""
import argparse
import json
import sys

from canari.consumer import check_component, list_components


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="canari-gate",
        description="Resolve a component's latest signed attestation and run the install gate.")
    ap.add_argument("--store", default="out", help="attestation store dir (default: out)")
    ap.add_argument("--registry", default=None, help="npm | pypi | mcp-registry | dsh-registry")
    ap.add_argument("--name", default=None, help="component name")
    ap.add_argument("--version", default=None, help="pin an exact version")
    ap.add_argument("--policy", default="default",
                    help="gate policy (default/strict/release-gate/lax/paranoid)")
    ap.add_argument("--policy-file", default=None, help="JSON policy file")
    ap.add_argument("--key", default=None, help="public key JSON (enables signature verification)")
    ap.add_argument("--key-registry", default=None, help="key_registry.json for lifecycle checks")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--list", action="store_true", help="list all components in the store")
    a = ap.parse_args(argv)

    if a.list:
        comps = list_components(a.store)
        if a.json:
            print(json.dumps(comps, ensure_ascii=False, indent=1))
        else:
            for c in comps:
                print("%-14s %-44s %-10s %s" % (c["registry"], c["name"],
                                                c["version"] or "-", c["verdict"]))
            print("-- %d components" % len(comps))
        return 0

    if not a.registry or not a.name:
        ap.error("--registry and --name are required (or use --list)")

    res = check_component(a.store, a.registry, a.name, version=a.version,
                          key_path=a.key, key_registry_path=a.key_registry,
                          policy=a.policy, policy_file=a.policy_file)
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=1))
    else:
        print("component: %s" % (res["subject"] or "%s:%s" % (a.registry, a.name)))
        print("attested:  %s" % (res["generated_at"] or "-"))
        print("verdict:   %s" % (res["verdict"] or "-"))
        print("gate:      %s (policy=%s)" % (res["decision"], res["policy"]))
        for r in res["reasons"]:
            print("  - %s" % r)
    if not res["found"]:
        return 3
    return {"ALLOW": 0, "BLOCK": 5, "REVIEW": 6}.get(res["decision"], 3)


if __name__ == "__main__":
    sys.exit(main())
