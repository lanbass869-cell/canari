# -*- coding: utf-8 -*-
"""audit_all.py - the checks that are NOT in pytest.

pytest proves units; this proves the shipped surface: every CLI answers --help
without doing real work, a real store verifies offline, the identity pipeline runs
end to end, and both offline verifiers agree on the published log bundle.

    python scripts/audit_all.py [--store DIR]
"""
import argparse
import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
results = []


def record(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print("%-46s %s %s" % (name, "PASS" if ok else "FAIL", detail), flush=True)


def _run(args, cwd=ROOT, timeout=180):
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return -1, "%s: %s" % (type(e).__name__, e)


# ------------------------------------------------------------------ A: CLIs
CLIS = ["baseline", "verify_cli", "gate_cli", "drift_cli", "mcp_server", "guard",
        "mcp_gate", "registry_audit", "sarif_ingest", "log_cli", "identity"]
# `python -m canari` dispatches to verify_cli through canari/__main__.py; it is a
# separate code path (module-level sys.exit) and gets its own check.
BARE = "canari"


def check_clis():
    """--help must be rc=0, print usage, and write nothing.

    Incident class this guards (2026-11-11): a CLI that did not parse argv ran its
    real logic on --help, writing to the production store.
    """
    before = sorted(os.listdir(ROOT))
    for mod in CLIS:
        rc, out = _run([PY, "-m", "canari.%s" % mod, "--help"], timeout=120)
        usage = "usage" in out.lower()
        record("cli --help canari.%s" % mod, rc == 0 and usage,
               "" if rc == 0 and usage else "rc=%s usage=%s" % (rc, usage))
    rc, out = _run([PY, "-m", BARE, "--help"], timeout=120)
    usage = "usage" in out.lower()
    record("cli --help python -m canari", rc == 0 and usage,
           "" if rc == 0 and usage else "rc=%s usage=%s" % (rc, usage))
    after = sorted(os.listdir(ROOT))
    record("cli --help wrote nothing to repo root", before == after,
           "" if before == after else "new: %s" % (set(after) - set(before)))


# --------------------------------------------------------------- B: real store
def check_store(store):
    from canari.signing import verify_signed
    key = os.path.join(store, "public_key.json")
    if not os.path.exists(key):
        record("store verify (offline)", False, "no public_key.json in %s" % store)
        return
    with open(key, encoding="utf-8") as f:
        pub = json.load(f)
    files = sorted(glob.glob(os.path.join(store, "attestations", "*.json")))
    ok = bad = 0
    first_err = ""
    for path in files:
        try:
            with open(path, encoding="utf-8") as f:
                bundle = json.load(f)
            good, _att, err = verify_signed(bundle.get("envelope") or {}, pub)
        except Exception as e:
            good, err = False, "%s: %s" % (type(e).__name__, e)
        if good:
            ok += 1
        else:
            bad += 1
            first_err = first_err or "%s: %s" % (os.path.basename(path), err)
    record("store verify (offline)", bad == 0 and ok > 0,
           "%d ok / %d bad%s" % (ok, bad, (" | " + first_err) if first_err else ""))


# ------------------------------------------------------------ C: identity chain
def check_identity(store):
    from canari.identity import build_clusters, find_conflicts, load_store
    if not os.path.isdir(os.path.join(store, "attestations")):
        record("identity clusters", False, "no attestations in %s" % store)
        return
    recs, bad = load_store(store)
    built = build_clusters(recs)
    conf = find_conflicts(recs)
    record("identity clusters", not bad and bool(recs),
           "%d records, %d clusters, %d monorepo, %d unknown" % (
               len(recs), len(built["clusters"]),
               sum(1 for c in built["clusters"] if c["kind"] == "monorepo"),
               built["without_repository"]))
    record("identity conflicts computed", True,
           "name_collision=%d repo_changed=%d" % (len(conf["name_collision"]),
                                                  len(conf["repo_changed"])))
    if not built["clusters"]:
        record("identity sign+verify", False, "no clusters to sign (no repositories)")
        return
    key = os.path.join(store, "private_key.pem")
    pub = os.path.join(store, "public_key.json")
    if not (os.path.exists(key) and os.path.exists(pub)):
        record("identity sign+verify", False, "missing key pair in store")
        return
    with tempfile.TemporaryDirectory() as td:
        rc, out = _run([PY, "-m", "canari.identity", "sign", "--store", store,
                        "--key", key, "--out", td], timeout=180)
        made = len(glob.glob(os.path.join(td, "*.identity.json")))
        rc2, out2 = _run([PY, "-m", "canari.identity", "verify", "--claims", td,
                          "--key", pub], timeout=180)
        record("identity sign+verify", rc == 0 and rc2 == 0 and made > 0,
               "signed=%d verify_rc=%s%s" % (made, rc2, ("" if rc2 == 0 else " | " + out2[:120])))


# ----------------------------------------------------------- D: offline verifiers
def check_log():
    bundle = os.path.join(ROOT, "docs", "log", "bundle-latest.json")
    if not os.path.exists(bundle):
        record("log offline verify (python)", False, "bundle-latest.json missing")
        return
    rc, out = _run([PY, "-m", "canari.verify_offline", bundle], timeout=180)
    record("log offline verify (python)", rc == 0, "" if rc == 0 else (out or "")[-160:])
    js = os.path.join(ROOT, "docs", "spec", "verify_offline.js")
    if not os.path.exists(js):
        record("log offline verify (node)", False, "verify_offline.js missing")
        return
    rc2, out2 = _run(["node", js, bundle, "--log-id", "canari-snapshot-log"], timeout=180)
    record("log offline verify (node)", rc2 == 0, "" if rc2 == 0 else (out2 or "")[-160:])


# --------------------------------------------------------------- E: dataset
def check_dataset():
    ds = os.path.join(ROOT, "dataset")
    man = os.path.join(ds, "MANIFEST.json")
    if not os.path.exists(man):
        record("dataset manifest", False, "MANIFEST.json missing")
        return
    with open(man, encoding="utf-8") as f:
        m = json.load(f)
    bad = [rel for rel, want in (m.get("sha256") or {}).items()
           if not os.path.exists(os.path.join(ds, rel))
           or hashlib.sha256(open(os.path.join(ds, rel), "rb").read()).hexdigest() != want]
    record("dataset manifest", not bad,
           "%d files listed%s" % (len(m.get("sha256") or {}),
                                  "" if not bad else " | bad: %s" % bad[:3]))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default=os.path.join(ROOT, "_probe_identity"))
    a = ap.parse_args(argv)
    check_clis()
    check_store(a.store)
    check_identity(a.store)
    check_log()
    check_dataset()
    failed = [r for r in results if not r[1]]
    print("\n%d checks, %d passed, %d failed" % (len(results), len(results) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
