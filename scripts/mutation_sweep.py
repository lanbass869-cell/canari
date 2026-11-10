# -*- coding: utf-8 -*-
"""mutation_sweep.py - measure whether the test suite actually catches bugs.

Each mutation is a plausible one-line regression in production code. The mutated
copy (canari/ + tests/) runs in a temp dir; a mutant is KILLED when the targeted
tests fail. Survivors are real test gaps, not style opinions.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable

# (label, file, old, new, test targets)
MUTATIONS = [
    ("signing.sort_keys", "canari/signing.py",
     'payload_bytes = json.dumps(a, ensure_ascii=False, sort_keys=True).encode("utf-8")',
     'payload_bytes = json.dumps(a, ensure_ascii=False, sort_keys=False).encode("utf-8")',
     ["tests/test_signing.py", "tests/test_deep_adversarial.py", "tests/test_deep_props.py"]),
    ("signing.verify_always_true", "canari/signing.py",
     '        return False, None, "%s: %s" % (type(e).__name__, str(e)[:200])',
     '        return True, {}, None',
     ["tests/test_signing.py", "tests/test_deep_adversarial.py", "tests/test_deep_props.py"]),
    ("gate.skip_signature", "canari/gate.py",
     "        if not ok:\n            return GateDecision(decision=\"BLOCK\",\n                                reasons=[\"signature verification FAILED: %s\" % (err or \"unknown\")],\n                                policy=policy_name, verdict=verdict, subject=subject_name)",
     "        if False:\n            pass",
     ["tests/test_gate.py", "tests/test_deep_adversarial.py"]),
    ("gate.skip_verdict_block", "canari/gate.py",
     "    if not is_gate_passing(payload):\n        decision = \"BLOCK\"\n        reasons.append(\"verdict is %s (gate blocks)\" % verdict)",
     "    if False:\n        pass",
     ["tests/test_gate.py", "tests/test_gate_expansion.py"]),
    ("gate.allow_findings_off", "canari/gate.py",
     "    if not policy.allow_findings and verdict == \"pass-with-findings\":",
     "    if False and verdict == \"pass-with-findings\":",
     ["tests/test_gate_expansion.py", "tests/test_gate.py"]),
    ("gate.freshness_off", "canari/gate.py",
     "    if policy.require_fresh:\n        fresh, reason = _check_freshness(payload)\n        if not fresh:",
     "    if policy.require_fresh:\n        fresh, reason = (True, None)\n        if not fresh:",
     ["tests/test_gate.py", "tests/test_gate_expansion.py"]),
    ("verify.chain_first_child_only", "canari/verify_cli.py",
     "                for child in children.get(current_digest, []):",
     "                for child in children.get(current_digest, [])[:1]:",
     ["tests/test_round18_chain_fork.py"]),
    ("verify.canonical_off", "canari/verify_cli.py",
     "    if canonical != payload_bytes:\n        return False, \"payload bytes != canonical JSON encoding (non-canonical serialization)\"",
     "    if False:\n        return False, \"x\"",
     ["tests/test_verify_cli.py", "tests/test_deep_props.py"]),
    ("consumer.picks_oldest", "canari/consumer.py",
     "    return cands[-1] if cands else None",
     "    return cands[0] if cands else None",
     ["tests/test_round16_consumer.py"]),
    ("guard.block_ignored", "canari/guard.py",
     "    if blocked:\n        print(\"[guard] refusing to run: %d blocked component(s)\" % len(blocked))\n        return 5",
     "    if False:\n        return 5",
     ["tests/test_round17_guard.py"]),
    ("guard.review_ignored", "canari/guard.py",
     "    if review and not a.allow_review:",
     "    if False:",
     ["tests/test_round17_guard.py"]),
    ("drift.same_version_flip", "canari/drift.py",
     "        if new[\"version\"] == old[\"version\"] and (nh != oh or nc != oc) and nv == ov:",
     "        if new[\"version\"] != old[\"version\"] and (nh != oh or nc != oc) and nv == ov:",
     ["tests/test_round16_consumer.py"]),
    ("drift.no_verdict_flip", "canari/drift.py",
     "        if nv != ov:",
     "        if False:",
     ["tests/test_round16_consumer.py"]),
    ("typosquat.threshold", "canari/typosquat.py",
     "        if distance <= threshold and similarity >= 0.72:",
     "        if distance <= threshold and similarity >= 0.99:",
     ["tests/test_round14_fixes.py"]),
    ("cadence.dormancy_threshold", "canari/cadence.py",
     "        if gap_days >= 365:",
     "        if gap_days >= 36500:",
     ["tests/test_round13_fixes.py"]),
    ("cadence.field_fallback_removed", "canari/cadence.py",
     '    raw = item.get("upload_time_iso_8601") or item.get("upload_time")',
     '    raw = item.get("upload_time")',
     ["tests/test_round13_fixes.py"]),
    ("baseline.atomic_off", "canari/baseline.py",
     "        tmp = bpath + \".tmp\"",
     "        tmp = bpath",
     ["tests/test_deep_adversarial.py"]),
    # EQUIVALENT: int(_prev_digest, 16) already rejects non-hex paths
    ("baseline.supersedes_guard_off(EQUIV)", "canari/baseline.py",
     "            if isinstance(_prev_digest, str) and len(_prev_digest) == 64:",
     "            if True:",
     ["tests/test_round14_fixes.py"]),
    ("pypi_native.latest_url", "canari/pypi_native.py",
     "    if version:\n        url = \"https://pypi.org/pypi/%s/%s/json\" % (",
     "    if False:\n        url = \"https://pypi.org/pypi/%s/%s/json\" % (",
     ["tests/test_round13_fixes.py", "tests/test_pypi_native.py"]),
    ("schema.gate_pass_set", "canari/schema.py",
     '_LIVE_STATUSES = frozenset({"pass", "pass-with-findings"})',
     '_LIVE_STATUSES = frozenset({"pass"})',
     ["tests/test_schema_and_gate.py", "tests/test_gate.py"]),
]


def _load_batch2():
    import importlib.util as _u
    spec = _u.spec_from_file_location(
        "mutations_batch2", os.path.join(HERE, "scripts", "mutations_batch2.py"))
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, "MUTATIONS_2", [])


def run_mutant(label, relfile, old, new, targets):
    d = tempfile.mkdtemp(prefix="mut_")
    try:
        shutil.copytree(os.path.join(HERE, "canari"), os.path.join(d, "canari"))
        shutil.copytree(os.path.join(HERE, "tests"), os.path.join(d, "tests"))
        for extra in ("pytest.ini",):
            src = os.path.join(HERE, extra)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(d, extra))
        fp = os.path.join(d, relfile)
        src = open(fp, encoding="utf-8").read()
        if old not in src:
            return label, "SKIP", "anchor not found"
        open(fp, "w", encoding="utf-8").write(src.replace(old, new, 1))
        env = dict(os.environ, PYTHONPATH=d)
        r = subprocess.run([PY, "-m", "pytest", "-x", "-q", "--no-header", "-p", "no:cacheprovider"] + targets,
                           cwd=d, capture_output=True, text=True, env=env,
                           encoding="utf-8", errors="replace", timeout=300)
        if r.returncode == 0:
            return label, "SURVIVED", ""
        tail = [l for l in (r.stdout or "").splitlines() if "failed" in l or "error" in l.lower()]
        return label, "KILLED", tail[-1][:90] if tail else ""
    except subprocess.TimeoutExpired:
        return label, "KILLED", "timeout"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="mutation-sweep")
    ap.add_argument("--min-kill", type=float, default=0.0,
                    help="fail (exit 1) when the kill rate is below this percent")
    a = ap.parse_args(argv)
    try:
        all_muts = MUTATIONS + _load_batch2()
    except Exception as _e:
        print('batch2 load failed:', _e)
        all_muts = MUTATIONS
    killed = survived = skipped = equiv = 0
    print("%-32s %-9s %s" % ("mutant", "verdict", "note"))
    for m in all_muts:
        label, verdict, note = run_mutant(*m)
        print("%-32s %-9s %s" % (label, verdict, note))
        if "(EQUIV)" in label:
            equiv += 1
        if verdict == "KILLED":
            killed += 1
        elif verdict == "SURVIVED":
            survived += 1
        else:
            skipped += 1
    total = killed + survived - equiv  # equivalent mutants cannot be killed
    rate = 100.0 * killed / total if total else 0.0
    print("\n%d mutants, killed=%d survived=%d equivalent=%d skipped=%d | kill rate %.0f%%" % (
        len(all_muts), killed, survived, equiv, skipped, rate))
    if a.min_kill and rate < a.min_kill:
        print("kill rate %.0f%% is below the required %.0f%%" % (rate, a.min_kill))
        return 1
    return 1 if (survived - equiv) > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
