"""scanner_adapter.py - T6: L3 scanner adapter interface.

Canari does not build its own vulnerability scanner. This module defines
the adapter interface for orchestrating external scanners (repo-forensics,
sentinel, cisco skill-scanner) and recording their findings as signed
attestation checks.

Design constraints:
- The adapter NEVER modifies the scanner - it invokes it and parses output.
- The scanner source tree digest is bound into scenario_sha256 for reproducibility.
- Findings are data; the verdict is Canari's own from the check list.
- Failure is data (dead_letter), never silent.

Reference implementation: repo-forensics v2 (29 scanners, 1138 re.compile).
Interface is generic enough for any CLI scanner that outputs JSON.
"""
import hashlib
import json
import os
import subprocess

from canari.npm_enum import _opener


def compute_source_digest(scanner_path):
    """SHA-256 over the scanner's source tree (git ls-tree equivalent for
    a directory walk). Binds the attestation to the exact scanner version
    that produced the findings."""
    h = hashlib.sha256()
    for root, dirs, files in os.walk(scanner_path):
        dirs[:] = sorted(x for x in dirs if x not in (".git", "node_modules", ".venv", "__pycache__"))
        for fn in sorted(files):
            fp = os.path.join(root, fn)
            h.update(fn.encode("utf-8"))
            try:
                with open(fp, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        h.update(chunk)
            except OSError:
                pass
    return h.hexdigest()


def run_repo_forensics(repo_path, scanner_root=None, timeout=300, mode="full"):
    """Run repo-forensics against a local path. Returns parsed findings dict
    or {"error": ...}. Requires repo-forensics to be cloned locally.

    Usage (bash): ./run_forensics.sh <path> --format json
    Internal: runs aggregate_json.py via python3 after all 29 scanners.
    On Windows we invoke the Python scripts directly.
    """
    if scanner_root is None:
        scanner_root = os.path.join(os.path.dirname(__file__), "..", "external", "repo-forensics",
                                     "skills", "repo-forensics")
    scanner_root = os.path.abspath(scanner_root)
    if not os.path.isdir(scanner_root):
        return {"error": "repo-forensics not found at %s" % scanner_root}

    scripts_dir = os.path.join(scanner_root, "scripts")
    agg = os.path.join(scripts_dir, "aggregate_json.py")
    if not os.path.isfile(agg):
        return {"error": "aggregate_json.py not found"}

    # compute source digest for scenario binding
    src_digest = compute_source_digest(scripts_dir)

    # Run the full scan via run_forensics.sh (bash) or python scripts directly
    # On Windows: invoke each scanner script + aggregate manually (simplified)
    # For the reference implementation we invoke run_forensics.sh via bash
    # and capture stdout.
    try:
        run_script = os.path.join(scanner_root, "scripts", "run_forensics.sh")
        if os.path.isfile(run_script) and os.name != "nt":
            # Unix: direct bash
            result = subprocess.run(
                ["bash", run_script, repo_path, "--format", "json"],
                capture_output=True, text=True, timeout=timeout, cwd=scanner_root)
        else:
            # Windows: try Git Bash, or fall back to auto_scan.py (single-script path)
            auto_scan = os.path.join(scripts_dir, "auto_scan.py")
            if os.path.isfile(auto_scan):
                result = subprocess.run(
                    ["python", auto_scan, repo_path, "--format", "json"],
                    capture_output=True, text=True, timeout=timeout, cwd=scanner_root)
            else:
                return {"error": "no viable entry point (run_forensics.sh or auto_scan.py)"}

        if result.returncode not in (0, 1, 2):
            return {"error": "scanner exit %d: %s" % (result.returncode, result.stderr[:200])}

        # parse JSON from stdout
        stdout = result.stdout
        # find the JSON payload (scanners may print progress before JSON)
        idx = stdout.find("{")
        if idx < 0:
            return {"error": "no JSON in scanner output"}
        data = json.loads(stdout[idx:])
        data["_canari_source_digest"] = src_digest
        data["_canari_scanner_path"] = scanner_root
        return data
    except subprocess.TimeoutExpired:
        return {"error": "scanner timeout after %ds" % timeout}
    except json.JSONDecodeError as e:
        return {"error": "JSON parse: %s" % str(e)[:200]}
    except Exception as e:
        return {"error": "%s: %s" % (type(e).__name__, str(e)[:200])}


def findings_to_checks(data):
    """Convert repo-forensics aggregate JSON into Canari check entries.
    Returns list of check dicts suitable for attestation["checks"].
    Also returns the run-level verdict.
    """
    if data is None:
        data = {}
    if "error" in data:
        return [{"id": "L3.1_SCANNER_ERROR", "verdict": "error",
                 "tool": "repo-forensics/adapter",
                 "evidence_ref": data["error"]}], "error"

    raw_summary = data.get("summary")
    summary = raw_summary if isinstance(raw_summary, dict) else {}
    total = summary.get("total", 0)
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    exit_code = data.get("exit_code", 99)
    scanner_count = data.get("scanner_count", 0)
    digest = data.get("_canari_source_digest", "?")[:16]

    tool_id = "repo-forensics-v2/%s/%d-scanners" % (digest, scanner_count)

    # ★2026-11-11 (F5): "no evidence" must never become "pass". A missing or
    # malformed summary, a scanner that ran nothing, or a non-zero exit code
    # all mean we did not actually vet the artifact.
    if not isinstance(raw_summary, dict):
        verdict_lvl = "unsupported"
        evidence = ("scanner returned no usable 'summary' (type=%s, exit=%s); "
                    "nothing was actually assessed" % (type(raw_summary).__name__, exit_code))
    elif critical > 0 or high > 0:
        verdict_lvl = "fail"
        evidence = "critical=%d high=%d total=%d exit=%d" % (critical, high, total, exit_code)
    elif total > 0:
        verdict_lvl = "pass-with-findings"
        evidence = "medium=%d low=%d total=%d" % (summary.get("medium", 0), summary.get("low", 0), total)
    elif scanner_count <= 0 or exit_code != 0:
        verdict_lvl = "unsupported"
        evidence = ("zero scanners ran or the scan exited non-zero "
                    "(scanners=%d, exit=%s); no findings is not a clean result"
                    % (scanner_count, exit_code))
    else:
        verdict_lvl = "pass"
        evidence = "0 findings across %d scanners, digest=%s" % (scanner_count, digest)

    checks = [{"id": "L3.1_STATIC_SCAN", "verdict": verdict_lvl,
               "tool": tool_id, "evidence_ref": evidence}]
    return checks, verdict_lvl


def get_rule_count(scanner_root=None):
    """Count re.compile() calls in the scanner source (honest rule count
    from source, not README). Returns int."""
    if scanner_root is None:
        scanner_root = os.path.join(os.path.dirname(__file__), "..", "external", "repo-forensics",
                                     "skills", "repo-forensics", "scripts")
    scanner_root = os.path.abspath(scanner_root)
    import re
    count = 0
    for root, dirs, files in os.walk(scanner_root):
        dirs[:] = [x for x in dirs if x not in (".git", "__pycache__")]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            try:
                t = open(os.path.join(root, fn), encoding="utf-8", errors="ignore").read()
                count += len(re.findall(r"re\.compile\(", t))
            except OSError:
                pass
    return count
