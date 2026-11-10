# -*- coding: utf-8 -*-
"""full_sweep.py - end-to-end acceptance sweep over the whole ledger + CLIs.

Runs every check an operator would run before calling a build "good":
  store    : every bundle parses, validates against the schema and verifies
             against the published key history
  chain    : supersession DAG verification
  tamper   : flipping one byte in a signed payload MUST fail verification
  cli      : gate / drift / verify --gate / guard / MCP server
  feed     : latest feed component count matches the store
  score    : the scoring card is internally consistent

Exit 0 only if every check passes.
"""
import glob
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
OUT = os.path.join(HERE, "out")
PY = sys.executable

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print("[%s] %-28s %s" % ("PASS" if ok else "FAIL", name, detail))


def main():
    from canari.schema import validate_attestation
    from canari.signing import verify_signed

    cur = json.load(open(os.path.join(OUT, "public_key.json"), encoding="utf-8"))
    old = json.load(open(os.path.join(OUT, "public_key_20261108.json"), encoding="utf-8"))
    keys = [cur, old]

    # --- store sweep
    files = glob.glob(os.path.join(OUT, "attestations", "*.bundle.json"))
    parse_bad = schema_bad = sig_bad = 0
    for f in files:
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            parse_bad += 1
            continue
        p = d.get("payload", {})
        if validate_attestation(p):
            schema_bad += 1
        if not any(verify_signed(d.get("envelope"), k)[0] for k in keys):
            sig_bad += 1
    check("store.parse", parse_bad == 0, "%d bundles, %d unreadable" % (len(files), parse_bad))
    check("store.schema", schema_bad == 0, "%d schema failures" % schema_bad)
    check("store.signature", sig_bad == 0, "%d sig failures (key history)" % sig_bad)

    # --- chain
    from canari.verify_cli import verify_chain
    rc = verify_chain(os.path.join(OUT, "attestations"))
    check("chain.verify", rc == 0, "rc=%d" % rc)

    # --- tamper
    victim = sorted(files)[0]
    bundle = json.load(open(victim, encoding="utf-8"))
    import base64
    raw = base64.b64decode(bundle["envelope"]["payload"])
    idx = raw.find(b'"verdict"')
    mutated = raw.replace(b'"pass"', b'"fail"', 1) if b'"pass"' in raw else raw[:10] + b"X" + raw[11:]
    env = dict(bundle["envelope"])
    env["payload"] = base64.b64encode(mutated).decode()
    tampered_fails = not any(verify_signed(env, k)[0] for k in keys)
    check("tamper.detected", tampered_fails, os.path.basename(victim))

    # --- gate CLI
    def run(args):
        return subprocess.run([PY, "-m"] + args, capture_output=True, text=True,
                              cwd=HERE, encoding="utf-8", errors="replace")

    r = run(["canari.gate_cli", "--store", "out", "--registry", "dsh-registry", "--name", "aegis"])
    check("cli.gate.review_or_allow", r.returncode in (0, 6), "rc=%d" % r.returncode)
    r = run(["canari.gate_cli", "--store", "out", "--registry", "dsh-registry",
             "--name", "deepseek-harness-wallet"])
    check("cli.gate.block", r.returncode == 5, "rc=%d" % r.returncode)
    r = run(["canari.gate_cli", "--store", "out", "--registry", "npm", "--name", "no-such-xyz"])
    check("cli.gate.notfound", r.returncode == 3, "rc=%d" % r.returncode)
    r = run(["canari.gate_cli", "--store", "out", "--list"])
    check("cli.gate.list", r.returncode == 0 and "components" in r.stdout,
          (r.stdout or "").strip().splitlines()[-1] if r.stdout else "")

    # --- drift CLI
    ddir = tempfile.mkdtemp()
    r = run(["canari.drift_cli", "--store", "out", "--write", ddir])
    ok = r.returncode == 0 and glob.glob(os.path.join(ddir, "drift-*.json"))
    check("cli.drift", bool(ok), "rc=%d" % r.returncode)

    # --- guard
    r = run(["canari.guard", "--store", "out", "--dry-run", "--", "dsh", "plugin", "add",
             "deepseek-harness-wallet"])
    check("cli.guard.block", r.returncode == 5, "rc=%d" % r.returncode)
    r = run(["canari.guard", "--store", "out", "--dry-run", "--", "ls"])
    check("cli.guard.passthrough", r.returncode == 0, "rc=%d" % r.returncode)

    # --- MCP server (one subprocess round-trip)
    p = subprocess.Popen([PY, "-m", "canari.mcp_server", "--store", "out",
                          "--key", os.path.join("out", "public_key.json")],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                         cwd=HERE, encoding="utf-8")
    def mcp(obj):
        p.stdin.write(json.dumps(obj, ensure_ascii=False) + "\n"); p.stdin.flush()
        return json.loads(p.stdout.readline())
    r1 = mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    r2 = mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    r3 = mcp({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
              "params": {"name": "store_summary", "arguments": {}}})
    p.stdin.close(); p.wait(timeout=20)
    tools = {t["name"] for t in r2["result"]["tools"]}
    summary = json.loads(r3["result"]["content"][0]["text"])
    check("mcp.handshake", r1["result"]["serverInfo"]["name"] == "canari", "")
    check("mcp.tools", tools == {"gate_check", "verify_bundle", "store_summary"}, str(sorted(tools)))
    check("mcp.summary", summary.get("components", 0) > 0, "%d components" % summary.get("components", 0))

    # --- feed consistency
    feeds = sorted(glob.glob(os.path.join(OUT, "feed", "feed-multi-*.json")))
    feed = json.load(open(feeds[-1], encoding="utf-8"))
    check("feed.latest", feed.get("store", {}).get("components") == summary.get("components"),
          "%s: %s" % (os.path.basename(feeds[-1]), feed.get("store", {}).get("components")))

    # --- score
    from canari.score import score
    s = score(OUT, public_key=cur, public_keys=[old])
    check("score.integrity", s.get("integrity", {}).get("pct_sig") == 100.0
          and s.get("integrity", {}).get("pct_schema") == 100.0,
          "sig=%s%% schema=%s%%" % (s["integrity"]["pct_sig"], s["integrity"]["pct_schema"]))

    bad = [r for r in results if not r[1]]
    print("\n%d checks, %d failed" % (len(results), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
