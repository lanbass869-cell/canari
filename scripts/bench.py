# -*- coding: utf-8 -*-
"""bench.py - latency of the paths a consumer actually hits."""
import json
import os
import random
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
OUT = os.path.join(HERE, "out")
PY = sys.executable


def pct(vals, q):
    vals = sorted(vals)
    return vals[min(len(vals) - 1, int(len(vals) * q))]


def main():
    from canari.consumer import list_components, check_component

    comps = list_components(OUT)
    random.seed(7)
    sample = random.sample(comps, min(50, len(comps)))

    t0 = time.time()
    list_components(OUT)
    print("list_components (%d): %.0f ms" % (len(comps), (time.time() - t0) * 1000))

    lat = []
    for c in sample:
        t = time.time()
        check_component(OUT, c["registry"], c["name"])
        lat.append((time.time() - t) * 1000)
    print("gate_check x%d: p50=%.0f ms p95=%.0f ms max=%.0f ms"
          % (len(lat), statistics.median(lat), pct(lat, 0.95), max(lat)))

    from canari.verify_cli import verify_chain
    t = time.time()
    verify_chain(os.path.join(OUT, "attestations"))
    print("verify_chain: %.0f ms" % ((time.time() - t) * 1000))

    from canari.score import score
    cur = json.load(open(os.path.join(OUT, "public_key.json"), encoding="utf-8"))
    old = json.load(open(os.path.join(OUT, "public_key_20261108.json"), encoding="utf-8"))
    t = time.time()
    score(OUT, public_key=cur, public_keys=[old])
    print("score (full verify): %.0f ms" % ((time.time() - t) * 1000))

    # MCP roundtrip through a real subprocess
    p = subprocess.Popen([PY, "-m", "canari.mcp_server", "--store", OUT],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                         cwd=HERE, encoding="utf-8")
    def call(i, name, args):
        t = time.time()
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                  "params": {"name": name, "arguments": args}}) + "\n")
        p.stdin.flush()
        p.stdout.readline()
        return (time.time() - t) * 1000
    call(1, "store_summary", {})  # warm-up
    m = [call(i, "gate_check", {"registry": sample[0]["registry"],
                                "name": sample[0]["name"]}) for i in range(10, 20)]
    print("mcp gate_check roundtrip: p50=%.0f ms max=%.0f ms" % (statistics.median(m), max(m)))
    p.stdin.close(); p.wait(timeout=20)
    return 0


if __name__ == "__main__":
    sys.exit(main())
