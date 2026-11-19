# -*- coding: utf-8 -*-
"""monitor_cli.py - probe registry endpoints and report decay with hysteresis.

The difference from emit_capsules.py: this script does not judge a single probe.
It appends every probe to an observation history and reports the *streak*
verdict for each endpoint (see canari/endpoint_history.py for the rules).

Run weekly. One run never confirms anything; the verdict appears once the same
failure has been seen in observations separated by at least --min-gap-hours.

    canari-monitor --limit 600 --history out/endpoint_history.json
    canari-monitor --report-only --history out/endpoint_history.json

Why the two-phase flag exists: probing is the expensive, network-touching half.
Analysing a history you already hold should not require re-probing anyone.
"""
import argparse
import collections
import json
import os
import sys
import time
import urllib.request

from canari.endpoint_history import (
    DEFAULT_MIN_GAP_SECONDS,
    DEFAULT_MIN_OBSERVATIONS,
    EndpointHistory,
)
from canari.mcp_probe import probe_endpoint

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers?limit=%d"


def fetch_registry(limit):
    req = urllib.request.Request(REGISTRY % limit,
                                 headers={"User-Agent": "canari-monitor/0.1"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode("utf-8"))


def targets(data, skip_hosts=()):
    """One URL per remote, de-duplicated, with the declaring entry attached."""
    seen, out = set(), []
    for s in data.get("servers") or []:
        server = s.get("server") or s
        for rm in (server.get("remotes") or []):
            url = rm.get("url")
            if not url or url in seen:
                continue
            if any(h in url for h in skip_hosts):
                continue
            seen.add(url)
            out.append((s, url))
    return out


def probe_all(todo, timeout, history, delay):
    """Probe every target, recording each result as it happens.

    The history is saved after every probe rather than once at the end: a run
    killed halfway still keeps the observations it did make, which is the whole
    point of an append-only history.
    """
    for i, (entry, url) in enumerate(todo, 1):
        probe = probe_endpoint(url, timeout=timeout)
        history.record(url, probe)
        history.save()
        print("[%d/%d] %-52s %-18s" % (i, len(todo), url[:52], probe.get("outcome")),
              flush=True)
        if delay:
            time.sleep(delay)


def report(history, out_path, min_observations, min_gap_seconds):
    verdicts = history.all_verdicts(min_observations=min_observations,
                                    min_gap_seconds=min_gap_seconds)
    counts = collections.Counter(v["verdict"] for v in verdicts.values())

    # Only the confirmed ones are findings. Everything else is a state of
    # knowledge, and reporting it as a finding is the error this module exists
    # to prevent.
    findings = {url: v for url, v in verdicts.items()
                if v["verdict"] in ("INCONSISTENT_CONFIRMED", "UNAVAILABLE_CONFIRMED")}

    doc = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "endpoints_observed": len(verdicts),
        "verdict_counts": dict(sorted(counts.items())),
        "confirmed_findings": len(findings),
        "thresholds": {"min_observations": min_observations,
                       "min_gap_seconds": min_gap_seconds},
        "findings": [{"url": u, "verdict": v["verdict"], "reason": v["reason"],
                      "observations": v["observations"], "counted": v["counted"],
                      "span_seconds": v["span_seconds"]}
                     for u, v in sorted(findings.items())],
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)

    print()
    print("observed %d endpoints" % doc["endpoints_observed"])
    for verdict, n in sorted(counts.items()):
        print("  %-26s %d" % (verdict, n))
    print()
    print("confirmed findings: %d" % doc["confirmed_findings"])
    for f in doc["findings"][:20]:
        print("  %-22s %s" % (f["verdict"], f["url"][:70]))
    print("\nwrote %s" % out_path)
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=200,
                    help="registry records to read (default 200)")
    ap.add_argument("--max-probe", type=int, default=50,
                    help="cap on endpoints probed in this run (default 50)")
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--delay", type=float, default=0.2,
                    help="pause between probes, seconds (politeness)")
    ap.add_argument("--history", default=None,
                    help="observation history path (default out/endpoint_history.json)")
    ap.add_argument("--out", default=None,
                    help="report path (default out/endpoint_verdicts.json)")
    ap.add_argument("--report-only", action="store_true",
                    help="skip probing; only re-derive the report from the history")
    ap.add_argument("--min-observations", type=int, default=DEFAULT_MIN_OBSERVATIONS)
    ap.add_argument("--min-gap-hours", type=float,
                    default=DEFAULT_MIN_GAP_SECONDS / 3600.0)
    ap.add_argument("--skip-host", action="append", default=[],
                    help="substring of a host to skip (repeatable), e.g. trycloudflare.com")
    a = ap.parse_args(argv)

    history_path = a.history or os.path.join(ROOT, "out", "endpoint_history.json")
    out_path = a.out or os.path.join(ROOT, "out", "endpoint_verdicts.json")
    history = EndpointHistory(history_path)

    if not a.report_only:
        data = fetch_registry(a.limit)
        todo = targets(data, a.skip_host)[:a.max_probe]
        print("registry records=%d, endpoints to probe=%d"
              % (len(data.get("servers") or []), len(todo)))
        if todo:
            probe_all(todo, a.timeout, history, a.delay)

    return report(history, out_path, a.min_observations,
                  int(a.min_gap_hours * 3600))


if __name__ == "__main__":
    sys.exit(0 if main() is not None else 1)
