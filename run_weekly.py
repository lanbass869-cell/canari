# Canari two-tier weekly scan
import os, sys, traceback, datetime
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)

LOG_PATH = os.path.join(HERE, "out", "weekly_scan.log")

# Scheduled tasks do not inherit the interactive shell's proxy variables; without
# these, direct connections to PyPI/npm CDNs hang in SYN_SENT. Defaults match the
# machine's system proxy (Clash); override with CANARI_PROXY if it moves.
_PROXY = os.environ.get("CANARI_PROXY", "http://127.0.0.1:12000")
os.environ.setdefault("HTTP_PROXY", _PROXY)
os.environ.setdefault("HTTPS_PROXY", _PROXY)
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost")

def _log(msg):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = "[%s] %s" % (ts, msg)
    print(line)
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")

try:
    from canari.baseline import deep_scan_with_metadata
    _log("starting weekly scan...")
    result = deep_scan_with_metadata(
        npm_deep=int(os.environ.get("CANARI_NPM_DEEP", "200")),
        pypi_deep=int(os.environ.get("CANARI_PYPI_DEEP", "100")),
        npm_meta=int(os.environ.get("CANARI_NPM_META", "5000")),
        pypi_meta=int(os.environ.get("CANARI_PYPI_META", "5000")),
        dsh_meta=int(os.environ.get("CANARI_DSH_META", "10000")))
    _log("deep: %d | metadata: npm=%d pypi=%d dsh=%d" % (
        result["deep_scan"]["total"],
        result["metadata_scan"]["npm"],
        result["metadata_scan"]["pypi"],
        result["metadata_scan"]["dsh"]))
    # canonical component-level feed (what consumers read)
    try:
        from canari.feed import write_feed
        fp_feed = write_feed(os.path.join(HERE, "out"))
        _log("feed rebuilt: %s" % fp_feed)
    except Exception as e:
        _log("feed rebuild failed: %s" % e)
    # drift report: verdict flips / same-version silent changes / findings deltas
    try:
        from canari.drift import compute_drift
        import json as _json
        rep = compute_drift(os.path.join(HERE, "out"))
        drift_dir = os.path.join(HERE, "out", "drift")
        os.makedirs(drift_dir, exist_ok=True)
        fp = os.path.join(drift_dir, "drift-%s.json" % datetime.date.today().strftime("%Y%m%d"))
        with open(fp, "w", encoding="utf-8") as f:
            _json.dump(rep, f, ensure_ascii=False, indent=1)
        _log("drift: compared=%d flips=%d silent=%d findings+%d findings-%d -> %s" % (
            rep["compared"], len(rep["verdict_flips"]), len(rep["silent_changes"]),
            len(rep["findings_added"]), len(rep["findings_removed"]), fp))
    except Exception as e:
        _log("drift report failed: %s" % e)
    _log("weekly scan completed OK")
except Exception as e:
    _log("FATAL: %s" % e)
    _log(traceback.format_exc())
    sys.exit(1)
