# Canari two-tier weekly scan
import os, sys, traceback, datetime
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)

LOG_PATH = os.path.join(HERE, "out", "weekly_scan.log")

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
        npm_deep=200, pypi_deep=100, registry_limit=100,
        npm_meta=5000, pypi_meta=5000, dsh_meta=10000)
    _log("deep: %d | metadata: npm=%d pypi=%d dsh=%d" % (
        result["deep_scan"]["total"],
        result["metadata_scan"]["npm"],
        result["metadata_scan"]["pypi"],
        result["metadata_scan"]["dsh"]))
    _log("weekly scan completed OK")
except Exception as e:
    _log("FATAL: %s" % e)
    _log(traceback.format_exc())
    sys.exit(1)
