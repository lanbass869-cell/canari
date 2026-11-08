# Canari two-tier weekly scan
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)
from canari.baseline import deep_scan_with_metadata
result = deep_scan_with_metadata(
    npm_deep=200, pypi_deep=100, registry_limit=100,
    npm_meta=5000, pypi_meta=5000, dsh_meta=10000)
print("deep: %d | metadata: npm=%d pypi=%d dsh=%d" % (
    result["deep_scan"]["total"],
    result["metadata_scan"]["npm"],
    result["metadata_scan"]["pypi"],
    result["metadata_scan"]["dsh"]))
