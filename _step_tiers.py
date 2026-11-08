# Two-tier scan: deep_scan (top N, tarball+sha256) vs metadata_scan (all, registry API only)
# This replaces the one-size-fits-all run_multi()

import os

ROOT = os.path.dirname(os.path.abspath(__file__))

# Read current baseline
bl_path = os.path.join(ROOT, "canari", "baseline.py")
bl = open(bl_path, encoding="utf-8").read()

# Add metadata_scan function (lightweight, no downloads)
metadata_code = open(os.path.join(ROOT, "_metadata_scan.txt"), encoding="utf-8").read()
bl += metadata_code
open(bl_path, "w", encoding="utf-8").write(bl)
print("metadata_scan added to baseline.py")
