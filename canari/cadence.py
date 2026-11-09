"""cadence.py - H1: Release cadence anomaly detection.

Detects three abnormal release patterns from PyPI JSON API metadata:
  1. release_burst: >= 5 versions published within 24 hours
  2. release_after_dormancy: the CURRENT release follows a >= 365 day gap
     (trustcheck semantics: dormancy is measured from the previous release
     into the current one, NOT from any historical gap - a mature package
     with a 2009 hole but weekly releases now is NOT dormant)
  3. release_cadence_acceleration: current interval <= 1h but historical
     median (excluding the current interval) >= 7 days

Data source: PyPI JSON API GET /pypi/{project}/json -> releases ->
upload_time_iso_8601 (the Z-suffixed field; plain upload_time has no TZ
marker and is only a fallback). No code execution required.
"""
import json
import statistics
import urllib.request
from datetime import datetime, timezone

from canari.npm_enum import _opener, UA

PYPI_JSON_URL = "https://pypi.org/pypi/{project}/json"


def _parse_upload_time(item):
    """Parse a file record's upload timestamp.

    Prefers upload_time_iso_8601 (always Z-suffixed, microsecond precision).
    Falls back to upload_time (no TZ marker) with a Z appended.
    """
    if not isinstance(item, dict):
        return None
    raw = item.get("upload_time_iso_8601") or item.get("upload_time")
    if not isinstance(raw, str):
        return None
    if not raw.endswith("Z") and "T" in raw:
        raw = raw + "Z"
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def analyze_release_cadence(project, current_version):
    if not project or not current_version:
        return []
    url = PYPI_JSON_URL.format(project=project)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with _opener().open(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception:
        return []
    releases = data.get("releases", {})
    if not isinstance(releases, dict):
        return []
    uploads = []
    for version, files in releases.items():
        if not isinstance(files, list):
            continue
        timestamps = [_parse_upload_time(f) for f in files]
        timestamps = [t for t in timestamps if t is not None]
        if timestamps:
            uploads.append((min(timestamps), str(version)))
    uploads.sort()
    current_idx = next((i for i, (_, ver) in enumerate(uploads) if ver == current_version), None)
    if current_idx is None:
        return []
    current_ts = uploads[current_idx][0]
    findings = []

    # 1. release_burst: >=5 versions in the 24h window ending at the current release
    recent = [ver for ts, ver in uploads if 0 <= (current_ts - ts).total_seconds() <= 86400]
    if len(recent) >= 5:
        findings.append({"id": "L2.4_RELEASE_CADENCE", "verdict": "pass", "tool": "canari-cadence/0.1",
                         "evidence_ref": "finding: release_burst - %d versions in 24h" % len(recent)})

    # 2. release_after_dormancy: gap INTO the current release >= 365 days
    #    (BUG-69 fix: was any historical gap; now only the current one counts)
    if current_idx > 0:
        gap_days = (current_ts - uploads[current_idx - 1][0]).total_seconds() / 86400
        if gap_days >= 365:
            findings.append({"id": "L2.4_RELEASE_CADENCE", "verdict": "pass", "tool": "canari-cadence/0.1",
                             "evidence_ref": "finding: release_after_dormancy - %.1f days" % gap_days})

    # 3. release_cadence_acceleration: current interval <= 1h while the median
    #    of PRIOR intervals (excluding the current one, BUG-71 fix) >= 7 days
    if current_idx > 0 and len(uploads) >= 3:
        latest_interval = (current_ts - uploads[current_idx - 1][0]).total_seconds()
        prior_intervals = [(uploads[i + 1][0] - uploads[i][0]).total_seconds()
                           for i in range(current_idx - 1)
                           if (uploads[i + 1][0] - uploads[i][0]).total_seconds() > 0]
        if len(prior_intervals) >= 3:
            baseline_median = statistics.median(prior_intervals)
            if latest_interval <= 3600 and baseline_median >= 7 * 86400:
                findings.append({"id": "L2.4_RELEASE_CADENCE", "verdict": "pass", "tool": "canari-cadence/0.1",
                                 "evidence_ref": "finding: release_cadence_acceleration - %.2f hours" % (latest_interval / 3600)})
    return findings
