"""cadence.py - H1: Release cadence anomaly detection.

Detects three abnormal release patterns from PyPI JSON API metadata:
  1. release_burst: >= 5 versions published within 24 hours
  2. release_after_dormancy: >= 365 days since last release
  3. release_cadence_acceleration: current interval <= 1h but historical median >= 7 days

Data source: PyPI JSON API GET /pypi/{project}/json -> releases -> upload_time
No code execution required. All from public metadata.
"""
import json
import statistics
import urllib.request
from datetime import datetime, timezone

from canari.npm_enum import _opener, UA

PYPI_JSON_URL = "https://pypi.org/pypi/{project}/json"


def _parse_upload_time(item):
    raw = item.get("upload_time") if isinstance(item, dict) else None
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
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
    current_ts = None
    for ts, ver in uploads:
        if ver == current_version:
            current_ts = ts
            break
    if current_ts is None:
        return []
    findings = []
    recent = [ver for ts, ver in uploads if 0 <= (current_ts - ts).total_seconds() <= 86400]
    if len(recent) >= 5:
        findings.append({"id": "L2.4_RELEASE_CADENCE", "verdict": "pass", "tool": "canari-cadence/0.1",
                         "evidence_ref": "finding: release_burst - %d versions in 24h" % len(recent)})
    relevant = [(ts, ver) for ts, ver in uploads if ts <= current_ts]
    dormancy_days = []
    for i in range(1, len(relevant)):
        gap = (relevant[i][0] - relevant[i-1][0]).total_seconds() / 86400
        if gap >= 365:
            dormancy_days.append(gap)
    if dormancy_days:
        findings.append({"id": "L2.4_RELEASE_CADENCE", "verdict": "pass", "tool": "canari-cadence/0.1",
                         "evidence_ref": "finding: release_after_dormancy - %.1f days" % max(dormancy_days)})
    current_idx = next((i for i, (_, ver) in enumerate(uploads) if ver == current_version), None)
    if current_idx is not None and current_idx > 0 and len(uploads) >= 3:
        latest_interval = (uploads[current_idx][0] - uploads[current_idx-1][0]).total_seconds()
        all_intervals = [(uploads[i+1][0] - uploads[i][0]).total_seconds()
                         for i in range(len(uploads)-1)
                         if uploads[i+1][0] <= current_ts and (uploads[i+1][0] - uploads[i][0]).total_seconds() > 0]
        if len(all_intervals) >= 3:
            baseline = statistics.median(all_intervals)
            if latest_interval <= 3600 and baseline >= 7 * 86400:
                findings.append({"id": "L2.4_RELEASE_CADENCE", "verdict": "pass", "tool": "canari-cadence/0.1",
                                 "evidence_ref": "finding: release_cadence_acceleration - %.2f hours" % (latest_interval / 3600)})
    return findings
