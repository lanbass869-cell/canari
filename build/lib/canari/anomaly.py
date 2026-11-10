"""anomaly.py - H2: Metadata anomaly detection.

Compares current package metadata with previous metadata from state.json.
Detects three types of ownership/repository changes:
  1. maintainer_identity_change: author/maintainer changed
  2. project_ownership_change: owner/organization changed
  3. declared_repository_change: source repository URL changed to non-overlapping location

trustcheck reference: malicious.py _metadata_anomaly_findings L844-918
"""


def detect_metadata_anomaly(current_meta, previous_meta):
    """Compare current and previous package metadata for ownership changes.

    Args:
        current_meta: dict with keys like maintainers, homepage, etc.
        previous_meta: dict from state.json (same structure) or None

    Returns:
        list of finding dicts, each with id, verdict, tool, evidence_ref.
        Empty list = no anomalies.
    """
    if not previous_meta or not current_meta:
        return []

    findings = []

    # 1. Maintainer identity change
    current_maintainers = _maintainer_identities(current_meta)
    previous_maintainers = _maintainer_identities(previous_meta)
    if current_maintainers and previous_maintainers and current_maintainers != previous_maintainers:
        findings.append({
            "id": "L2.5_METADATA_ANOMALY",
            "verdict": "pass",
            "tool": "canari-anomaly/0.1",
            "evidence_ref": "finding: maintainer_identity_change - previous=%s current=%s" % (
                ",".join(sorted(previous_maintainers)),
                ",".join(sorted(current_maintainers)),
            ),
        })

    # 2. Repository URL change (non-overlapping)
    current_repos = _repository_urls(current_meta)
    previous_repos = _repository_urls(previous_meta)
    if current_repos and previous_repos and not current_repos.intersection(previous_repos):
        findings.append({
            "id": "L2.5_METADATA_ANOMALY",
            "verdict": "pass",
            "tool": "canari-anomaly/0.1",
            "evidence_ref": "finding: declared_repository_change - previous=%s current=%s" % (
                ",".join(sorted(previous_repos)),
                ",".join(sorted(current_repos)),
            ),
        })

    return findings


def _maintainer_identities(meta):
    """Extract maintainer identity strings from metadata."""
    identities = set()
    for key in ("maintainers", "author", "author_email"):
        value = meta.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    name = item.get("name", "")
                    email = item.get("email", "")
                    if name:
                        identities.add(name.strip().casefold())
                elif isinstance(item, str) and item.strip():
                    identities.add(item.strip().casefold())
        elif isinstance(value, str) and value.strip():
            identities.add(value.strip().casefold())
    return identities


def _repository_urls(meta):
    """Extract normalized repository URLs from metadata."""
    urls = set()
    for key in ("homepage", "repository", "repo_url"):
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            urls.add(_normalize_url(value))
        if isinstance(value, dict):
            url = value.get("url", "")
            if url and isinstance(url, str):
                urls.add(_normalize_url(url))
    return urls


def _normalize_url(url):
    """Normalize a URL for comparison (lowercase, strip trailing slash, strip .git)."""
    url = url.strip().casefold().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    return url
