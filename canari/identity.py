# -*- coding: utf-8 -*-
"""identity.py - are two registry entries the same component?

The question this answers, in one line: `ato-mcp` exists on npm and on PyPI.
Same project, or two unrelated projects wearing one name? A name cannot answer
that. The publishing repository can: the same repository is the same project.

Measured 2026-11-18 (experiments/identity_conflict): of 101 bare names present on
both npm and PyPI inside one MCP Registry snapshot, 61 pointed at the same
repository and 40 at different ones - 33 of those under different GitHub owners.

Prior art, stated honestly: ecosyste.ms already serves repo -> packages for all
six million npm packages (`packages.ecosyste.ms/api/v1/packages/lookup?
repository_url=`). Canari does not rebuild that index. This module asks the two
registry APIs directly for one pair and returns a verdict, so the verdict can be
signed, kept in the append-only log and enforced at install time.

Usage:
    canari-identity check npm:ato-mcp pypi:ato-mcp [--json]

Exit codes: 0 same repository, 1 different repository, 2 unknown (no repository
URL on one side, or a lookup failed). Unknown is never reported as "same".
"""
import argparse
import json
import re
import sys
import urllib.parse
import urllib.request

UA = "canari-identity/0.1 (+https://github.com/lanbass869-cell/canari)"
_REPO_HOSTS = r"(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sr\.ht)"


def normalize_repo(value):
    """Canonical repository identity, or None when there is nothing to compare.

    Deliberately narrow: only host/owner/name survive. Two URLs that differ in
    scheme, `.git`, trailing slash, case or `git+` prefix must compare equal,
    and anything that is not a recognised host is lowercased and stripped so
    the comparison stays conservative rather than pretending to understand it.
    """
    if not value:
        return None
    if isinstance(value, dict):
        value = value.get("url") or ""
    url = str(value).strip().lower()
    if not url:
        return None
    url = re.sub(r"^git\+", "", url)
    url = url.replace("git://", "https://").replace("ssh://git@", "https://")
    url = re.sub(r"^git@([^:]+):", r"https://\1/", url)
    url = re.sub(r"\.git$", "", url)
    url = url.rstrip("/")
    m = re.search(_REPO_HOSTS + r"/([^/\s]+)/([^/?#\s]+)", url)
    if m:
        host = m.group(1)
        owner = m.group(2)
        name = m.group(3)
        # sr.ht uses ~owner/repo
        if host == "sr.ht":
            mm = re.search(r"sr\.ht/(~[^/]+)/([^/?#\s]+)", url)
            if mm:
                return "sr.ht/%s/%s" % (mm.group(1), mm.group(2))
        return "%s/%s/%s" % (host, owner, name)
    return url or None


def _get_json(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def repo_of_npm(name):
    data = _get_json("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
    repo = data.get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url")
    return normalize_repo(repo)


def repo_of_pypi(name):
    data = _get_json("https://pypi.org/pypi/%s/json" % urllib.parse.quote(name))
    info = data.get("info") or {}
    for key, val in (info.get("project_urls") or {}).items():
        low = (key or "").lower()
        if "repo" in low or "source" in low or "code" in low:
            got = normalize_repo(val)
            if got:
                return got
    return normalize_repo(info.get("home_page"))


def repo_of(spec):
    """'npm:@scope/name' or 'pypi:name' -> normalised repository URL."""
    if ":" not in spec:
        raise ValueError("expected registry:name, got %r" % spec)
    registry, name = spec.split(":", 1)
    registry = registry.strip().lower()
    if registry == "npm":
        return repo_of_npm(name)
    if registry == "pypi":
        return repo_of_pypi(name)
    raise ValueError("unsupported registry %r (npm, pypi)" % registry)


def classify(left, right):
    """('same' | 'different' | 'unknown', reason)."""
    if not left or not right:
        return "unknown", "no repository URL on at least one side"
    if left == right:
        return "same", "both sides publish from %s" % left
    return "different", "%s and %s are different repositories" % (left, right)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="canari-identity",
        description="Ask whether two registry entries are the same component.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    chk = sub.add_parser("check", help="compare two registry:name specs")
    chk.add_argument("a")
    chk.add_argument("b")
    chk.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    try:
        left, right = repo_of(a.a), repo_of(a.b)
    except Exception as e:
        if a.json:
            print(json.dumps({"error": str(e), "verdict": "unknown"}))
        else:
            sys.stderr.write("canari-identity: lookup failed: %s\n" % str(e)[:200])
        return 2

    verdict, reason = classify(left, right)
    if a.json:
        print(json.dumps({"a": a.a, "b": a.b, "a_repo": left, "b_repo": right,
                          "verdict": verdict, "reason": reason}, indent=1))
    else:
        print("%s vs %s: %s" % (a.a, a.b, verdict.upper()))
        print("  " + reason)
    return {"same": 0, "different": 1, "unknown": 2}[verdict]


if __name__ == "__main__":
    sys.exit(main())
