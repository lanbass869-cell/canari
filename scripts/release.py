# -*- coding: utf-8 -*-
"""release.py - build artifacts, checksum+sign them, and open a GitHub release.

Reproducible release process (see docs/release-process.md). PyPI upload is a
separate documented step because it needs a token this script does not hold.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(REPO, "dist")
GH = "https://api.github.com"
PROXY = os.environ.get("CANARI_PROXY")  # unset by default: no proxy assumptions
REPO_DESCRIPTION = ("Verdict ledger for AI agent components: signed, offline-verifiable "
                    "attestations with supersession history and an install gate. "
                    "Scans npm/PyPI/MCP Registry/dsh.")
REPO_HOMEPAGE = "https://pypi.org/project/canari-mcp/"
REPO_TOPICS = ["mcp", "mcp-server", "agent-security", "agent-skills", "ai-agents",
               "attestation", "dsse", "in-toto", "sigstore", "slsa",
               "supply-chain", "security"]


def _retry(fn, attempts=3, delay=2.0):
    """Retry a network call. The local proxy intermittently returns
    SSL: UNEXPECTED_EOF_WHILE_READING on the first handshake."""
    import time
    last = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - network layer, retry anything
            last = e
            if i < attempts - 1:
                time.sleep(delay * (i + 1))
    raise last


def _opener():
    import urllib.request
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}) if PROXY else urllib.request.ProxyHandler({}))


def build():
    subprocess.check_call([sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", DIST], cwd=REPO)


def checksum_and_sign():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = os.path.join(REPO, "out", "release_key.pem")
    if os.path.exists(key):
        priv = serialization.load_pem_private_key(open(key, "rb").read(), password=None)
    else:
        priv = Ed25519PrivateKey.generate()
        open(key, "wb").write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                         format=serialization.PublicFormat.Raw)
    lines = []
    for fn in sorted(os.listdir(DIST)):
        if fn.endswith((".whl", ".tar.gz")):
            h = hashlib.sha256(open(os.path.join(DIST, fn), "rb").read()).hexdigest()
            lines.append("%s  %s" % (h, fn))
    sums = ("\n".join(lines) + "\n").encode()
    open(os.path.join(DIST, "SHA256SUMS"), "wb").write(sums)
    open(os.path.join(DIST, "SHA256SUMS.sig"), "w", encoding="utf-8").write(
        json.dumps({"alg": "ed25519", "sig_b64": base64.b64encode(priv.sign(sums)).decode()}, indent=1))
    json.dump({"alg": "ed25519", "public_hex": pub.hex()},
              open(os.path.join(DIST, "release_public_key.json"), "w", encoding="utf-8"), indent=1)
    return sums.decode()


def github_release(tag, notes_path=None, repo="lanbass869-cell/canari"):
    import urllib.request
    token = open(os.environ.get("CANARI_GH_TOKEN_FILE", r"E:\RUANJIAN\.secure\github\token")).read().strip()
    body = open(notes_path, encoding="utf-8").read() if notes_path else "Release %s" % tag
    op = _opener()

    def api(method, url, data=None, raw=False, ctype="application/json"):
        payload = data if raw else (json.dumps(data).encode() if data is not None else None)
        req = urllib.request.Request(url, data=payload, method=method, headers={
            "User-Agent": "canari-release", "Authorization": "token %s" % token,
            "Accept": "application/vnd.github+json", "Content-Type": ctype})
        return _retry(lambda: op.open(req, timeout=60).read().decode())

    rel = json.loads(api("POST", "%s/repos/%s/releases" % (GH, repo),
                         {"tag_name": tag, "name": "Canari %s" % tag, "body": body,
                          "draft": False, "prerelease": False}))
    upload = rel["upload_url"].split("{")[0]
    for fn in sorted(os.listdir(DIST)):
        if fn.endswith((".whl", ".tar.gz")) or fn.startswith("SHA256SUMS") or fn.startswith("release_public_key"):
            api("POST", "%s?name=%s" % (upload, fn),
                open(os.path.join(DIST, fn), "rb").read(), raw=True,
                ctype="application/octet-stream")
            print("  uploaded", fn)
    return rel["html_url"]


def pypi_upload(dist_dir=None, skip_existing=True, token_file=None):
    """Publish every wheel/sdist in dist/ to PyPI.

    Lessons baked in (2026-11-10): twine's rich renderer crashes with
    UnicodeEncodeError on a GBK console AFTER the first file already uploaded,
    leaving a partial release - so force UTF-8 and disable the progress bar.
    """
    dist_dir = dist_dir or DIST
    tf = token_file or os.environ.get("CANARI_PYPI_TOKEN_FILE",
                                      r"E:\RUANJIAN\memory_hub\tokens_pypi_20260928.txt")
    token = None
    if os.path.exists(tf):
        for line in open(tf, encoding="utf-8"):
            if line.strip().startswith("pypi-"):
                token = line.strip()
                break
    if not token:
        token = os.environ.get("CANARI_PYPI_TOKEN")
    if not token:
        raise SystemExit("no PyPI token (set CANARI_PYPI_TOKEN or CANARI_PYPI_TOKEN_FILE)")

    files = [os.path.join(dist_dir, f) for f in sorted(os.listdir(dist_dir))
             if f.endswith((".whl", ".tar.gz"))]
    if not files:
        raise SystemExit("no distributions in %s" % dist_dir)
    env = dict(os.environ, TWINE_USERNAME="__token__", TWINE_PASSWORD=token,
               PYTHONIOENCODING="utf-8", PYTHONUTF8="1", NO_COLOR="1")
    if PROXY:
        env.setdefault("HTTPS_PROXY", PROXY)
        env.setdefault("HTTP_PROXY", PROXY)
    cmd = [sys.executable, "-m", "twine", "upload", "--disable-progress-bar"]
    if skip_existing:
        cmd.append("--skip-existing")
    cmd += files
    print("$ twine upload %s" % " ".join(os.path.basename(f) for f in files))
    rc = subprocess.call(cmd, cwd=REPO, env=env)
    if rc != 0:
        raise SystemExit("twine upload failed (rc=%d)" % rc)
    return True


def set_repo_metadata(repo="lanbass869-cell/canari", description=None,
                      homepage=None, topics=None):
    """Set description/homepage and topics. Topics need PUT /topics - PATCH /repo
    returns 200 but silently leaves topics empty (learned 2026-11-10)."""
    import urllib.request
    token = open(os.environ.get("CANARI_GH_TOKEN_FILE",
                                r"E:\RUANJIAN\.secure\github\token")).read().strip()
    op = _opener()

    def call(method, url, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "User-Agent": "canari-release", "Authorization": "token %s" % token,
            "Accept": "application/vnd.github+json", "Content-Type": "application/json"})
        return _retry(lambda: json.loads(op.open(req, timeout=30).read().decode()))

    body = {}
    if description:
        body["description"] = description
    if homepage:
        body["homepage"] = homepage
    if body:
        call("PATCH", "%s/repos/%s" % (GH, repo), body)
    if topics:
        call("PUT", "%s/repos/%s/topics" % (GH, repo), {"names": topics})
    d = call("GET", "%s/repos/%s" % (GH, repo))
    return {"description": d.get("description"), "topics": d.get("topics"),
            "homepage": d.get("homepage")}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="canari-release")
    ap.add_argument("--tag", default=None, help="e.g. v0.1.0; omit to only build+sign")
    ap.add_argument("--notes", default=None, help="markdown file for the release body")
    ap.add_argument("--pypi", action="store_true", help="also upload to PyPI")
    ap.add_argument("--no-build", action="store_true", help="reuse existing dist/")
    ap.add_argument("--metadata", action="store_true",
                    help="also refresh repo description/homepage/topics")
    a = ap.parse_args(argv)
    if not a.no_build:
        build()
    print(checksum_and_sign())
    if a.tag:
        print("release:", github_release(a.tag, a.notes))
    else:
        print("artifacts built and signed in dist/ (no tag -> no GitHub release)")
    if a.pypi:
        pypi_upload()
        print("pypi: uploaded")
    if a.metadata:
        import json as _json
        print("repo metadata:", _json.dumps(set_repo_metadata(
            description=REPO_DESCRIPTION, homepage=REPO_HOMEPAGE, topics=REPO_TOPICS),
            ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
