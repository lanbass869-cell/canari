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
PROXY = os.environ.get("CANARI_PROXY", "http://127.0.0.1:12000")


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
        with op.open(req, timeout=60) as r:
            return r.read().decode()

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


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="canari-release")
    ap.add_argument("--tag", default=None, help="e.g. v0.1.0; omit to only build+sign")
    ap.add_argument("--notes", default=None, help="markdown file for the release body")
    a = ap.parse_args(argv)
    build()
    print(checksum_and_sign())
    if a.tag:
        print("release:", github_release(a.tag, a.notes))
    else:
        print("artifacts built and signed in dist/ (no tag -> no GitHub release)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
