# -*- coding: utf-8 -*-
"""Census: do MCP clients verify server identity before dispatch?

Scans source trees (not tests/docs/examples) for four capability families.
Patterns are deliberately literal; each hit is reported with file+line so it can
be checked by hand rather than trusted.
"""
import json, os, re, sys

ROOT = r"E:\Temp\tbdig\clients"
SKIP_DIRS = {"node_modules","dist","build",".git","coverage","vendor","third_party",
             "test","tests","__tests__","spec","docs","doc","examples","example",
             "fixtures","benchmarks","bench",".github",".venv","venv","site-packages"}
EXTS = {".py",".ts",".tsx",".js",".jsx",".go",".rs",".java",".kt",".cs"}

FAMILIES = {
 "TLS_DISABLED": [r"rejectUnauthorized\s*:\s*false", r"NODE_TLS_REJECT_UNAUTHORIZED",
                  r"verify\s*=\s*False", r"InsecureSkipVerify\s*:\s*true",
                  r"check_hostname\s*=\s*False", r"ssl\._create_unverified_context"],
 "PINNING":      [r"cert(ificate)?[_ ]?pinning", r"\bspki\b", r"fingerprints?",
                  r"publicKeyPinning", r"pin_?sha256", r"tls.*pin"],
 "ENDPOINT_CHANGE": [r"url\s*(has\s*)?changed", r"endpoint.*(differs|changed)",
                     r"previous(ly)?_?(url|endpoint)", r"unexpected.*(url|endpoint)",
                     r"host.*changed", r"redirect.*(endpoint|server)"],
 "ATTESTATION":  [r"attestation", r"sigstore", r"cosign", r"\bdsse\b", r"in-?toto",
                  r"provenance", r"verify_signature", r"signature_?verif"],
 "ALLOWLIST":    [r"allowed_?servers", r"trusted_?servers", r"server_?allowlist",
                  r"pinned_?servers", r"trust_?store"],
}

def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in EXTS:
                p = os.path.join(dirpath, fn)
                if os.path.getsize(p) > 2_000_000:
                    continue
                yield p

results = {}
for repo in sorted(os.listdir(ROOT)):
    base = os.path.join(ROOT, repo)
    if not os.path.isdir(base): continue
    # tarball extraction nests one level
    subs = [d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]
    if len(subs) == 1: base = os.path.join(base, subs[0])
    hits = {k: [] for k in FAMILIES}
    nfiles = 0
    for p in iter_files(base):
        nfiles += 1
        try:
            txt = open(p, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        for fam, pats in FAMILIES.items():
            for pat in pats:
                for m in re.finditer(pat, txt, re.I):
                    ln = txt.count("\n", 0, m.start()) + 1
                    hits[fam].append((os.path.relpath(p, base), ln, txt.splitlines()[ln-1].strip()[:120]))
    results[repo] = {"files": nfiles, "hits": {k: v[:5] for k, v in hits.items()},
                     "counts": {k: len(v) for k, v in hits.items()}}
    print("%-42s files=%-6d %s" % (repo.replace("__","/"), nfiles,
          " ".join("%s=%d" % (k, len(hits[k])) for k in FAMILIES)))
json.dump(results, open(r"E:\Temp\tbdig\_census.json","w",encoding="utf-8"), ensure_ascii=False, indent=1)
