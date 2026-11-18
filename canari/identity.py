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


def _get_json(url, timeout=25, accept=None):
    headers = {"User-Agent": UA}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
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


_SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"


def repo_from_provenance_doc(doc):
    """Publishing repository from a PyPI provenance object, or None.

    PEP 740 does not expose a standalone endpoint: the Simple JSON API lists
    `files[].provenance` (a URL) for release files that carry attestations, and
    fetching that URL returns `attestation_bundles[].publisher.repository`.

    That publisher repository is signed by PyPI's Trusted Publishing, so it is a
    stronger link than `project_urls` (which is self-declared metadata). Measured
    2026-11-18: of 135 PyPI MCP packages with no repository in their metadata, 15
    (11.1%) are recoverable this way; the other 116 have no attestation at all.
    """
    for bundle in (doc or {}).get("attestation_bundles") or []:
        repo = ((bundle or {}).get("publisher") or {}).get("repository")
        if repo:
            return normalize_repo("https://github.com/" + str(repo).strip("/"))
    return None


def pypi_provenance_repo(project, timeout=20):
    """Ask PyPI for this project's Trusted Publishing repository, best effort."""
    try:
        simple = _get_json("https://pypi.org/simple/%s/"
                           % urllib.parse.quote(project), accept=_SIMPLE_JSON,
                           timeout=timeout)
    except Exception:
        return None
    for f in reversed((simple or {}).get("files") or []):
        url = (f or {}).get("provenance")
        if not url:
            continue
        try:
            return repo_from_provenance_doc(_get_json(url, timeout=timeout))
        except Exception:
            continue
    return None


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


def cluster_id(repository):
    """Content-addressed cluster id. One function, so sign/verify/gate agree."""
    import hashlib as _hl
    repo = normalize_repo(repository)
    if not repo:
        return None
    return "sha256:" + _hl.sha256(repo.encode("utf-8")).hexdigest()[:24]


def claim_filename(repository):
    """The filename canari-identity sign writes for this repository."""
    cid = cluster_id(repository)
    return None if cid is None else cid.split(":")[-1] + ".identity.json"


def _subject(record):
    """Accept a bare attestation, a bundle, or a statement; return the subject."""
    if not isinstance(record, dict):
        return {}
    if "subject" in record and isinstance(record["subject"], dict):
        return record["subject"]
    payload = record.get("payload")
    if isinstance(payload, dict):
        if isinstance(payload.get("subject"), dict):
            return payload["subject"]
        pred = payload.get("predicate")
        if isinstance(pred, dict) and isinstance(pred.get("subject"), dict):
            return pred["subject"]
    pred = record.get("predicate")
    if isinstance(pred, dict):
        return pred.get("subject") or {}
    return {}


def build_clusters(records):
    """Group records by the repository they were published from.

    A cluster is one publishing repository and every (registry, name, version)
    that claims it. The id is content-addressed (sha256 of the normalised
    repository), so two independent runs over the same data produce the same id
    and cannot silently disagree about which cluster is which.

    Records with no repository are skipped, and the count is reported instead of
    being folded into a cluster: they are UNKNOWN, and an unknown is not a member.
    """
    import hashlib as _hl
    clusters = {}
    skipped = 0
    for rec in records:
        subj = _subject(rec)
        repo = normalize_repo(subj.get("repository"))
        if not repo:
            skipped += 1
            continue
        name = subj.get("name") or ""
        registry = subj.get("registry") or ""
        member = {"registry": registry, "name": name,
                  "version": subj.get("version") or ""}
        bucket = clusters.setdefault(repo, {"repository": repo, "members": []})
        if member not in bucket["members"]:
            bucket["members"].append(member)
    out = []
    for repo, bucket in sorted(clusters.items()):
        members = sorted(bucket["members"],
                         key=lambda m: (m["registry"], m["name"], m["version"]))
        names = sorted({m["name"] for m in members})
        out.append({
            "id": cluster_id(repo),
            "repository": repo,
            "registries": sorted({m["registry"] for m in members}),
            "members": members,
            # ★2026-11-18 (measured on real data): one repository can publish
            # several *different* components - `modelcontextprotocol/servers`
            # ships fetch / git / time. A repository link is a project-family
            # link, not a proof that two names are the same package. The count
            # is reported so a reader can see a monorepo instead of inferring
            # sameness from the cluster.
            "distinct_names": len(names),
            "kind": "monorepo" if len(names) > 1 else "package",
        })
    return {"clusters": out, "without_repository": skipped,
            "records_with_repository": sum(len(c["members"]) for c in out)}


def find_conflicts(records):
    """Two shapes worth signing, and one that is only a question.

    repo_changed  the same (registry, name) was published from different
                  repositories over time - the identity moved, which is either a
                  transfer or a takeover, and either way the ledger must show it.
    name_collision the same bare name is used in different registries from
                  different repositories - `ato-mcp` on npm and PyPI are two
                  projects. This is the ambiguity measured on 2026-11-18; it is
                  reported, not judged, because a name clash is legal.
    """
    by_component = {}
    by_bare = {}
    for rec in records:
        subj = _subject(rec)
        repo = normalize_repo(subj.get("repository"))
        if not repo:
            continue
        name = subj.get("name") or ""
        registry = subj.get("registry") or ""
        by_component.setdefault((registry, name), set()).add(repo)
        by_bare.setdefault(name, {}).setdefault(repo, set()).add(registry)

    repo_changed = [
        {"registry": reg, "name": name, "repositories": sorted(repos)}
        for (reg, name), repos in sorted(by_component.items()) if len(repos) > 1
    ]
    name_collision = [
        {"name": name,
         "repositories": sorted(repos),
         "registries": sorted({r for regs in repos.values() for r in regs})}
        for name, repos in sorted(by_bare.items()) if len(repos) > 1
    ]
    return {"repo_changed": repo_changed, "name_collision": name_collision}


def load_store(store_dir):
    """Every attestation body under <store>/attestations (payload only)."""
    import glob
    import os as _os
    from canari.signing import read_signed_payload
    records, unreadable = [], []
    for path in sorted(glob.glob(_os.path.join(store_dir, "attestations", "*.json"))):
        try:
            with open(path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
        except Exception as e:
            unreadable.append({"path": path, "error": "not json: %s" % str(e)[:80]})
            continue
        payload, err = read_signed_payload(bundle)
        if err or not isinstance(payload, dict):
            unreadable.append({"path": path, "error": str(err)[:80]})
            continue
        records.append(payload)
    return records, unreadable


def _sign_cmd(a):
    import datetime as _dt
    import os as _os
    records, unreadable = load_store(a.store)
    built = build_clusters(records)
    conflicts = find_conflicts(records)
    out_dir = a.out or _os.path.join(a.store, "identity")
    observed = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    written, errors = sign_claims(built["clusters"], conflicts, observed, a.key, out_dir)
    report = {"clusters": len(built["clusters"]), "signed": len(written),
              "errors": errors, "out": out_dir,
              "without_repository": built["without_repository"]}
    if a.json:
        print(json.dumps(report, ensure_ascii=False, indent=1))
    else:
        print("clusters %d  signed %d  errors %d  -> %s" % (
            report["clusters"], report["signed"], len(errors), out_dir))
        if report["without_repository"]:
            print("  %d record(s) had no repository and produced no claim"
                  % report["without_repository"])
    return 0 if not errors else 1


def _verify_cmd(a):
    import glob
    import os as _os
    from canari.signing import verify_signed
    with open(a.key, "r", encoding="utf-8") as f:
        pub = json.load(f)
    ok_n = bad_n = 0
    failures = []
    for path in sorted(glob.glob(_os.path.join(a.claims, "*.identity.json"))):
        try:
            with open(path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
        except Exception as e:
            failures.append({"path": path, "error": "not json: %s" % str(e)[:80]})
            bad_n += 1
            continue
        good, claim, err = verify_signed(bundle.get("envelope") or {}, pub)
        if not good or not isinstance(claim, dict):
            failures.append({"path": path, "error": "signature: %s" % err})
            bad_n += 1
            continue
        bad = validate_claim(claim)
        if bad:
            failures.append({"path": path, "error": "; ".join(bad[:3])})
            bad_n += 1
        else:
            ok_n += 1
    if a.json:
        print(json.dumps({"verified": ok_n, "failed": bad_n,
                          "failures": failures[:10]}, indent=1))
    else:
        print("verified %d  failed %d" % (ok_n, bad_n))
        for f in failures[:5]:
            print("  %s: %s" % (f["path"], f["error"]))
    return 0 if bad_n == 0 else 1


def _clusters_cmd(a):
    import os as _os
    records, unreadable = load_store(a.store)
    built = build_clusters(records)
    conflicts = find_conflicts(records)
    report = {
        "store": a.store,
        "records": len(records),
        "unreadable": len(unreadable),
        "clusters": len(built["clusters"]),
        "members": built["records_with_repository"],
        "without_repository": built["without_repository"],
        "repo_changed": len(conflicts["repo_changed"]),
        "name_collision": len(conflicts["name_collision"]),
        "cross_registry_clusters": sum(1 for c in built["clusters"]
                                       if len(c["registries"]) > 1),
        "monorepo_clusters": sum(1 for c in built["clusters"]
                                 if c["kind"] == "monorepo"),
        "examples": conflicts["name_collision"][:5],
    }
    if a.write:
        _os.makedirs(a.write, exist_ok=True)
        with open(_os.path.join(a.write, "clusters.json"), "w", encoding="utf-8") as f:
            json.dump({"clusters": built["clusters"],
                       "without_repository": built["without_repository"],
                       "unreadable": unreadable}, f, ensure_ascii=False, indent=1)
        with open(_os.path.join(a.write, "conflicts.json"), "w", encoding="utf-8") as f:
            json.dump(conflicts, f, ensure_ascii=False, indent=1)
    if a.json:
        print(json.dumps(report, ensure_ascii=False, indent=1))
    else:
        print("records %d  clusters %d  members %d  without-repository %d" % (
            report["records"], report["clusters"], report["members"],
            report["without_repository"]))
        print("cross-registry clusters %d  repo-changed %d  name-collision %d  monorepo %d" % (
            report["cross_registry_clusters"], report["repo_changed"],
            report["name_collision"], report["monorepo_clusters"]))
        for ex in report["examples"]:
            print("  name collision: %s -> %s" % (ex["name"], " | ".join(ex["repositories"])))
    return 0


_CLAIM_TYPE = "https://agentcheck.dev/identity/v0.1"


def build_claim(cluster, conflicts, observed_at):
    """One signed statement: "these members are the same component, and here is why".

    The claim is deliberately narrow. It asserts a *link*, records the method that
    produced it (publishing repository, normalised), and repeats the conflicts
    visible for this cluster so a reader does not have to re-derive them. It does
    not assert that any member is safe - that stays the attestation's job.
    """
    related = [c for c in conflicts.get("name_collision", [])
               if c["name"] in {m["name"] for m in cluster["members"]}]
    return {
        "_type": _CLAIM_TYPE,
        "subject": {"repository": cluster["repository"],
                    "cluster_id": cluster["id"]},
        "members": cluster["members"],
        "registries": cluster["registries"],
        "kind": cluster.get("kind", "package"),
        "distinct_names": cluster.get("distinct_names", len(cluster["members"])),
        "method": "publishing-repository/v1",
        "method_note": ("members share one normalised publishing repository; a "
                        "missing repository is never treated as a match; one "
                        "repository may publish several different packages "
                        "(kind=monorepo), which is a project link, not proof that "
                        "two names are the same package"),
        "conflicts": {"name_collision": related},
        "observed_at": observed_at,
    }


def validate_claim(claim):
    """Structural check for an identity claim. Empty list = valid."""
    errs = []
    if not isinstance(claim, dict):
        return ["claim is not an object"]
    if claim.get("_type") != _CLAIM_TYPE:
        errs.append("_type must be %s" % _CLAIM_TYPE)
    subj = claim.get("subject")
    if not isinstance(subj, dict):
        errs.append("subject missing")
    else:
        if not isinstance(subj.get("repository"), str) or not subj["repository"]:
            errs.append("subject.repository must be a non-empty string")
        if not isinstance(subj.get("cluster_id"), str) or not subj["cluster_id"]:
            errs.append("subject.cluster_id must be a non-empty string")
    members = claim.get("members")
    if not isinstance(members, list) or not members:
        errs.append("members must be a non-empty list")
    else:
        for i, m in enumerate(members):
            if not isinstance(m, dict):
                errs.append("members[%d] is not an object" % i)
                continue
            for key in ("registry", "name"):
                if not isinstance(m.get(key), str) or not m[key]:
                    errs.append("members[%d].%s must be a non-empty string" % (i, key))
    if not isinstance(claim.get("observed_at"), str) or not claim["observed_at"]:
        errs.append("observed_at must be a non-empty string")
    if not isinstance(claim.get("conflicts"), dict):
        errs.append("conflicts must be an object")
    return errs


def sign_claims(clusters, conflicts, observed_at, key_path, out_dir):
    """Sign one claim per cluster. Returns (written paths, errors)."""
    import os as _os
    from canari.signing import load_private_key, sign_attestation
    signer = load_private_key(key_path)
    if signer is None:
        raise RuntimeError("could not load private key: %s" % key_path)
    _os.makedirs(out_dir, exist_ok=True)
    written, errors = [], []
    for cluster in clusters:
        claim = build_claim(cluster, conflicts, observed_at)
        bad = validate_claim(claim)
        if bad:
            errors.append({"cluster": cluster.get("id"), "errors": bad})
            continue
        bundle = sign_attestation(claim, signer)
        name = cluster["id"].split(":")[-1] + ".identity.json"
        path = _os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, ensure_ascii=False, indent=1)
        written.append(path)
    return written, errors


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="canari-identity",
        description="Ask whether two registry entries are the same component.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    chk = sub.add_parser("check", help="compare two registry:name specs")
    chk.add_argument("a")
    chk.add_argument("b")
    chk.add_argument("--json", action="store_true")
    cl = sub.add_parser("clusters", help="group a store by publishing repository")
    cl.add_argument("--store", default="out", help="attestation store dir (default: out)")
    cl.add_argument("--write", default=None, help="write clusters.json/conflicts.json here")
    cl.add_argument("--json", action="store_true")
    sg = sub.add_parser("sign", help="sign one identity claim per cluster")
    sg.add_argument("--store", default="out")
    sg.add_argument("--key", required=True, help="private key PEM")
    sg.add_argument("--out", default=None, help="output dir (default: <store>/identity)")
    sg.add_argument("--json", action="store_true")
    vf = sub.add_parser("verify", help="verify signed identity claims offline")
    vf.add_argument("--claims", required=True, help="directory of *.identity.json")
    vf.add_argument("--key", required=True, help="public key JSON")
    vf.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.cmd == "clusters":
        return _clusters_cmd(a)
    if a.cmd == "sign":
        return _sign_cmd(a)
    if a.cmd == "verify":
        return _verify_cmd(a)

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
