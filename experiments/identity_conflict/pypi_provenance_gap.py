"""Does PyPI Trusted Publishing provenance recover the packages whose metadata
has no repository? PEP 740 puts the answer in the Simple JSON API, not in a
separate endpoint: files[].provenance is a URL, and the provenance object carries
attestation_bundles[].publisher.repository."""
import json, os, sys, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE=os.path.dirname(os.path.abspath(__file__))
UA="canari-research/1.0"
ACC="application/vnd.pypi.simple.v1+json"

def get(url, accept=None, timeout=25):
    h={"User-Agent":UA}
    if accept: h["Accept"]=accept
    with urllib.request.urlopen(urllib.request.Request(url,headers=h),timeout=timeout) as r:
        return json.loads(r.read().decode())

def provenance_repo(proj):
    try:
        d=get("https://pypi.org/simple/%s/" % urllib.parse.quote(proj), ACC)
    except Exception as e:
        return None, "simple:%s" % type(e).__name__
    files=d.get("files") or []
    for f in reversed(files):
        purl=f.get("provenance")
        if not purl: continue
        try:
            p=get(purl)
        except Exception as e:
            return None, "provenance:%s" % type(e).__name__
        for b in (p.get("attestation_bundles") or []):
            pub=b.get("publisher") or {}
            if pub.get("repository"):
                return "github.com/" + pub["repository"].lower().strip("/"), None
    return None, "no-attestation" if files else "no-files"

if __name__ == "__main__":
    cov=json.load(open(os.path.join(HERE,"repo_coverage.json"),encoding="utf-8"))
    missing=[r for r in cov["rows"] if r["registry"]=="pypi" and not r["repository"]]
    print("PyPI rows without repository:", len(missing), flush=True)
    with ThreadPoolExecutor(max_workers=8) as ex:
        res=list(ex.map(lambda r: (r["name"],)+provenance_repo(r["name"]), missing))
    gained=[(n,repo) for n,repo,err in res if repo]
    reasons={}
    for n,repo,err in res:
        if not repo: reasons[err]=reasons.get(err,0)+1
    out={"total_without":len(missing),"recovered":len(gained),
         "recovery_rate": len(gained)/len(missing) if missing else 0,
         "failures_by_reason":reasons,
         "examples":gained[:20]}
    json.dump(out, open(os.path.join(HERE,"pypi_provenance_gap.json"),"w",encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print(json.dumps({k:v for k,v in out.items() if k!="examples"}, indent=1))
    for n,r in gained[:12]: print("  ", n, "->", r)
