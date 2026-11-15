# -*- coding: utf-8 -*-
"""publish_log.py - rebuild the public artefacts from docs/log.

Writes:
  docs/log/bundle-latest.json   an offline-verifiable bundle for the newest entry
  docs/log/index.html           human-readable listing of entries and heads

Deliberately does not touch log.jsonl / heads.jsonl / public_key.json: those
are the evidence. Regenerating the presentation layer must never be able to
alter it.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from canari.logstore import open_log  # noqa: E402

LOG_DIR = os.path.join(ROOT, "docs", "log")
LOG_ID = "canari-snapshot-log"


def build_bundle(L, path):
    """Bundle the newest entry against the newest head."""
    n = L.size()
    if n == 0:
        raise SystemExit("log is empty; nothing to bundle")
    head = L.last_head()
    if not head:
        raise SystemExit("no signed head; run log_daily.py first")
    idx = min(head["body"]["size"] - 1, n - 1)
    b = L.export_bundle(idx)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(b, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    return b


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def build_page(L, path):
    entries = L.entry_objs()
    heads = L.heads()
    pub = L.public_key()
    last = heads[-1]["body"] if heads else None
    rows = []
    for e in entries:
        p = e.get("payload") or {}
        states = p.get("states") or {}
        statestr = " ".join("%s=%s" % (k, v) for k, v in sorted(states.items()))
        rows.append(
            "<tr><td>%s</td><td>%s</td><td><code>%s...</code></td>"
            "<td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (e.get("seq"), esc(e.get("timestamp")), esc((p.get("sha256") or "")[:16]),
               esc(p.get("bytes", "")), esc(p.get("rows", "")), esc(statestr),
               esc(p.get("source_probed_at", ""))))
    headrows = ["<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>"
                % (h["body"]["size"], esc(h["body"]["root"]), esc(h["body"]["timestamp"]))
                for h in heads]
    root = last["root"] if last else ""
    size = last["size"] if last else 0
    ts = last["timestamp"] if last else ""
    kid = esc(pub.get("keyid", ""))
    page = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Canari append-only log</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 body{font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
      max-width:1080px;margin:2rem auto;padding:0 1rem;color:#1b1f24;background:#fbfbfc}
 h1{font-size:1.5rem;margin-bottom:.2rem}
 h2{font-size:1.1rem;margin-top:2rem;border-bottom:1px solid #e3e6ea;padding-bottom:.3rem}
 .sub{color:#5b6570;margin-top:0}
 table{border-collapse:collapse;width:100%;font-size:13px}
 th,td{border-bottom:1px solid #e8ebee;padding:.45rem .5rem;text-align:left;vertical-align:top}
 th{background:#f2f4f6;font-weight:600}
 code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
 .box{background:#fff;border:1px solid #e3e6ea;border-radius:8px;padding:1rem 1.2rem}
 .note{color:#5b6570;font-size:13px}
</style></head><body>
<h1>Canari append-only log</h1>
<p class="sub">A signed, append-only record of what public agent-component data
looked like on a given day. Checkable offline, without trusting this server.</p>

<div class="box">
<p><strong>Latest signed tree head</strong></p>
<p>size <code>__SIZE__</code><br>root <code>__ROOT__</code><br>signed __TS__</p>
<p class="note">Verify: <code>node docs/spec/verify_offline.js docs/log/bundle-latest.json --root __ROOT__</code></p>
</div>

<h2>Entries</h2>
<table><tr><th>#</th><th>logged at (UTC)</th><th>sha256</th><th>bytes</th>
<th>rows</th><th>upstream states</th><th>upstream probed</th></tr>
__ROWS__
</table>

<h2>Published tree heads</h2>
<table><tr><th>size</th><th>root</th><th>signed at</th></tr>__HEADROWS__</table>

<h2>What a passing proof means</h2>
<p>Each entry commits to the exact bytes and SHA-256 of a published dataset
(<a href="https://mcpcost.ulehla.dev/">mcpcost</a>, CC BY 4.0). The tree head
signature proves who logged it; the inclusion proof proves the entry is in the
log; the consistency proof proves a later head still contains an earlier one.
None of that says the underlying data is correct -- only that the record was
not added, dropped, or rewritten after the fact.</p>

<h2>Verification</h2>
<p class="note">Two independent implementations, both offline:
<code>python -m canari.verify_offline bundle-latest.json</code> and
<code>node docs/spec/verify_offline.js bundle-latest.json</code>. Format:
<a href="../spec/append-only-log.md">append-only-log.md</a>.
Test vectors: <a href="../spec/merkle-vectors.json">merkle-vectors.json</a> (168 cases).</p>

<p class="note">public key id <code>__KID__</code></p>
</body></html>
"""
    page = (page.replace("__SIZE__", str(size)).replace("__ROOT__", root)
                .replace("__TS__", esc(ts)).replace("__ROWS__", "".join(rows))
                .replace("__HEADROWS__", "".join(headrows)).replace("__KID__", kid))
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(page)


def main():
    L = open_log(LOG_DIR, log_id=LOG_ID)
    audit = L.audit()
    if not audit["ok"]:
        print("AUDIT FAILED: %s" % "; ".join(audit["errors"]), file=sys.stderr)
        return 2
    b = build_bundle(L, os.path.join(LOG_DIR, "bundle-latest.json"))
    build_page(L, os.path.join(LOG_DIR, "index.html"))
    print("size=%d root=%s entry=%d" % (L.size(), b["tree_head"]["body"]["root"],
                                        b["entry"]["index"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
