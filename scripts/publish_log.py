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

# The internal log_id, embedded in every native head body since the first
# entry. It cannot be changed without re-signing history, which this project
# refuses to do.
LOG_ID = "canari-snapshot-log"

# The c2sp origin line, which is what a witness keys its state by. It is
# deliberately NOT the internal log_id:
#
#   * an origin must never change once a witness has co-signed it, so it has to
#     be collision-resistant from the start -- a bare name like
#     "canari-snapshot-log" could be claimed by any other operator, and a
#     witness would then hold state for two different logs under one key;
#   * a namespaced URL we control ("github.com/<owner>/<repo>/log") cannot
#     collide by accident.
#
# The two identities describe the same tree: the checkpoint's (size, root) must
# equal a signed head body's (size, root), which is checkable by anyone. The
# mismatch between the two labels is documented in docs/spec/append-only-log.md
# section 12.1 rather than papered over.
C2SP_ORIGIN = "github.com/lanbass869-cell/canari/log"


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


def write_immutable_heads(L, heads_dir):
    """Write one file per published head, named by its root.

    Why this exists (real bug, 2026-11-15): the OpenTimestamps proof was made
    over docs/log/head-latest.json. That file is a *mutable pointer* -- the
    daily job rewrites it (new audit block, new appended list), so its bytes
    change and the OTS commitment no longer matches the file on disk. The proof
    then 404s at every calendar and proves nothing.

    A timestamp is only meaningful over bytes that never change. Each historic
    head body is immutable by construction (it is fixed once signed), so we
    write it to heads/<size>-<root>.json and anchor THAT. The filename contains
    the root, so the file is self-identifying: if it is ever altered, the
    filename contradicts its content.
    """
    os.makedirs(heads_dir, exist_ok=True)
    written = []
    for h in L.heads():
        body = h["body"]
        name = "%06d-%s.json" % (body["size"], body["root"])
        path = os.path.join(heads_dir, name)
        payload = canonical_head_bytes(body)
        if os.path.exists(path):
            if open(path, "rb").read() != payload:
                raise SystemExit(
                    "REFUSING to overwrite immutable head %s with different bytes" % name)
            written.append((path, False))
            continue
        with open(path, "wb") as f:
            f.write(payload)
        written.append((path, True))
    return written


def canonical_head_bytes(body):
    return json.dumps(body, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def apply_corrections(entries):
    """Return (effective_entries, corrections) applying `correction` records.

    The log itself is never rewritten: entry N keeps whatever it said. For a
    reader, though, showing a field we already know is wrong (and that we
    corrected in public) is just confusing. So the rendered view shows the
    corrected value and lists the correction so nothing is hidden.
    """
    effective = [dict(e, payload=dict(e.get("payload") or {})) for e in entries]
    corrections = []
    for i, e in enumerate(entries):
        p = e.get("payload") or {}
        if p.get("kind") != "correction":
            continue
        corrections.append({"seq": i, "corrects_seq": p.get("corrects_seq"),
                            "field": p.get("field"), "old": p.get("old_value"),
                            "new": p.get("new_value"), "reason": p.get("reason", "")})
        tgt = p.get("corrects_seq")
        if isinstance(tgt, int) and 0 <= tgt < len(effective):
            effective[tgt]["payload"][p.get("field")] = p.get("new_value")
            effective[tgt]["corrected"] = True
    return effective, corrections


def build_page(L, path):
    entries, corrections = apply_corrections(L.entry_objs())
    heads = L.heads()
    pub = L.public_key()
    last = heads[-1]["body"] if heads else None
    rows = []
    for i, e in enumerate(entries):
        p = e.get("payload") or {}
        states = p.get("states") or {}
        statestr = " ".join("%s=%s" % (k, v) for k, v in sorted(states.items()))
        kind = p.get("kind") or e.get("kind") or ""
        if kind == "correction":
            # A correction record has no snapshot fields; rendering it as a
            # blank snapshot row (the first run did) makes the table look
            # broken. Point at the corrected entry instead.
            rows.append(
                "<tr><td>%s</td><td>%s</td><td colspan=\"5\">correction of "
                "entry %s: <code>%s</code> = <code>%s</code></td></tr>"
                % (i, esc(e.get("timestamp")), p.get("corrects_seq"),
                   esc(p.get("field")), esc(p.get("new_value"))))
            continue
        if kind == "verdict":
            subject = p.get("component") or ""
            rows.append(
                "<tr><td>%s</td><td>%s</td><td colspan=\"2\"><code>%s</code></td>"
                "<td colspan=\"3\">verdict <strong>%s</strong> "
                "(bundle sha256 <code>%s...</code>)</td></tr>"
                % (i, esc(e.get("timestamp")), esc(subject), esc(p.get("verdict")),
                   esc((p.get("bundle_sha256") or "")[:16])))
            continue
        rows.append(
            "<tr><td>%s</td><td>%s</td><td><code>%s...</code></td>"
            "<td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (i, esc(e.get("timestamp")), esc((p.get("sha256") or "")[:16]),
               esc(p.get("bytes", "")), esc(p.get("rows", "")), esc(statestr),
               esc(p.get("source_probed_at", ""))))
    headrows = ["<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>"
                % (h["body"]["size"], esc(h["body"]["root"]), esc(h["body"]["timestamp"]))
                for h in heads]
    root = last["root"] if last else ""
    size = last["size"] if last else 0
    ts = last["timestamp"] if last else ""
    kid = esc(pub.get("keyid", ""))
    corr_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td><code>%s</code></td>"
        "<td>%s</td></tr>" % (c["seq"], c["corrects_seq"], esc(c["field"]),
                              esc(c["new"]), esc(c["reason"]))
        for c in corrections)
    corr_block = ("<h2>Corrections</h2>"
                  "<p class=\"note\">This log is append-only, so a published field "
                  "is never edited. When a committed entry's metadata turns out to "
                  "be wrong, a correction record is appended and the entry above "
                  "shows the corrected value. The original value stays in "
                  "<code>log.jsonl</code> and is covered by the same proofs.</p>"
                  "<table><tr><th>seq</th><th>corrects</th><th>field</th>"
                  "<th>corrected value</th><th>reason</th></tr>%s</table>"
                  % corr_rows) if corrections else ""
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
<table><tr><th>#</th><th>logged at (UTC)</th><th>sha256 / subject</th><th>bytes</th>
<th>rows</th><th>upstream states / verdict</th><th>upstream probed</th></tr>
__ROWS__
</table>

__CORRECTIONS__
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
                .replace("__HEADROWS__", "".join(headrows)).replace("__KID__", kid)
                .replace("__CORRECTIONS__", corr_block))
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(page)


def main():
    L = open_log(LOG_DIR, log_id=LOG_ID, c2sp_origin=C2SP_ORIGIN)
    audit = L.audit()
    if not audit["ok"]:
        print("AUDIT FAILED: %s" % "; ".join(audit["errors"]), file=sys.stderr)
        return 2
    b = build_bundle(L, os.path.join(LOG_DIR, "bundle-latest.json"))
    build_page(L, os.path.join(LOG_DIR, "index.html"))
    # The c2sp checkpoint note at a stable path: this is what a witness client
    # polls. Without it a witness has nothing to co-sign, no matter how correct
    # our Merkle proofs are.
    try:
        note = L.checkpoint_note(origin=C2SP_ORIGIN)
        chk = L.verify_checkpoint_note(note)
        if not chk["ok"]:
            raise SystemExit("our own checkpoint note does not verify")
        with open(os.path.join(LOG_DIR, "checkpoint.txt"), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write(note)
    except Exception as e:
        print("checkpoint export failed: %s: %s" % (type(e).__name__, e),
              file=sys.stderr)
    # head-latest.json is the pointer everything downstream pins against
    # (CI verification, a consumer's --root, the OTS target choice). It used to
    # be written by log_daily.py, which meant that any later step that sealed a
    # new head (log_verdicts.py) left it stale -- CI then pinned yesterday's
    # root against today's bundle and failed, which is exactly how this was
    # found (run 43685282965). Exactly one writer now: this function.
    audit = L.audit()
    with open(os.path.join(LOG_DIR, "head-latest.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump({"appended": [], "head": L.last_head(), "audit": audit},
                  f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")

    heads = write_immutable_heads(L, os.path.join(LOG_DIR, "heads"))
    new_heads = [p for p, created in heads if created]
    print("size=%d root=%s entry=%d immutable_heads=%d new=%d"
          % (L.size(), b["tree_head"]["body"]["root"], b["entry"]["index"],
             len(heads), len(new_heads)))
    for p in new_heads:
        print("  new head file: %s" % os.path.basename(p))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
