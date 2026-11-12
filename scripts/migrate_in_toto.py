# -*- coding: utf-8 -*-
"""migrate_in_toto.py - rewrite the store as in-toto Statement v1 bundles.

Before this migration a bundle was a DSSE envelope whose payload was a bare
Canari attestation body. GUAC/cosign cannot consume that: they look for
`_type: https://in-toto.io/Statement/v1`, an ARRAY `subject` with
`digest.sha256`, plus `predicateType` / `predicate`. Measured on a real bundle:
all four were wrong or missing.

The migration is content-preserving: the attestation body moves verbatim into
`predicate`, the signature is recomputed over the new payload with the SAME
private key, and supersession pointers are remapped so the whole chain stays
connected.

Two digest definitions are involved:
  old      sha256(canonical FULL body incl. the inline signature block)
  new      payload_digest(body) - canonical body EXCLUDING the signature
Because the new definition is signature-independent, a future re-sign cannot
orphan the chain (that was a latent defect in the old scheme).

Usage:
  python scripts/migrate_in_toto.py            # dry run, prints the plan
  python scripts/migrate_in_toto.py --apply    # rewrite bundles + state.json
"""
import argparse
import base64
import collections
import glob
import json
import os
import shutil
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from canari.signing import (load_private_key, payload_digest, sign_attestation,
                            unwrap_statement, verify_signed)

OUT = os.path.join(REPO, "out")
ATT = os.path.join(OUT, "attestations")


def old_digest(body):
    """Digest scheme used by releases before this migration."""
    import hashlib
    return hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    att = os.path.join(a.out, "attestations")
    files = sorted(glob.glob(os.path.join(att, "*.bundle.json")))
    if not files:
        print("no bundles under", att)
        return 1

    key_path = os.path.join(a.out, "private_key.pem")
    if not os.path.exists(key_path):
        print("missing private key:", key_path)
        return 1
    signer = load_private_key(key_path)
    if signer is None:
        print("cannot load private key:", key_path)
        return 1
    pub = signer.public_key.to_dict()

    # ---- pass 1: read every bundle, grab the attestation body exactly as written
    entries = []
    already = 0
    unreadable = []
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8") as f:
                bundle = json.load(f)
            body = bundle.get("payload")
            if not isinstance(body, dict):
                unreadable.append((fp, "no top-level payload"))
                continue
            # Idempotency: the migration state lives in the SIGNED payload, not
            # in the top-level mirror (which is always the bare attestation).
            # Checking the mirror made every re-run re-sign the whole store and
            # then report bogus dangling pointers, because the pointers it tried
            # to look up were already in the new digest scheme.
            try:
                raw_signed = json.loads(base64.b64decode(bundle["envelope"]["payload"]))
            except Exception:
                raw_signed = None
            if isinstance(raw_signed, dict) and raw_signed.get("_type") == "https://in-toto.io/Statement/v1":
                already += 1
                continue
            s = body.get("subject") or {}
            entries.append({
                "path": fp,
                "body": body,
                "old_digest": old_digest(body),
                "registry": s.get("registry", "?"),
                "name": s.get("name", "?"),
                "generated_at": body.get("generated_at", ""),
            })
        except Exception as e:                                # noqa: BLE001
            unreadable.append((fp, str(e)[:120]))

    print("bundles            : %d" % len(files))
    print("already in-toto    : %d" % already)
    print("to migrate         : %d" % len(entries))
    print("unreadable         : %d" % len(unreadable))
    for fp, why in unreadable[:10]:
        print("   !", os.path.basename(fp), why)

    groups = collections.defaultdict(list)
    for e in entries:
        groups[(e["registry"], e["name"])].append(e)
    for items in groups.values():
        items.sort(key=lambda x: (x["generated_at"], os.path.basename(x["path"])))

    n_remapped = 0
    n_dangling = 0
    # ---- pass 2: oldest -> newest, remap supersedes, re-sign
    for key, items in sorted(groups.items()):
        done = {}
        for e in items:
            body = dict(e["body"])
            sup = body.get("supersedes")
            if sup:
                if sup in done:
                    body["supersedes"] = done[sup]
                    n_remapped += 1
                elif sup == e["old_digest"]:
                    body.pop("supersedes", None)   # self-reference: drop
                elif sup == payload_digest(body):
                    pass                            # already in the new scheme
                else:
                    n_dangling += 1
            signed = sign_attestation(body, signer)
            new_d = payload_digest(signed["payload"])
            done[e["old_digest"]] = new_d
            e["new_body"] = body
            e["new_bundle"] = {"envelope": signed["envelope"],
                               "payload": signed["payload"]}
            e["new_digest"] = new_d

    print("supersedes remapped: %d" % n_remapped)
    print("dangling pointers  : %d (left as-is)" % n_dangling)

    if not a.apply:
        print("\nDRY RUN - nothing written. Re-run with --apply.")
        return 0

    # ---- backup, then write
    bak = os.path.join(a.out, "_pre_intoto_backup")
    if not os.path.isdir(bak):
        os.makedirs(bak)
        for fp in files:
            shutil.copy2(fp, os.path.join(bak, os.path.basename(fp)))
        print("backup written to", bak)

    # map old->new digest for state.json
    remap = {}
    for items in groups.values():
        for e in items:
            remap[e["old_digest"]] = e["new_digest"]

    written = 0
    for items in groups.values():
        for e in items:
            tmp = e["path"] + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(e["new_bundle"], f, ensure_ascii=False, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, e["path"])
            written += 1

    # ---- state.json: remap attestation_digest
    state_path = os.path.join(a.out, "state.json")
    if os.path.exists(state_path):
        with open(state_path, "r", encoding="utf-8") as f:
            state = json.load(f)
        changed = 0
        for comp in (state.get("components") or {}).values():
            d = comp.get("attestation_digest")
            if isinstance(d, str) and d in remap:
                comp["attestation_digest"] = remap[d]
                changed += 1
        shutil.copy2(state_path, state_path + ".pre-intoto")
        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=1)
        print("state.json digests remapped: %d" % changed)

    print("bundles rewritten  : %d" % written)

    # ---- self-check
    bad_sig = 0
    for items in groups.values():
        for e in items:
            ok, body, err = verify_signed(e["new_bundle"]["envelope"], pub)
            if not ok or body.get("verdict") != e["body"].get("verdict"):
                bad_sig += 1
    print("post-migration signature/verdict mismatches: %d" % bad_sig)
    return 0 if bad_sig == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
