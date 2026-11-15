# -*- coding: utf-8 -*-
"""verify_offline.py - verify a Canari log bundle with no network and no trust.

Deliberately self-contained: this file does NOT import the rest of `canari`.
The Merkle arithmetic and the signature check are re-implemented here in about
60 lines of hashlib + cryptography, because "our library verified our bundle"
is not evidence. A consumer who distrusts this project must be able to port
this file in an afternoon and check the same bytes.

What a passing bundle proves:
  1. the tree head was signed by the holder of the private key matching
     `public_key` (and the signature covers the domain-separated head body,
     so it cannot be replayed as a record or an attestation signature);
  2. `entry.data_b64` is the leaf at `entry.index` in a tree of `head.size`
     whose root is `head.root`;
  3. if a consistency block is present, the head at `from_head` is a prefix
     of the head at `tree_head` -- the later log did not drop or rewrite the
     earlier entries.

What it does NOT prove: that the payload inside the record is true, that the
publisher holds no other key, or that you are looking at the newest head ever
published. Those need out-of-band trust anchoring (a head you recorded
yourself, or a gossip witness).

Usage:
    python verify_offline.py bundle.json [--log-id ID] [--root HEX] [--min-size N]

Exit codes: 0 all checks passed, 2 a check failed, 3 bad usage/unreadable.
"""
import argparse
import base64
import hashlib
import json
import sys

SPEC = "canari-append-only-log/v1"
BUNDLE_SPEC = "canari-inclusion-bundle/v1"
SIGN_PREFIX = b"canari-tree-head/v1\x00"
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def verify_inclusion(data: bytes, index: int, size: int, root_hex: str, proof_hex) -> bool:
    if size <= 0 or index < 0 or index >= size:
        return False
    if size > (1 << 40) or len(proof_hex) > 64:
        return False
    r = _h(LEAF_PREFIX + data)
    fn, sn = index, size - 1
    for p_hex in proof_hex:
        try:
            p = bytes.fromhex(p_hex)
        except ValueError:
            return False
        if len(p) != 32 or sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            r = _h(NODE_PREFIX + p + r)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _h(NODE_PREFIX + r + p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r.hex() == root_hex


def verify_consistency(first: int, second: int, first_root: str, second_root: str,
                       proof_hex) -> bool:
    if first < 0 or second < first or second > (1 << 40) or len(proof_hex) > 64:
        return False
    if first == second:
        return len(proof_hex) == 0 and first_root == second_root
    if first == 0:
        return len(proof_hex) == 0
    prf = []
    for p_hex in proof_hex:
        try:
            p = bytes.fromhex(p_hex)
        except ValueError:
            return False
        if len(p) != 32:
            return False
        prf.append(p)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn == 0:
        fr = sr = bytes.fromhex(first_root)
        rest = prf
    else:
        if not prf:
            return False
        fr = sr = prf[0]
        rest = prf[1:]
    for c in rest:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            fr = _h(NODE_PREFIX + c + fr)
            sr = _h(NODE_PREFIX + c + sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _h(NODE_PREFIX + sr + c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr.hex() == first_root and sr.hex() == second_root


def verify_head_signature(head: dict, key: dict) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        body = head["body"]
        if body.get("spec") != SPEC:
            return False
        raw = bytes.fromhex(head["signature"]["sig"])
        if len(raw) != 64:
            return False
        if key.get("keytype", "ed25519") != "ed25519":
            return False
        pub = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(key["keyval"]["public"]))
        pub.verify(raw, SIGN_PREFIX + canonical_bytes(body))
        return True
    except Exception:
        return False


def _valid_head_body(body, log_id=None) -> str:
    if not isinstance(body, dict):
        return "head body is not an object"
    if body.get("spec") != SPEC:
        return "unsupported head spec: %r" % (body.get("spec"),)
    if log_id is not None and body.get("log_id") != log_id:
        return "log_id mismatch"
    size = body.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or not (0 <= size <= (1 << 40)):
        return "bad size %r" % (size,)
    root = body.get("root")
    if not isinstance(root, str) or len(root) != 64:
        return "bad root"
    try:
        bytes.fromhex(root)
    except ValueError:
        return "root is not hex"
    if not isinstance(body.get("timestamp"), str) or not body["timestamp"]:
        return "bad timestamp"
    return ""


def verify_bundle(bundle: dict, expected_log_id=None, expected_root=None,
                  min_size=0, pinned_prefix_root=None) -> dict:
    """Return {"ok": bool, "checks": [{"name","ok","detail"}], "log_id", "size", "root"}.

    Never raises for malformed input; malformed input is a failed check.
    """
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        return ok

    if not isinstance(bundle, dict):
        add("bundle.shape", False, "bundle is not a JSON object")
        return {"ok": False, "checks": checks}
    add("bundle.spec", bundle.get("spec") == BUNDLE_SPEC,
        "spec=%r" % (bundle.get("spec"),))

    log_id = bundle.get("log_id")
    if expected_log_id is not None:
        add("log_id.pinned", log_id == expected_log_id,
            "bundle=%r expected=%r" % (log_id, expected_log_id))

    key = bundle.get("public_key")
    if not isinstance(key, dict):
        add("public_key.present", False, "missing public_key")
        return {"ok": False, "checks": checks}
    add("public_key.present", True, "keyid field=%r" % (key.get("keyid"),))

    head = bundle.get("tree_head")
    if not isinstance(head, dict) or not isinstance(head.get("body"), dict):
        add("tree_head.present", False, "missing tree_head")
        return {"ok": False, "checks": checks}
    body = head["body"]
    err = _valid_head_body(body, log_id)
    add("tree_head.structure", not err, err)
    add("tree_head.signature", verify_head_signature(head, key),
        "ed25519 over canari-tree-head/v1\\x00 + canonical body")

    entry = bundle.get("entry") or {}
    try:
        data = base64.b64decode(entry.get("data_b64", ""), validate=True)
        data_ok = bool(data)
    except Exception:
        data, data_ok = b"", False
    add("entry.data_decodes", data_ok, "%d bytes" % len(data))

    index = entry.get("index")
    size = body.get("size")
    if data_ok and isinstance(index, int) and isinstance(size, int):
        add("entry.inclusion", verify_inclusion(
            data, index, size, body.get("root", ""), bundle.get("inclusion_proof") or []),
            "index=%d size=%d" % (index, size))
    else:
        add("entry.inclusion", False, "index or size missing/not an int")

    if expected_root is not None:
        add("root.pinned", body.get("root") == expected_root,
            "head=%r expected=%r" % (body.get("root"), expected_root))
    if min_size:
        add("size.min", isinstance(size, int) and size >= min_size,
            "size=%r min=%r" % (size, min_size))

    ckpt = bundle.get("checkpoint")
    if ckpt:
        # c2sp.org/tlog-checkpoint inside a c2sp.org/signed-note. Verified here
        # with the same ~20 lines a witness uses, not by importing our own
        # encoder: the point is that the bytes travel.
        try:
            text, style = _parse_note(ckpt)
            o, sz, rt = _parse_checkpoint_text(text)
            pub_bytes = bytes.fromhex(key["keyval"]["public"])
            good = _verify_note_sig(text, style, o, pub_bytes) and sz == size and rt.hex() == body.get("root")
            add("checkpoint.c2sp", good,
                "origin=%r size=%r root=%r" % (o, sz, rt.hex()[:16]))
        except Exception as e:
            add("checkpoint.c2sp", False, "%s: %s" % (type(e).__name__, e))

    cons = bundle.get("consistency")
    if cons:
        fh = cons.get("from_head") or {}
        fb = fh.get("body") or {}
        ferr = _valid_head_body(fb, log_id)
        add("consistency.from_head_structure", not ferr, ferr)
        add("consistency.from_head_signature", verify_head_signature(fh, key),
            "signed by the same published key")
        if not ferr and isinstance(size, int):
            add("consistency.proof", verify_consistency(
                fb.get("size", -1), size, fb.get("root", ""), body.get("root", ""),
                cons.get("proof") or []),
                "from=%r to=%r" % (fb.get("size"), size))
        else:
            add("consistency.proof", False, "unusable from_head")

    if pinned_prefix_root is not None:
        # The consumer recorded an earlier head root out of band. Demand that
        # the bundle's consistency block connects *that* root to the current
        # head. Without this, "the publisher is consistent with itself" can be
        # true while the consumer's own observation was rewritten away.
        if not cons:
            add("prefix.pinned", False,
                "bundle has no consistency block, so a pinned earlier root "
                "cannot be shown to be a prefix of this head")
        else:
            got = ((cons.get("from_head") or {}).get("body") or {}).get("root")
            add("prefix.pinned", got == pinned_prefix_root,
                "from_head.root=%r pinned=%r" % (got, pinned_prefix_root))
            if got == pinned_prefix_root and not ferr_ok(cons):
                add("prefix.chain", False, "consistency block did not verify")
            elif got == pinned_prefix_root:
                add("prefix.chain", True, "pinned root is a prefix of this head")

    return {"ok": all(c["ok"] for c in checks), "checks": checks,
            "log_id": log_id, "size": size, "root": body.get("root")}


EM_DASH = "\u2014"
LOG_KEY_TYPE = 0x01


def _b64d(text):
    import base64 as _b
    raw = _b.b64decode(text, validate=True)
    if _b.b64encode(raw).decode("ascii") != text:
        raise ValueError("non-canonical base64")
    return raw


def _parse_checkpoint_text(text):
    if not text.endswith("\n"):
        raise ValueError("checkpoint text must end with newline")
    lines = text[:-1].split("\n")
    if len(lines) < 3 or any(not x for x in lines):
        raise ValueError("checkpoint needs at least three non-empty lines")
    origin, size_s, root_b64 = lines[0], lines[1], lines[2]
    if not size_s.isdigit() or (size_s != "0" and size_s.startswith("0")):
        raise ValueError("bad size")
    root = _b64d(root_b64)
    if len(root) != 32:
        raise ValueError("root must be 32 bytes")
    return origin, int(size_s), root


def _parse_note(data):
    if not data.endswith("\n"):
        raise ValueError("note ends with newline")
    split = data.rfind("\n\n")
    if split < 0:
        raise ValueError("note needs a blank line before signatures")
    text, block = data[:split + 1], data[split + 2:]
    sigs = []
    for line in block[:-1].split("\n"):
        if not line.startswith(EM_DASH + " "):
            raise ValueError("signature line must start with em dash")
        rest = line[len(EM_DASH) + 1:]
        name, _, payload = rest.partition(" ")
        raw = _b64d(payload)
        if len(raw) < 5:
            raise ValueError("signature payload too short")
        sigs.append((name, raw[:4], raw[4:]))
    if not sigs:
        raise ValueError("no signature lines")
    return text, sigs


def _verify_note_sig(text, sigs, origin, pub_bytes):
    import hashlib as _h
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    want = _h.sha256(origin.encode("utf-8") + b"\n" + bytes([LOG_KEY_TYPE])
                     + pub_bytes).digest()[:4]
    for name, kid, sig in sigs:
        if name == origin and kid == want and len(sig) == 64:
            try:
                Ed25519PublicKey.from_public_bytes(pub_bytes).verify(
                    sig, text.encode("utf-8"))
                return True
            except Exception:
                return False
    return False


def ferr_ok(cons) -> bool:
    """True when the consistency block's from_head is structurally valid."""
    fb = ((cons or {}).get("from_head") or {}).get("body") or {}
    return _valid_head_body(fb, fb.get("log_id")) == ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Verify a Canari log bundle offline.")
    ap.add_argument("bundle")
    ap.add_argument("--log-id", default=None)
    ap.add_argument("--root", default=None, help="pin an expected head root (hex)")
    ap.add_argument("--min-size", type=int, default=0)
    ap.add_argument("--pinned-prefix", default=None,
                    help="a tree-head root you recorded earlier; proves this "
                         "head still contains that history")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args(argv)
    try:
        with open(a.bundle, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as e:
        print("cannot read bundle: %s" % e, file=sys.stderr)
        return 3
    rep = verify_bundle(bundle, a.log_id, a.root, a.min_size, a.pinned_prefix)
    if a.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1, sort_keys=True))
    else:
        for c in rep["checks"]:
            print("%s %s%s" % ("PASS" if c["ok"] else "FAIL", c["name"],
                               ("  (" + c["detail"] + ")") if c["detail"] else ""))
        print("RESULT: %s" % ("OK" if rep["ok"] else "FAILED"))
    return 0 if rep["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
