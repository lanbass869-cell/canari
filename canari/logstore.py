# -*- coding: utf-8 -*-
"""logstore.py - append-only record log with signed, checkable tree heads.

The gap this fills: every existing component scanner (SkillSpector, Snyk
agent-scan, AI-Infra-Guard, chainloop, Anchor) publishes a *claim about today*.
None of them lets a consumer check, offline and without trusting the publisher,
that (a) a specific record is really in the published log and (b) no earlier
record was dropped or rewritten between two publication dates.

Layout of a log directory:

    log_dir/
      log.jsonl      one canonical-JSON record per line, append-only
      heads.jsonl    one signed tree head per line
      public_key.json  {"keyid": ..., "key": <SSlibKey dict>}

Record bytes: the exact bytes of the JSON line (LF excluded) with keys sorted
and separators (",", ":"). The Merkle leaf hashes those bytes, so a record's
hash is reproducible by anyone holding the line.

Tree head body: {"log_id", "size", "root", "timestamp", "spec"}. The signed
message is b"canari-tree-head/v1\\x00" + canonical body bytes; the domain
prefix stops a tree-head signature from ever being replayed as a record or an
attestation signature.

Why the append path can refuse to run (and must):
  * size < last signed head size          -> entries were truncated
  * root(first size) != last head root    -> entries were rewritten in place
Both raise instead of silently signing a history that disagrees with what was
already published. A log that accepts a rewrite under its own signature is
worse than no log, because it manufactures false assurance.

Directory writes take canari.state.FileLock so a scheduled run and a manual run
cannot interleave and produce duplicate sequence numbers.
"""
import base64
import json
import os
import time

from canari import checkpoint as c2sp
from canari.merkle import (consistency_proof, inclusion_proof, leaf_hash,
                           merkle_root)
from canari.signing import (generate_keypair, load_or_generate_keypair,
                            save_private_key)
from canari.state import FileLock

SPEC = "canari-append-only-log/v1"
BUNDLE_SPEC = "canari-inclusion-bundle/v1"
SIGN_PREFIX = b"canari-tree-head/v1\x00"
ENTRY_SPEC = "canari-log-entry/v1"

# Upper bound so a malicious bundle cannot make a verifier spin. Real proof
# length is <= log2(size); 64 covers any imaginable log (< 2**64 entries).
MAX_PROOF_LEN = 64
MAX_LOG_SIZE = 1 << 40


class LogError(Exception):
    """Base class for append-only log failures."""


class LogTruncated(LogError):
    """The on-disk log is shorter than a tree head we already signed."""


class LogRewritten(LogError):
    """The on-disk log changed a prefix we already signed."""


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _utc(ts=None) -> str:
    if ts is None:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return ts


def head_body(log_id, size, root_hex, timestamp, prev=None) -> dict:
    body = {"spec": SPEC, "log_id": log_id, "size": int(size),
            "root": root_hex, "timestamp": timestamp}
    if prev:
        body["prev"] = prev
    return body


def head_body_digest(body: dict) -> str:
    """sha256 over the canonical head body - the link a successor commits to.

    This is the same bytes the signature covers (minus the SIGN_PREFIX domain
    separator), so anything that would invalidate a signature also breaks the
    chain.
    """
    import hashlib
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def head_signing_input(body: dict) -> bytes:
    return SIGN_PREFIX + canonical_bytes(body)


def sign_head(body: dict, signer) -> dict:
    """Return a signed head: {"body": body, "signature": {...}}."""
    sig = signer.sign(head_signing_input(body))
    return {"body": dict(body), "signature": {"scheme": "ed25519",
                                              "keyid": sig.keyid,
                                              "sig": sig.signature}}


def verify_head_signature(head: dict, key_dict: dict) -> bool:
    """Check a tree head against a public key dict. Never raises."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        body = head["body"]
        sig_hex = head["signature"]["sig"]
        raw = bytes.fromhex(sig_hex)
        if len(raw) != 64:
            return False
        pub_hex = key_dict["keyval"]["public"]
        if key_dict.get("keytype", "ed25519") != "ed25519":
            return False
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(raw, head_signing_input(body))
        return True
    except Exception:
        return False


def check_head_body(body: dict, log_id=None) -> str:
    """Structural validation of a head body. Returns an error string or ""."""
    if not isinstance(body, dict):
        return "head body is not an object"
    if body.get("spec") != SPEC:
        return "unsupported head spec: %r" % (body.get("spec"),)
    if log_id is not None and body.get("log_id") != log_id:
        return "log_id mismatch: %r != %r" % (body.get("log_id"), log_id)
    size = body.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or not (0 <= size <= MAX_LOG_SIZE):
        return "bad size: %r" % (size,)
    root = body.get("root")
    if not isinstance(root, str) or len(root) != 64:
        return "bad root: %r" % (root,)
    try:
        bytes.fromhex(root)
    except ValueError:
        return "root is not hex"
    if not isinstance(body.get("timestamp"), str) or not body["timestamp"]:
        return "bad timestamp"
    if "prev" in body:
        prev = body["prev"]
        if not isinstance(prev, str) or len(prev) != 64:
            return "bad prev: %r" % (prev,)
        try:
            bytes.fromhex(prev)
        except ValueError:
            return "prev is not hex"
    return ""


class AppendOnlyLog:
    def __init__(self, log_dir, log_id="canari-log", private_key_path=None,
                 c2sp_origin=None):
        self.dir = os.path.abspath(log_dir)
        self.log_id = log_id
        # The origin a witness keys its state by. Defaults to log_id so a caller
        # that does not care gets one consistent identity, but the published log
        # sets it to a collision-resistant URL. export_bundle and
        # checkpoint_note must agree, or the bundle carries a checkpoint under a
        # different origin than the published checkpoint.txt -- which is exactly
        # the inconsistency this parameter removes.
        self.c2sp_origin = c2sp_origin or log_id
        self.entries_path = os.path.join(self.dir, "log.jsonl")
        self.heads_path = os.path.join(self.dir, "heads.jsonl")
        self.key_path = os.path.join(self.dir, "public_key.json")
        self._priv_path = private_key_path or os.path.join(self.dir, "signing_key.pem")
        os.makedirs(self.dir, exist_ok=True)
        self._entries = None
        self._heads = None
        self._signer = None
        self._public = None

    # ---- storage -------------------------------------------------------
    def _read_entries(self):
        """Read the raw entry bytes, one per line, LF-terminated.

        CRLF handling is deliberate, not sloppiness. A leaf hash is over the
        exact bytes of the line, so a repository checkout that converts LF to
        CRLF changes *every* leaf and makes an intact log report as rewritten.
        That happened here on 2026-11-15: CI (Linux) verified fine while a
        Windows checkout audited as REWRITTEN, with a completely different root.

        The real fix is `.gitattributes` marking docs/log/** as `-text`. This
        reader is the second line of defence: it drops one trailing CR so a
        mangled checkout still verifies, and records that it had to, so audit()
        can report it instead of hiding it.
        """
        out = []
        self._crlf_seen = False
        if not os.path.exists(self.entries_path):
            return out
        with open(self.entries_path, "rb") as f:
            for line in f.read().split(b"\n"):
                if not line.strip():
                    continue
                if line.endswith(b"\r"):
                    line = line[:-1]
                    self._crlf_seen = True
                out.append(line)
        return out

    def entries(self):
        if self._entries is None:
            self._entries = self._read_entries()
        return list(self._entries)

    def entry_objs(self):
        return [json.loads(b.decode("utf-8")) for b in self.entries()]

    def size(self) -> int:
        return len(self.entries())

    def leaf_hashes(self):
        return [leaf_hash(b) for b in self.entries()]

    def root(self) -> str:
        return merkle_root(self.leaf_hashes()).hex()

    def heads(self):
        if self._heads is None:
            out = []
            if os.path.exists(self.heads_path):
                with open(self.heads_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            out.append(json.loads(line))
            self._heads = out
        return list(self._heads)

    def last_head(self):
        hs = self.heads()
        return hs[-1] if hs else None

    # ---- keys ----------------------------------------------------------
    def _ensure_signer(self):
        if self._signer is not None:
            return self._signer
        if os.path.exists(self._priv_path):
            signer = load_or_generate_keypair(self._priv_path)[0]
        else:
            signer, pub = generate_keypair()
            save_private_key(signer, self._priv_path)
            self._public = pub
        self._signer = signer
        self._write_public_key(signer.public_key)
        return signer

    def _write_public_key(self, pub):
        payload = {"keyid": pub.keyid, "key": pub.to_dict(),
                   "log_id": self.log_id, "spec": SPEC}
        tmp = self.key_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, sort_keys=True, indent=1)
            f.write("\n")
        os.replace(tmp, self.key_path)
        self._public = payload

    def public_key(self) -> dict:
        """{"keyid","key","log_id","spec"}. Reads the file; never invents one."""
        if self._public is not None:
            return self._public
        if os.path.exists(self.key_path):
            with open(self.key_path, "r", encoding="utf-8") as f:
                self._public = json.load(f)
            return self._public
        if os.path.exists(self._priv_path):
            # A key exists but was never published; publish it now.
            self._ensure_signer()
            return self._public
        return {}

    # ---- append --------------------------------------------------------
    def append(self, payload, kind="record", timestamp=None) -> dict:
        """Append ONE record. Returns {"index", "hash", "entry"}."""
        rec = self.append_many([{"kind": kind, "payload": payload,
                                 "timestamp": _utc(timestamp)}])
        return rec[0]

    def append_many(self, records) -> list:
        """Append records atomically (one lock, one fsync)."""
        records = list(records)
        if not records:
            return []
        with FileLock(self.entries_path):
            # Re-read inside the lock so a concurrent writer cannot make us
            # reuse sequence numbers.
            self._entries = self._read_entries()
            start = len(self._entries)
            new_lines = []
            results = []
            for i, r in enumerate(records):
                entry = {"spec": ENTRY_SPEC, "seq": start + i,
                         "kind": r.get("kind", "record"),
                         "timestamp": r.get("timestamp") or _utc(),
                         "payload": r.get("payload")}
                b = canonical_bytes(entry)
                new_lines.append(b)
                results.append({"index": start + i,
                                "hash": leaf_hash(b).hex(),
                                "entry": entry})
            with open(self.entries_path, "ab") as f:
                for b in new_lines:
                    f.write(b + b"\n")
                f.flush()
                os.fsync(f.fileno())
            self._entries = self._entries + new_lines
        return results

    # ---- seal ----------------------------------------------------------
    def _prefix_root(self, n):
        return merkle_root(self.leaf_hashes()[:n]).hex()

    def audit(self) -> dict:
        """Check internal consistency against the last signed head.

        Returns {"ok", "size", "root", "last_head", "errors"}. Does not raise;
        callers decide. seal() treats a failure as fatal.
        """
        errors = []
        entries = self.entries()
        lh = self.last_head()

        # Chain check. Every head from the first one that carries `prev` onward
        # must name its immediate predecessor's body digest. Without this, heads
        # are independent signatures and a deleted historical head is invisible:
        # each survivor still verifies and the last one still matches the log
        # (measured 2026-11-16: removing heads[1] of 3 gave ok=true).
        unchained = 0
        heads = self.heads()
        for i in range(1, len(heads)):
            prev_claim = (heads[i].get("body") or {}).get("prev")
            if not prev_claim:
                unchained += 1
                continue
            expected = head_body_digest(heads[i - 1].get("body") or {})
            if prev_claim != expected:
                errors.append(
                    "CHAIN BROKEN at head %d: prev=%s but head %d hashes to %s "
                    "(a head was removed, reordered, or rewritten)"
                    % (i, prev_claim[:12], i - 1, expected[:12]))
        for i, b in enumerate(entries):
            try:
                obj = json.loads(b.decode("utf-8"))
            except Exception as e:
                errors.append("entry %d is not valid JSON: %s" % (i, e))
                break
            if obj.get("seq") != i:
                errors.append("entry %d has seq %r (expected %d)" % (i, obj.get("seq"), i))
                break
        root = merkle_root([leaf_hash(b) for b in entries]).hex()
        if lh:
            body = lh.get("body", {})
            err = check_head_body(body, self.log_id)
            if err:
                errors.append("last head invalid: " + err)
            pub = self.public_key().get("key")
            if pub and not verify_head_signature(lh, pub):
                errors.append("last head signature does not verify")
            if body.get("size", 0) > len(entries):
                errors.append("TRUNCATED: %d entries on disk < last signed size %d"
                              % (len(entries), body["size"]))
            elif body.get("root") != self._prefix_root(body["size"]):
                errors.append("REWRITTEN: prefix root at signed size %d no longer matches"
                              % body["size"])
        if getattr(self, "_crlf_seen", False):
            # Not an integrity failure -- the hashes were computed over the
            # bytes this reader returns -- but a consumer must know their
            # checkout mangles evidence files, because any *other* tool that
            # hashes the file directly will disagree.
            print("[log] WARNING: %s contains CRLF line endings; a checkout "
                  "converted evidence files. Add docs/log/** -text to "
                  ".gitattributes." % self.entries_path)
        return {"ok": not errors, "size": len(entries), "root": root,
                "last_head": lh, "errors": errors,
                "unchained_heads": unchained,
                "crlf_normalized": bool(getattr(self, "_crlf_seen", False))}

    def seal(self, timestamp=None, force=False) -> dict:
        """Publish a signed head over the current log. Returns head or None.

        Refuses (raises) if the on-disk log contradicts an already-signed head.
        Returns None when there is nothing new to publish, unless force=True.
        """
        with FileLock(self.heads_path):
            self._entries = self._read_entries()
            self._heads = None
            entries = self._entries
            last = self.last_head()
            if last:
                body = last["body"]
                err = check_head_body(body, self.log_id)
                if err:
                    raise LogError("existing head is invalid: " + err)
                if len(entries) < body["size"]:
                    raise LogTruncated(
                        "%d entries on disk but head at size %d was already published"
                        % (len(entries), body["size"]))
                if self._prefix_root(body["size"]) != body["root"]:
                    raise LogRewritten(
                        "the first %d entries no longer hash to the published root; "
                        "refusing to sign a rewritten history" % body["size"])
                if len(entries) == body["size"] and not force:
                    return None
            signer = self._ensure_signer()
            prev_digest = head_body_digest(last["body"]) if last else None
            body = head_body(self.log_id, len(entries),
                             merkle_root([leaf_hash(b) for b in entries]).hex(),
                             _utc(timestamp), prev=prev_digest)
            head = sign_head(body, signer)
            line = canonical_bytes(head)
            with open(self.heads_path, "ab") as f:
                f.write(line + b"\n")
                f.flush()
                os.fsync(f.fileno())
            self._heads = None
            return head

    # ---- proofs --------------------------------------------------------
    def prove_inclusion(self, index, head=None) -> dict:
        entries = self.entries()
        lh = head or self.last_head()
        if not lh:
            raise LogError("no signed head exists; call seal() first")
        size = lh["body"]["size"]
        if not (0 <= index < size):
            raise IndexError("index %d outside signed head of size %d" % (index, size))
        leaves = [leaf_hash(b) for b in entries[:size]]
        proof = inclusion_proof(leaves, index)
        return {"index": index, "data_b64": base64.b64encode(entries[index]).decode("ascii"),
                "proof": [p.hex() for p in proof], "head": lh}

    def prove_consistency(self, first_size=None, head=None) -> dict:
        hs = self.heads()
        if not hs:
            raise LogError("no signed heads exist")
        cur = head or hs[-1]
        if first_size is None:
            if len(hs) < 2:
                raise LogError("need at least two heads; pass first_size explicitly")
            first = hs[-2]
        else:
            cands = [h for h in hs if h["body"]["size"] == first_size]
            if not cands:
                raise LogError("no signed head at size %d" % first_size)
            first = cands[-1]
        leaves = [leaf_hash(b) for b in self.entries()[:cur["body"]["size"]]]
        proof = consistency_proof(leaves, first["body"]["size"])
        return {"from_head": first, "to_head": cur,
                "proof": [p.hex() for p in proof]}

    # ---- c2sp interoperability -----------------------------------------
    def checkpoint_note(self, head=None, origin=None) -> str:
        """The same head as a c2sp.org signed note, co-signable by any witness.

        Our native head format is `{"body":...,"signature":...}` signed over a
        domain prefix. That is fine for us but useless to an existing
        transparency-log witness, which speaks c2sp.org/signed-note,
        tlog-checkpoint and tlog-cosignature. Emitting both costs nothing and
        is the difference between "a log only our verifier can read" and "a log
        the witness network can co-sign".
        """
        h = head or self.last_head()
        if not h:
            raise LogError("no signed head exists; call seal() first")
        body = h["body"]
        signer = self._ensure_signer()
        return c2sp.sign_checkpoint(signer, origin or self.c2sp_origin,
                                    body["size"],
                                    bytes.fromhex(body["root"]))

    def verify_checkpoint_note(self, note=None, origin=None) -> dict:
        """Verify our own checkpoint note and return what it commits to."""
        text_src = note if note is not None else self.checkpoint_note(origin=origin)
        text, sigs = c2sp.parse_note(text_src)
        o, size, root = c2sp.parse_checkpoint(text)
        pub = bytes.fromhex(self.public_key()["key"]["keyval"]["public"])
        vk = c2sp.VerifierKey(o, c2sp.LOG_KEY_TYPE, pub)
        return {"ok": c2sp.verify_log_signature(text, sigs, vk),
                "origin": o, "size": size, "root": root.hex(), "note": text_src}

    def export_bundle(self, index, consistency=True) -> dict:
        """Offline-verifiable package for one record: signature + inclusion
        (+ consistency vs the previous head). Contains no secret material."""
        inc = self.prove_inclusion(index)
        pk = dict(self.public_key().get("key") or {})
        if self.public_key().get("keyid"):
            pk = dict(pk, keyid=self.public_key()["keyid"])
        bundle = {"spec": BUNDLE_SPEC, "log_id": self.log_id,
                  "public_key": pk,
                  "entry": {"index": inc["index"], "data_b64": inc["data_b64"]},
                  "tree_head": inc["head"],
                  "inclusion_proof": inc["proof"]}
        try:
            bundle["checkpoint"] = self.checkpoint_note()
        except LogError:
            pass
        if consistency:
            try:
                c = self.prove_consistency(head=inc["head"])
                bundle["consistency"] = {"from_head": c["from_head"],
                                         "proof": c["proof"]}
            except LogError:
                pass
        return bundle


def open_log(log_dir, log_id="canari-log", private_key_path=None,
             c2sp_origin=None) -> AppendOnlyLog:
    return AppendOnlyLog(log_dir, log_id=log_id, private_key_path=private_key_path,
                         c2sp_origin=c2sp_origin)
