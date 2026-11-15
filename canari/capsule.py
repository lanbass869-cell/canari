# -*- coding: utf-8 -*-
"""capsule.py - measurement capsules per draft-templeman-scitt-measurement-capsule-01.

Why this module exists: Canari measures whether what an MCP server *declares*
matches what it *actually does*. That is the question this IETF draft asks:

    "does what a subject publicly declares about itself ... match what an
    unaffiliated reader can observe?"

The draft is Experimental for a specific, stated reason: its handling of the
UNCHECKABLE state "has not been shown useful by more than one implementation".
This module is an attempt at being that second implementation, and the
conformance runner in scripts/ checks it against the vectors the draft itself
publishes.

What this module encodes (all quoted rules are the draft's):

* capsule_id = SHA-256 of the JCS serialisation with `capsule_id` excluded
* a batch is an RFC 9162 Merkle Tree Hash over the capsule_id values as 32-byte
  strings, sorted ascending, with the 0x00 leaf prefix of RFC 9162 2.1.1
* COSE_Sign1 (RFC 9052) with alg = -19 (EdDSA)
* negative rules the draft names, enforced here so a caller cannot skip them:
    no member named `decision` at any depth
    `sources` values are digests, never URLs
    the stored bytes of a capsule line are its JCS form
    a leaf set carries no duplicates
    a hash envelope carries no content-type (label 3)

Known limitation, stated rather than hidden: the JCS implementation here is
correct for the value types these capsules use (strings, integers, booleans,
null, arrays, objects). RFC 8785 number formatting for non-integral floats is
not implemented, and a capsule containing one is rejected rather than silently
canonicalised differently from the reference implementation.
"""
import hashlib
import json
import math

CAPSULE_SCHEMA = "csoai.measurement-capsule/0.2"
BATCH_SCHEMA = "csoai.measurement-capsule-batch/0.2"

# draft section 8: measurement states. UNCHECKABLE is never a pass, a failure,
# a zero or an absence.
STATES = ("CONSISTENT", "INCONSISTENT", "UNCHECKABLE")

# draft: no member named `decision` at any depth; a capsule grants no authority
FORBIDDEN_MEMBERS = ("decision", "approval", "authorisation", "authorization")

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


class CapsuleError(ValueError):
    """A capsule or batch that violates a rule the draft states."""


# ---------------------------------------------------------------- JCS

def _check_jcs_safe(obj, path="", depth=0):
    if depth > 64:
        raise CapsuleError("nesting deeper than 64 at %s" % path)
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CapsuleError("non-string key at %s" % path)
            _check_jcs_safe(v, path + "/" + k, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _check_jcs_safe(v, "%s/%d" % (path, i), depth + 1)
    elif isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise CapsuleError("NaN/Infinity is not representable in JCS at %s" % path)
        if obj != int(obj):
            raise CapsuleError(
                "non-integral float at %s: RFC 8785 number formatting is not "
                "implemented here, and guessing would silently produce a "
                "different capsule_id than the reference implementation" % path)


def jcs(obj) -> bytes:
    """RFC 8785 canonical JSON. Refuses inputs this implementation cannot
    canonicalise identically to the reference (see module docstring)."""
    _check_jcs_safe(obj)
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


# ---------------------------------------------------------------- capsule id

def find_forbidden(obj, path="", hits=None):
    """Every member named `decision` (or an approval/authorisation synonym)."""
    if hits is None:
        hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in FORBIDDEN_MEMBERS:
                hits.append({"rule": "no-authority-member",
                             "member": k, "path": path or "/"})
            find_forbidden(v, path + "/" + str(k), hits)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            find_forbidden(v, "%s/%d" % (path, i), hits)
    return hits


def capsule_id(doc) -> str:
    """SHA-256 over the JCS form with capsule_id excluded."""
    body = {k: v for k, v in doc.items() if k != "capsule_id"}
    return hashlib.sha256(jcs(body)).hexdigest()


def is_digest(value) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def check_stored_bytes(raw: bytes, doc) -> list:
    """A capsule line's stored bytes must equal its JCS form.

    Otherwise `capsule_id` covers a canonicalisation the reader never sees, and
    two readers holding the same line can disagree about what was signed.
    """
    try:
        canon = jcs(doc)
    except CapsuleError as e:
        return [{"rule": "stored-bytes-are-jcs", "detail": str(e)}]
    if raw != canon:
        return [{"rule": "stored-bytes-are-jcs",
                 "detail": "stored %d bytes, canonical form is %d bytes"
                           % (len(raw), len(canon))}]
    return []


def validate_capsule(doc) -> list:
    """Return a list of violations. Empty list means the capsule is conformant
    against the rules this module implements."""
    problems = []
    if not isinstance(doc, dict):
        return [{"rule": "capsule-is-object"}]
    problems += find_forbidden(doc)
    if doc.get("schema") != CAPSULE_SCHEMA:
        problems.append({"rule": "schema", "got": doc.get("schema")})
    state = doc.get("measurement_state")
    if state not in STATES:
        problems.append({"rule": "measurement-state", "got": state})
    sources = doc.get("sources")
    if not isinstance(sources, dict) or not sources:
        problems.append({"rule": "sources-present"})
    else:
        for k, v in sources.items():
            # null is legal and meaningful: the draft's own UNCHECKABLE vector
            # records `initialize_response: null` because nothing was read. A
            # made-up digest there would be a lie; an omitted key would lose the
            # distinction between "not read" and "not applicable". Anything that
            # is neither a digest nor null -- a URL, an inline document -- is
            # what the sources-digest-only rule is actually about.
            if v is None:
                continue
            if not is_digest(v):
                problems.append({"rule": "sources-digest-only", "member": k,
                                 "got": str(v)[:60]})
    stated = doc.get("capsule_id")
    if stated is not None:
        got = capsule_id(doc)
        if stated != got:
            problems.append({"rule": "capsule-id", "stated": stated, "computed": got})
    return problems


# ---------------------------------------------------------------- Merkle batch

def _leaf(capsule_id_hex: str) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + bytes.fromhex(capsule_id_hex)).digest()


def _node(l, r) -> bytes:
    return hashlib.sha256(NODE_PREFIX + l + r).digest()


def _largest_pow2_below(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    leaves = list(leaves)
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = _largest_pow2_below(len(leaves))
    return _node(mth(leaves[:k]), mth(leaves[k:]))


def batch_root(capsule_ids) -> str:
    """RFC 9162 MTH over capsule_id values as 32-byte strings, sorted ascending."""
    ids = sorted(capsule_ids)
    if len(set(ids)) != len(ids):
        raise CapsuleError("leaf-set-no-duplicates: the batch contains a repeated capsule_id")
    return mth([_leaf(i) for i in ids]).hex()


def _recompute(leaf, index, size, proof) -> str:
    """RFC 9162 2.1.3.2 inclusion verification, returning the root hex."""
    fn, sn, r = index, size - 1, leaf
    if size <= 0 or index < 0 or index >= size:
        raise CapsuleError("index outside the tree")
    for p in proof:
        if sn == 0:
            raise CapsuleError("proof longer than the tree")
        if (fn & 1) or (fn == sn):
            r = _node(p, r)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise CapsuleError("proof does not reach the root")
    return r.hex()


def audit_path(capsule_ids, target_id) -> list:
    ids = sorted(capsule_ids)
    leaves = [_leaf(i) for i in ids]
    idx = ids.index(target_id)

    def walk(ls, i):
        if len(ls) == 1:
            return []
        k = _largest_pow2_below(len(ls))
        if i < k:
            return walk(ls[:k], i) + [mth(ls[k:])]
        return walk(ls[k:], i - k) + [mth(ls[:k])]

    return [p.hex() for p in walk(leaves, idx)]


# ---------------------------------------------------------------- COSE

def _cbor():
    try:
        import cbor2
        return cbor2
    except ImportError as e:                       # pragma: no cover
        raise CapsuleError(
            "COSE support needs cbor2: pip install cbor2") from e


def cose_sig_structure(protected_bstr: bytes, payload: bytes) -> bytes:
    """COSE_Sign1 Sig_structure (RFC 9052 4.4): ["Signature1", protected, "", payload]."""
    return _cbor().dumps(["Signature1", protected_bstr, b"", payload])


def _ed25519_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if len(pub) != 32 or len(sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except Exception:
        return False


def decode_cose_sign1(blob: bytes):
    """Return (protected_bytes, protected_map, payload, signature).

    Accepts a detached-signature form (payload nil) by returning payload None.
    """
    obj = _cbor().loads(blob)
    # COSE_Sign1 is CBOR tag 18. Some encoders emit the bare array; cbor2
    # decodes the tagged form into a CBORTag, so accept both and say so.
    tag = getattr(obj, "tag", None)
    if tag is not None:
        if tag != 18:
            raise CapsuleError("expected CBOR tag 18 (COSE_Sign1), got tag %r" % (tag,))
        obj = obj.value
    if not isinstance(obj, (list, tuple)) or len(obj) != 4:
        raise CapsuleError("a COSE_Sign1 is a 4-element array")
    protected, unprotected, payload, signature = obj
    if not isinstance(protected, bytes):
        raise CapsuleError("protected header must be a bstr")
    pmap = _cbor().loads(protected) if protected else {}
    if not isinstance(pmap, dict):
        raise CapsuleError("protected header must decode to a map")
    return protected, pmap, payload, signature


def verify_cose_sign1(blob: bytes, public_key: bytes, *, hash_envelope=False):
    """Verify a COSE_Sign1. For a hash envelope the payload *is* the digest of
    the thing signed, so the signature is over the digest bytes."""
    protected, pmap, payload, signature = decode_cose_sign1(blob)
    if pmap.get(1) != -19:
        raise CapsuleError("alg must be -19 (EdDSA), got %r" % (pmap.get(1),))
    if hash_envelope and 3 in pmap:
        raise CapsuleError("rfc9995-no-label-3: a hash envelope carries no content type")
    if payload is None:
        raise CapsuleError("detached payload needs the payload supplied separately")
    msg = cose_sig_structure(protected, payload)
    if not _ed25519_verify(public_key, signature, msg):
        raise CapsuleError("cose-signature: signature does not verify")
    return {"alg": pmap.get(1), "kid": pmap.get(4), "payload": payload,
            "protected": protected, "claims": pmap.get(15)}
