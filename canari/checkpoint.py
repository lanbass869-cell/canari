# -*- coding: utf-8 -*-
"""checkpoint.py - c2sp.org checkpoint, signed note, cosignature/v1.

Why this file exists (honest reason, 2026-11-15): Canari shipped its own
vendor-specific tree head format. That was a real weakness, not a moat. A
transparency log is only as strong as the number of independent parties willing
to co-sign it, and those parties already speak one format:

    c2sp.org/signed-note        the note + signature line envelope
    c2sp.org/tlog-checkpoint    origin / size / base64 root
    c2sp.org/tlog-cosignature   cosignature/v1 over the checkpoint text

Competitor `alexar76/histor` implements these and pushes to a live witness
network. Any witness that co-signs HISTOR can co-sign Canari too, if - and only
if - we emit the same bytes. So we do.

Byte-exact rules (all from those three documents):

    note text      = <origin>\\n<size>\\n<base64 root>\\n
    key id         = SHA-256(<name> || 0x0A || <type byte> || <public key>)[:4]
    signature line = "\\u2014 " <name> " " base64(<key id> || <signature>) "\\n"
    note           = <text> "\\n" <signature lines>
    log key        = type 0x01, Ed25519 over the note text
    cosignature/v1 = type 0x04, Ed25519 over
                     "cosignature/v1\\ntime <unix seconds>\\n" || <note text>
                     signature bytes = <8-byte big-endian time> || <64-byte Ed25519>
    verifier key   = <name> "+" <hex key id> "+" base64(<type byte> || <pub key>)

Standard base64 with padding; non-canonical input is rejected.
"""
import base64
import binascii
import hashlib
import re
import struct

LOG_KEY_TYPE = 0x01
COSIGNATURE_V1_TYPE = 0x04
SIGNATURE_PREFIX = "\u2014 "
COSIGNATURE_CONTEXT = b"cosignature/v1\ntime "

_NAME_RE = re.compile(r"^[^\s+]+$")
MAX_SIG_LINES = 16
MAX_SIZE_DIGITS = 19


class NoteError(ValueError):
    """A note, checkpoint or signature line that does not follow the format."""


# ---- encoding helpers ---------------------------------------------------

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_strict(text: str) -> bytes:
    """Standard base64 with padding. Non-canonical input is refused."""
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise NoteError("bad base64: %s" % exc) from exc
    if b64(raw) != text:
        raise NoteError("non-canonical base64")
    return raw


def check_name(name: str) -> str:
    if not isinstance(name, str) or not name or not _NAME_RE.match(name):
        raise NoteError("a key name is non-empty with no spaces and no '+'")
    if len(name.encode("utf-8")) > 255:
        raise NoteError("a key name is at most 255 bytes")
    return name


def key_id(name: str, type_byte: int, public_key: bytes) -> bytes:
    """First four bytes of SHA-256(name || 0x0A || type || pubkey)."""
    check_name(name)
    if len(public_key) != 32:
        raise NoteError("an Ed25519 public key is 32 bytes")
    return hashlib.sha256(
        name.encode("utf-8") + b"\n" + bytes([type_byte]) + public_key
    ).digest()[:4]


def vkey(name: str, type_byte: int, public_key: bytes) -> str:
    """The verifier-key string a client is configured with."""
    return "%s+%s+%s" % (name, key_id(name, type_byte, public_key).hex(),
                         b64(bytes([type_byte]) + public_key))


class VerifierKey:
    __slots__ = ("name", "type_byte", "public_key")

    def __init__(self, name, type_byte, public_key):
        self.name = name
        self.type_byte = type_byte
        self.public_key = public_key

    @property
    def key_id(self):
        return key_id(self.name, self.type_byte, self.public_key)

    @classmethod
    def parse(cls, text):
        parts = (text or "").strip().split("+", 2)
        if len(parts) != 3:
            raise NoteError("a vkey is <name>+<hex key id>+<base64 key>")
        name, hex_id, b64key = parts
        check_name(name)
        raw = b64_strict(b64key)
        if len(raw) != 33:
            raise NoteError("an Ed25519 vkey is one type byte plus 32 key bytes")
        key = cls(name, raw[0], raw[1:])
        if key.type_byte not in (LOG_KEY_TYPE, COSIGNATURE_V1_TYPE):
            raise NoteError("unsupported key type 0x%02x" % key.type_byte)
        if key.key_id.hex() != hex_id.lower():
            raise NoteError("vkey id does not match its name and key")
        return key


# ---- checkpoint --------------------------------------------------------

def checkpoint_text(origin, tree_size, root):
    check_name(origin)
    if not isinstance(tree_size, int) or isinstance(tree_size, bool) or tree_size < 0:
        raise NoteError("tree size is a non-negative integer")
    if len(root) != 32:
        raise NoteError("a root hash is 32 bytes")
    return "%s\n%d\n%s\n" % (origin, tree_size, b64(root))


def parse_checkpoint(text):
    """Return (origin, size, root). At least three non-empty lines."""
    if not isinstance(text, str) or not text.endswith("\n"):
        raise NoteError("checkpoint text ends with a newline")
    lines = text[:-1].split("\n")
    if len(lines) < 3 or any(not line for line in lines):
        raise NoteError("a checkpoint has at least three non-empty lines")
    origin, size_text, root_b64 = lines[0], lines[1], lines[2]
    check_name(origin)
    if (not size_text.isascii() or not size_text.isdigit()
            or len(size_text) > MAX_SIZE_DIGITS
            or (len(size_text) == MAX_SIZE_DIGITS
                and size_text > "9223372036854775807")
            or (size_text != "0" and size_text.startswith("0"))):
        raise NoteError("tree size is an ASCII decimal without leading zeros")
    root = b64_strict(root_b64)
    if len(root) != 32:
        raise NoteError("a root hash is 32 bytes")
    return origin, int(size_text), root


# ---- signature lines and notes -----------------------------------------

class SignatureLine:
    __slots__ = ("name", "key_id", "signature")

    def __init__(self, name, key_id_bytes, signature):
        self.name = name
        self.key_id = key_id_bytes
        self.signature = signature

    def render(self):
        return SIGNATURE_PREFIX + self.name + " " + b64(self.key_id + self.signature) + "\n"


def parse_signature_line(line):
    if not line.startswith(SIGNATURE_PREFIX):
        raise NoteError("a signature line starts with an em dash and a space")
    rest = line[len(SIGNATURE_PREFIX):]
    space = rest.find(" ")
    if space < 0:
        raise NoteError("a signature line is a name, a space, and base64")
    name, payload = rest[:space], rest[space + 1:]
    check_name(name)
    raw = b64_strict(payload)
    if len(raw) < 5:
        raise NoteError("a signature payload carries a 4-byte key id and a signature")
    return SignatureLine(name, raw[:4], raw[4:])


def render_note(text, signatures):
    if not text.endswith("\n"):
        raise NoteError("note text ends with a newline")
    if not signatures:
        raise NoteError("a note has at least one signature line")
    if len(signatures) > MAX_SIG_LINES:
        raise NoteError("at most %d signature lines" % MAX_SIG_LINES)
    seen = set()
    for s in signatures:
        ident = (s.name, s.key_id)
        if ident in seen:
            raise NoteError("two signature lines with the same name and key id")
        seen.add(ident)
    return text + "\n" + "".join(s.render() for s in signatures)


def parse_note(data):
    """Return (text, signature_lines). Text is everything before the last blank line."""
    if not isinstance(data, str) or not data.endswith("\n"):
        raise NoteError("a note ends with a newline")
    if any(ord(c) < 0x20 and c != "\n" for c in data):
        raise NoteError("a note carries no control characters other than newline")
    split = data.rfind("\n\n")
    if split < 0:
        raise NoteError("a note has a blank line between text and signatures")
    text, sig_block = data[:split + 1], data[split + 2:]
    if not text:
        raise NoteError("a note has non-empty text")
    if not sig_block:
        raise NoteError("a note has at least one signature line")
    lines = sig_block[:-1].split("\n")
    if len(lines) > MAX_SIG_LINES:
        raise NoteError("at most %d signature lines" % MAX_SIG_LINES)
    sigs = [parse_signature_line(line) for line in lines]
    seen = set()
    for s in sigs:
        ident = (s.name, s.key_id)
        if ident in seen:
            raise NoteError("two signature lines with the same name and key id")
        seen.add(ident)
    return text, sigs


# ---- signing and verification -----------------------------------------

def _ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if len(public_key) != 32 or len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except Exception:
        return False


def signature_from_signer(signer, message: bytes) -> bytes:
    """Ed25519 signature bytes from a securesystemslib CryptoSigner.

    CryptoSigner.sign() returns a Signature whose `.signature` is a hex string,
    not base64. Getting that wrong produces a 128-byte "signature" that no
    verifier accepts, so the conversion lives in one place.
    """
    sig = signer.sign(message)
    raw = bytes.fromhex(sig.signature)
    return raw


def sign_checkpoint(signer, origin: str, tree_size: int, root: bytes) -> str:
    """A checkpoint note signed by the log key under `origin` (type 0x01)."""
    pub = signer.public_key.to_dict()["keyval"]["public"]
    pub_bytes = bytes.fromhex(pub)
    text = checkpoint_text(origin, tree_size, root)
    line = SignatureLine(origin, key_id(origin, LOG_KEY_TYPE, pub_bytes),
                         signature_from_signer(signer, text.encode("utf-8")))
    return render_note(text, [line])


def verify_log_signature(note_text: str, lines, verifier: VerifierKey) -> bool:
    """True when a signature line matching name AND key id verifies over the text."""
    if verifier.type_byte != LOG_KEY_TYPE:
        return False
    for s in lines:
        if s.name == verifier.name and s.key_id == verifier.key_id:
            return _ed25519_verify(verifier.public_key, s.signature,
                                   note_text.encode("utf-8"))
    return False


def cosignature_message(text: str, timestamp: int) -> bytes:
    return COSIGNATURE_CONTEXT + str(int(timestamp)).encode() + b"\n" + text.encode("utf-8")


def cosign(signer, name: str, text: str, timestamp: int):
    """Produce a cosignature/v1 line. Signature bytes = 8-byte BE time || Ed25519."""
    check_name(name)
    pub = bytes.fromhex(signer.public_key.to_dict()["keyval"]["public"])
    sig = signature_from_signer(signer, cosignature_message(text, timestamp))
    return SignatureLine(name, key_id(name, COSIGNATURE_V1_TYPE, pub),
                         struct.pack(">Q", int(timestamp)) + sig)


def verify_cosignature(text: str, line, verifier: VerifierKey):
    """The timestamp when `line` is a valid cosignature/v1 by `verifier`, else None."""
    if verifier.type_byte != COSIGNATURE_V1_TYPE:
        return None
    if line.name != verifier.name or line.key_id != verifier.key_id:
        return None
    if len(line.signature) != 8 + 64:
        return None
    timestamp = struct.unpack(">Q", line.signature[:8])[0]
    if _ed25519_verify(verifier.public_key, line.signature[8:],
                       cosignature_message(text, timestamp)):
        return int(timestamp)
    return None
