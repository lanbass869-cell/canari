# Canari append-only log, v1

Status: implemented in `canari/logstore.py`; verifier is
`canari/verify_offline.py` (imports nothing from `canari`). Vectors:
`docs/spec/merkle-vectors.json` (168 cases). Date: 2026-11-15.

## 1. What problem this solves

A signed attestation answers "who said this about this artifact". It does not
answer "did they later delete or rewrite that statement". Every scanner in this
category (SkillSpector, Snyk agent-scan, AI-Infra-Guard, chainloop, and the
MCP registry itself) publishes claims about *today* and keeps no checkable
history. A consumer who wants to know whether a package was quietly downgraded
has nothing to check against.

An append-only Merkle log converts "trust the publisher" into "check 32 bytes".

## 2. Entry

One line per entry in `log.jsonl`, canonical JSON
(`ensure_ascii=false, sort_keys=true, separators=(",",":")`) encoded UTF-8,
LF-terminated:

```json
{"kind":"source-snapshot","payload":{"source":"mcpcost-evidence"},"seq":7,"spec":"canari-log-entry/v1","timestamp":"2026-11-15T04:00:00Z"}
```

`seq` MUST equal the entry's zero-based position. The leaf commits to the exact
bytes of the line (without the LF), so any byte change is a different leaf.

`kind` is informational; the log does not interpret `payload`. A consumer must
treat `payload` as opaque bytes it is choosing to timestamp.

## 3. Leaf and node hashing (RFC 9162 section 2.1.1)

```
leaf(data)  = SHA-256(0x00 || data)
node(l, r)  = SHA-256(0x01 || l || r)
empty root  = SHA-256("")
```

The prefixes are not cosmetic. Without them, a leaf whose bytes equal an
internal node's bytes is a valid second preimage, which lets a forger build a
tree with a chosen root. The empty root is `SHA-256("")` and not all zeros so
that "no entries" is unambiguous.

## 4. Tree head

```json
{"body":{"log_id":"canari-snapshot-log","root":"<64 hex>","size":12,
         "spec":"canari-append-only-log/v1","timestamp":"2026-11-15T04:00:00Z"},
 "signature":{"keyid":"<64 hex>","scheme":"ed25519","sig":"<128 hex>"}}
```

Signed message:

```
"canari-tree-head/v1\x00" || canonical_json(body)
```

The domain prefix is required: without it, a tree-head signature could be
replayed as a signature over an attestation or an entry whose bytes happen to
equal a head body. Ed25519 signatures are hex, not base64 (securesystemslib
emits hex; a verifier that assumes base64 rejects every valid head).

Heads are appended to `heads.jsonl`, one per line, and never removed.

## 5. Inclusion proof

RFC 6962 audit path over `leaf(entry)`, `index`, `size`. Verification is
iterative: walk the proof, fold left or right per `(fn & 1) or (fn == sn)`,
shift both counters, and require `sn == 0` with the running hash equal to the
head root at the end.

Do not implement this from the RFC's `SUBPROOF` pseudocode. Its boolean
inverts meaning at the base case; an inclusion path generated from it verifies
only for index 0. `canari/merkle.py` uses an explicit recursive audit path and
documents the failure.

## 6. Consistency proof

Proof that the tree of size `first` is a prefix of the tree of size `second`.
This is the check that catches a publisher who **re-signs a fork**: a signature
over the new head is valid, so only the consistency proof can show that the old
prefix is still there.

The subtle branch: after peeling trailing bits of `first - 1`, if `fn == 0` the
verifier must start from the **trusted first root**, not from a proof element.
Omitting that branch makes every genuine proof fail while still accepting
forged same-size trees. The verifier returns false unless both roots are
reconstructed.

## 7. Bundle format

`canari-inclusion-bundle/v1`:

| field | meaning |
|---|---|
| `spec` | `canari-inclusion-bundle/v1` |
| `log_id` | must match the head body |
| `public_key` | SSlibKey dict (`keytype`,`scheme`,`keyval.public`) |
| `entry` | `{index, data_b64}` - the exact entry line bytes |
| `tree_head` | signed head (section 4) |
| `inclusion_proof` | list of 32-byte hex strings |
| `consistency` | optional `{from_head, proof}` |

A bundled verifier needs exactly this file. No network, no registry, no access
to `canari`.

## 8. Verification rules (MUST)

1. `head.body.spec` is `canari-append-only-log/v1`; `log_id` matches if pinned.
2. `head.signature` verifies under `public_key` over the domain-prefixed body.
3. `entry.data_b64` is valid base64; `0 <= index < size`; inclusion proof
   reconstructs `head.body.root`.
4. If `consistency` is present: `from_head` verifies under the same key, and
   the consistency proof connects `from_head.body.root` to `head.body.root`.
5. Any malformed field is a **failure**, never a skip. A verifier that treats
   an unparsable proof as "not applicable" has no security value.

A verifier MAY additionally pin `root`, `log_id`, and `min_size` out of band
(the head the consumer recorded yesterday). That is what turns "the publisher
is consistent with itself" into "the publisher is consistent with what I saw".

## 9. What this does not prove

- that a `payload` statement is true;
- that the publisher holds no other, unannounced signing key (a fork is bounded
  by consistency witnesses, not prevented);
- that the head in hand is the newest one ever published;
- that the log covers every record the publisher knows about.

These are trust-anchoring problems, not arithmetic problems. The honest answer
is that they need gossip or witness cosignature. Do not claim otherwise.

## 10. Append path rules

`seal()` MUST refuse when the on-disk log disagrees with the last signed head:

| condition | outcome |
|---|---|
| entries on disk < last signed size | `LogTruncated` |
| prefix root at signed size changed | `LogRewritten` |
| head body malformed / bad signature | `LogError` |
| nothing new | returns `None` (no head written) |

A log that signs a rewrite under its own key is worse than no log, because it
manufactures false assurance. Directory writes take a cross-process lock so a
scheduled run and a manual run cannot interleave.
