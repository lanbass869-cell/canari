# What the append-only log does and does not prove

A short security note written after a fault-injection pass over the verification
path (2026-11-16). It is deliberately specific about the boundary, because "signed"
is routinely read as more than it is.

## What a signed head proves

Each entry in `heads.jsonl` is an Ed25519 signature over a head body:

```json
{"log_id": "...", "root": "<64 hex>", "size": <n>,
 "spec": "canari-append-only-log/v1", "timestamp": "<ISO-8601>"}
```

Verifying one head against `public_key.json` proves that whoever holds the signing
key asserted: *at time T, the Merkle tree over the first n records of log `log_id`
had this root.*

Recomputing the root from `log.jsonl` then proves the records on disk are the ones
that root commits to. `canari-log audit DIR` does both, and also checks every
earlier head.

## What it does not prove

### 1. Heads are chained, so deleting one is detected

Each head body carries an optional `prev` field: the SHA-256 of the previous
head's canonical body (the same bytes the signature covers, minus the domain
separator). `canari-log audit` verifies every link.

```
head[i].body.prev == sha256(canonical_bytes(head[i-1].body))
```

Removing, reordering or rewriting a head therefore breaks the chain:

```
$ python -m canari.log_cli audit ./log      # after deleting heads[1] of 3
{"ok": false,
 "errors": ["CHAIN BROKEN at head 1: prev=54e51b36a7d9 but head 0 hashes to
             ea7b5e859d22 (a head was removed, reordered, or rewritten)"]}
rc=2
```

Before this field existed the same deletion was invisible: every surviving head
verified on its own and the last one still matched `log.jsonl`, so the audit
returned `ok: true` (measured 2026-11-16). That is the defect this closes.

**The legacy prefix is unchained and is reported as such.** `prev` cannot be
retrofitted without invalidating the signatures that already exist, so heads
written before the field still have no link. The audit does not treat that as
tampering - it counts them:

```json
"unchained_heads": 4
```

Those four links are the gap that remains. A consumer who cares should start
pinning from the first head that has `prev`, and treat earlier ones as history
rather than as evidence.

**Still not covered: rollback to an older head.** Nothing references the newest
head, so deleting the *last* one and republishing nothing leaves a shorter but
internally valid history. Only a party outside the log can catch that - pin a head
somewhere the operator does not control (`canari-verify --chain`, a git commit, a
release, a witness). `docs/log/witness-request-draft.txt` is the draft for the
witness route.

**Why the fix was not made silently.** Adding a field to the signed head body is a
format change: every consumer that recomputes `prev` or verifies the body must know
about it, and the published log's existing heads cannot be made to comply after the
fact. It is recorded here, versioned as an additive field (old verifiers ignore it;
new ones check it), and covered by tests before being sealed into the published log.

### 1b. Do not force-seal an unchanged log

`seal --force` can publish a second head at a size that already has one. Its
timestamp (and, now, its `prev`) differ, so its canonical bytes differ, but its
`(size, root)` pair is identical - and `scripts/publish_log.py` names the immutable
snapshot `heads/%06d-%s.json % (size, root)`. Two heads with the same pair collide,
and the publisher correctly refuses to overwrite the anchored file:

```
REFUSING to overwrite immutable head 000043-1af057f1....json with different bytes
```

Measured 2026-11-16 while starting the chain on the published log. The seal itself
succeeded and the audit stayed green; the collision only appeared at publish time.
Renaming the snapshot to include the head digest would fix it, but the existing
files are already anchored with OpenTimestamps under the `(size, root)` name, so the
name is frozen. Consequence: the first chained head will be the next *natural* seal
(one that grows the log), not a forced re-seal.

### 2. A signature proves who said it, not that it is true

The head says "at time T the log had this root". It says nothing about whether the
verdicts inside are correct. Measurement correctness is a separate question, and for
the typosquat side it is not even well-posed without the comparison corpus — see
[docs/analysis-corpus-dependence.md](../analysis-corpus-dependence.md).

### 3. `docs/log/signing_key.pem` is not in the repository

The working copy of the log keeps its private key beside the data
(`signing_key.pem`, 119 bytes). It is listed in `.gitignore` and `git ls-files`
confirms it is untracked. If that ever changes, anyone with a clone could mint a
head and the whole surface becomes theatre. Anyone forking this repo should generate
their own key with `canari-log init`.

## Fault-injection results (2026-11-16)

Thirteen cases against the real code paths. "Clean" means: non-zero exit and no
traceback, or a documented degraded result — never a silent pass.

| # | fault | expected | observed |
|---|---|---|---|
| A | bundle file truncated to half | reject | clean, rc=3, no traceback |
| B | top-level payload rewritten (verdict -> pass) | reject | clean, rc=2 |
| C | `log.jsonl` truncated mid-record | audit fails | clean, rc=2, no traceback |
| D | head removed from `heads.jsonl` | audit fails | clean, rc=2, `CHAIN BROKEN` (fixed by the `prev` field) |
| E | signed head root mutated | audit fails | clean, rc=2 |
| F | non-JSON file dropped into `attestations/` | drift survives | clean |
| G | empty store | empty report | clean |
| H | empty comparison corpus | no verdict, no crash | clean (returns None) |
| I | expired attestation under `--gate` | not ALLOW | clean, rc=2 |
| K | 3 processes appending 30 records each | 90 records, audit ok | clean, 90 records |
| L | registry enumeration raises | degrade, no raise | clean, 0 total |
| M | per-package fetch raises | error attestation, no raise | clean, 1 bundle |
| N | unwritable output directory | no crash | clean |

All thirteen now fail safely. D was the exception when this pass started - it
succeeded silently because heads were independent signatures. The `prev` field closed
it for every link that carries one; the four legacy links and rollback-to-older-head
remain, and both are stated above rather than hidden.
