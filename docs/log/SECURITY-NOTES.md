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

### 1. Deleting a historical head is not detected

`heads.jsonl` is a sequence of independent signatures. Each is valid on its own, and
the last one still matches `log.jsonl`, so **removing an entry from the middle of
the file leaves the audit green**:

```
$ python -m canari.log_cli audit ./log      # after deleting heads[1]
{"ok": true, "size": 3}
```

Measured on a three-head fixture: deleting the middle head gives `rc=0`, `ok: true`.
Mutating a head's root gives `rc=2`, `ok: false` — so the signatures are checked;
what is missing is a link *between* heads.

**Consequence.** The head log is append-only by convention, not by evidence. An
operator who can write `heads.jsonl` can drop the record of a size it published
earlier and the log cannot tell.

**Mitigation available today.** Publish the head, or a digest of the whole
`heads.jsonl`, somewhere you do not control — a git commit, a release, a witness.
`docs/log/witness-request-draft.txt` is the draft for exactly that. A party holding
an older head can also verify a later one against it, which is what
`canari-verify --chain DIR` is for.

**Mitigation not implemented.** A `prev` field holding the hash of the previous
head body would make deletion and reordering evident without any external party. It
has not been added because it changes the signed head body, and the 43 heads already
published under `.../v1` would then be "unchained" relative to their successors. That
is a format-version decision, not a bug fix, so it is recorded here rather than made
silently.

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
| **D** | **head removed from `heads.jsonl`** | **audit fails** | **`ok: true`, rc=0 — gap** |
| E | signed head root mutated | audit fails | clean, rc=2 |
| F | non-JSON file dropped into `attestations/` | drift survives | clean |
| G | empty store | empty report | clean |
| H | empty comparison corpus | no verdict, no crash | clean (returns None) |
| I | expired attestation under `--gate` | not ALLOW | clean, rc=2 |
| K | 3 processes appending 30 records each | 90 records, audit ok | clean, 90 records |
| L | registry enumeration raises | degrade, no raise | clean, 0 total |
| M | per-package fetch raises | error attestation, no raise | clean, 1 bundle |
| N | unwritable output directory | no crash | clean |

Twelve of thirteen fail safely. The one that does not is D, and it is a property of
the format rather than of the implementation.
