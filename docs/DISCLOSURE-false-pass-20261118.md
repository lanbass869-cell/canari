# Disclosure: records that claimed a check they never ran

**Date:** 2026-11-18. **Scope:** all 6,787 attestations in the store plus the code that
produces them. This note is written before the fix is deployed, because the numbers are
about records that were already published and signed.

## What was wrong

The record-level verdict was computed as

```python
verdict = "pass" if sha else "fail"
```

`sha` is the tarball/sdist digest, so **any package whose bytes downloaded was recorded as
`pass`**, regardless of what the heuristics inside the record actually did. Separately,
`canari/cadence.py` returned `[]` for two different situations — "ran, found nothing" and
"could not run at all (version absent from upload history)" — and every call site turned
`[]` into a `pass` row.

The combination means a record can read `verdict: pass` while carrying rows that say
`unsupported`. That is a false pass: the record claims a check the pipeline never performed.

## How many records are affected

Computed by re-deriving the verdict from each signed record's own `checks` array
(`canari.baseline._record_verdict`), restricted to the two registries whose code path the
fix changes:

| registry | records | would be reclassified | share |
|---|---|---|---|
| pypi | 2,763 | **2,233** | **80.8%** |
| npm | 1,464 | **584** | **39.9%** |
| **both** | **4,227** | **2,817** | **66.6%** |

The pypi rate is the higher of the two because many pypi records were built without a
pre-fetched PyPI JSON document, so cadence could not run at all — and that "could not run"
was being recorded as a pass.

`dsh-registry` (2,033) and `mcp-registry` (527) records use a different code path and are
not affected by this change.

## What changed

1. `cadence.py` now returns **`None`** when the check cannot be performed and **`[]`** only
   when it ran and found nothing. Every call site maps `None` to `verdict: unsupported`
   with a reason, instead of `pass`.
2. `baseline._record_verdict()` derives the record verdict from the checks that actually
   ran: any `fail` → fail; any `error` → error; any `unsupported`/`skip` → unsupported;
   any `finding:` → pass-with-findings; otherwise pass.
3. `tests/test_false_pass_hardening.py` pins all of it (22 tests).
4. Three pre-existing tests asserted the *old* contract (`... == []` for a check that could
   not run). They were updated, because they were protecting the bug.

## What this does NOT do

- It does **not** rewrite the 6,787 signed records already in the store. Attestations are
  append-only; editing them would destroy the property the log exists to provide. Records
  keep the verdict they were signed with, and this note records that a subset of them
  overstate what was checked.
- It does **not** make the pipeline check more things. It only stops it from claiming checks
  it did not run.

## A separate gap this audit surfaced

`canari-gate`, `canari-guard` and `canari-consumer` **never read `artifact_sha256`**. They
resolve an attestation by name (and optionally version) and evaluate the gate on it, but they
do not compare the artifact hash against the bytes the user is about to install. So the
"bound to the exact bytes" property holds at *record* level — a record cannot be altered
without breaking its signature — but it is **not enforced at consumption time**.

Closing that would need the gate to receive a digest of the bytes it is about to run (or to
hash them itself), which is a feature, not a fix. It is listed here so the current behaviour
is not described as something it is not.

## Reproducing the counts

```python
# every record, re-derive the verdict from its own checks
import glob, json, base64
from canari.baseline import _record_verdict
for f in glob.glob("out/attestations/*.bundle.json"):
    p = json.loads(base64.b64decode(json.load(open(f))["envelope"]["payload"]))["predicate"]
    s = p["subject"]
    print(f, p["verdict"], "->", _record_verdict(p["checks"], s.get("artifact_sha256")))
```
