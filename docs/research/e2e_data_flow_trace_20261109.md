# Canari End-to-End Data Flow Trace
## From HTTP response to signed bundle to install gate decision
## Traced with real packages, real HTTP calls, real cryptographic operations

---

## Path 1: Package WITH native provenance (express@5.3.0)

### Step 1: Packument fetch
```
GET https://registry.npmjs.org/express
→ {"dist-tags": {"latest": "5.3.0"}, "versions": {"5.3.0": {"dist": {"integrity": "sha512-...", "tarball": "..."}}}}
```
Source: `npm_enum.py L104-111` — `fetch_packument()` uses `urllib.parse.quote(name, safe="")` for URL encoding.

### Step 2: Version resolution
```
latest_version_info(packument) → {
    "version": "5.3.0",
    "dist_integrity": "sha512-...",
    "tarball": "https://registry.npmjs.org/express/-/express-5.3.0.tgz",
    "maintainers": [...],
    "deprecated": False
}
```
Source: `npm_enum.py L114-125` — reads `dist-tags.latest` → `versions[latest]` → `dist.integrity`, `dist.tarball`.

### Step 3: Artifact hash
```
_download_sha256(tarball_url) → "e643434d..." (64 hex chars)
```
Source: `baseline.py L65-84` — streams 64KB chunks through `hashlib.sha256()`.

### Step 4: Native provenance ingestion
```
native_ingest("express", "5.3.0") → {
    "present": true,
    "predicate_types": ["v0.1", "v1"],
    "v1_verified": true,
    "v1_identity": "https://github.com/expressjs/express/.github/workflows/npm-publish.yml@refs/tags/v5.3.0",
    "v0_presence_only": 1,
    "verifier": "sigstore-python/4.5.1"
}
```
Source: `native.py L84-111` — fetches npm attestation endpoint, classifies entries by verification material type, verifies v1 (certificate-based) via sigstore-python `verify_dsse()`, records v0.1 (publicKey-hint) as presence-only.

### Step 5: Credential shape detection
```
credential_shapes(att) → [] (clean)
```
Source: `signing.py L100-130` — recursively scans all strings in the attestation against 7 rules, with percent-decode fallback and _OWN_HASH_FIELDS exemption. Excludes `evidence_refs` and `signature` dict.

### Step 6: NFC normalization
```
_nfc_normalize(att) → same structure with all strings NFC-normalized
```
Source: `signing.py L42-65` — recursively normalizes every string with `unicodedata.normalize("NFC", s)`, raises on NFC key collisions.

### Step 7: Signing
```
sign_attestation(att, signer) → {"envelope": {...DSSE...}, "payload": {...}}
```
Source: `signing.py L131-165` — two-pass signing:
- Pass 1: sign empty envelope → get keyid + sig → inject into inline signature block
- Pass 2: sign payload WITH inline signature block → final DSSE envelope
The envelope signature is the authoritative one.

### Step 8: Verification
```
verify_signed(envelope, pub_dict) → (True, payload, None)
```
Source: `signing.py L168-186` — in-toto Envelope.from_dict → SSlibKey.verify_signature(PAE) → json.loads(payload).

### Step 9: Gate decision
```
evaluate_gate(bundle_path, key_path, key_registry_path, "default")
→ GateDecision(decision="ALLOW", reasons=[], ...)
```
Source: `gate.py L75-172` — checks: signature, verdict, freshness, key validity, error checks, native provenance, registry allowlist, findings REVIEW.

---

## Path 2: Package WITHOUT native provenance (agent-install@0.0.8)

Same as Path 1 except Step 4 returns None:
```
native_ingest("agent-install", "0.0.8") → None
```
The `native_provenance` field is NOT added to the payload (L210-211 in baseline.py: `if native_prov is not None`).

In the gate evaluation, `require_native_provenance` policy check at `gate.py L150-155` finds `native_present=False`. Under the `default` policy (require=False), this doesn't affect the decision. Under `release-gate` (require=True), this changes ALLOW → REVIEW.

---

## Path 3: Package with download failure

```
_download_sha256(tarball_url) → None (network error, 404, etc.)
```
The L2.1_ARTIFACT_HASH check gets `verdict: "fail"` with evidence_ref explaining the failure. The artifact_sha256 is set to `"0" * 64` (schema requires valid hex; all-zero = "we couldn't compute it"). The overall verdict becomes `"fail"`.

In the gate, `is_gate_passing()` returns False → BLOCK.

---

## Path 4: Package with fetch error (packument unreachable)

The entire build_attestation is never called. In `run_multi()`, the error is caught and an error attestation is created with:
```json
{"checks": [{"id": "L1.1_REGISTRY_PRESENT", "verdict": "error", "evidence_ref": "fetch failed: ..."}]}
```
This is the mcpcheckup cascade pattern (A4 fix): even a failed package produces a signed, auditable attestation.

---

## Path 5: Supersession chain (multiple runs)

Run 1: `build_attestation` → `sign_attestation` → save to `npm_pkg_20261109T120000.bundle.json`
Run 2: `build_attestation` → `_save_att` reads state.json → finds prev digest → sets `supersedes` → `sign_attestation` → save to `npm_pkg_20261109T120100.bundle.json`
Run 3: same → save to `npm_pkg_20261109T120200.bundle.json`

The chain:
```
120000 (no supersedes, digest=D1)
120100 (supersedes=D1, digest=D2)
120200 (supersedes=D2, digest=D3)
```

Verified: `verify_chain()` correctly walks D1→D2→D3, all reachable, no cycles, rc=0.

---

## 12-round audit summary: 43 bugs found, 40 fixed

| Category | Count | Examples |
|---|---|---|
| Missing imports / wrong references | 6 | pypi_native_ingest, UA, _opener, save_private_key, base64 |
| Wrong URL / wrong nesting | 5 | DSH URLs, MCP server.name, MCP cursor nesting |
| Silent failures | 8 | pypi timeout, key file missing, native ingest failure, registry cursor stuck |
| Logic errors | 8 | downloads_monthly always 0, bundle overwrite, NFC missing, credential FP |
| Security issues | 5 | path traversal, credential in payload, missing key file skip, policy mutation |
| Dead code / duplication | 6 | DeadLetterLog, key lifecycle dup, downloads_monthly, evidence_ref hex |
| Design gaps | 4 | schema additionalProperties, NFC key collision, evidence_ref hex, project-style NFC |

The remaining unfixed issues are all documented in this report's audit findings (5 items from signing.py line-by-line read: NFC result keys, evidence_ref hex FP, private key permissions, key_id derivation comment, revoke_key no save enforcement).
