# Canari release process

Two credential-dependent steps are deliberately manual; everything else is scripted.

## 1. Build + sign + publish a GitHub release (scripted)

```
python scripts/release.py --tag v0.1.0 --notes docs/release-notes-v0.1.0.md
```

What it does:
- `python -m build` -> `dist/*.whl`, `dist/*.tar.gz`
- writes `dist/SHA256SUMS`, signs it with the project release key (`out/release_key.pem`,
  Ed25519) into `dist/SHA256SUMS.sig`, publishes `dist/release_public_key.json`
- creates the GitHub release and uploads all five assets

The release key is separate from the attestation signing key. Keep `out/` private.

## 2. Publish to PyPI (scripted since 2026-11-10)

```
python scripts/release.py --pypi            # add --metadata to also refresh repo description/topics
```

Token source, first match wins:
1. `CANARI_PYPI_TOKEN` env var
2. `CANARI_PYPI_TOKEN_FILE` (default `E:\RUANJIAN\memory_hub\tokens_pypi_20260928.txt`,
   reads the first line starting with `pypi-`)

**Two production lessons baked into the script:**

- twine's rich renderer raises `UnicodeEncodeError` on a GBK Windows console *after*
  the first file has already uploaded, so the release ends up half-published. The
  script forces `PYTHONIOENCODING=utf-8`, `PYTHONUTF8=1`, `NO_COLOR=1` and
  `--disable-progress-bar`.
- Always upload with `--skip-existing` so a half-finished run can be resumed.

## 2b. Repo metadata (description / homepage / topics)

```
python scripts/release.py --metadata
```

**GitHub topics need `PUT /repos/{owner}/{repo}/topics`.** `PATCH /repos/{owner}/{repo}`
returns 200 but silently leaves the topics list empty - that cost a debugging round.

## 2c. One command for a normal release

```
python scripts/release.py --tag v0.1.1 --notes docs/release-notes-v0.1.1.md --pypi --metadata
```
builds, signs, creates the GitHub release with 5 assets, uploads to PyPI and refreshes
repo visibility.

## 3. Quality gate before any release

```
python scripts/quality_gate.py           # tests + coverage >= 85% + mutation kill >= 90%
python scripts/full_sweep.py             # store-level end-to-end checks
python scripts/verify_live_sample.py     # re-derive a sample from live registries
```

## 4. Consumer verification of a release

```
sha256sum -c SHA256SUMS
python - <<'PY'
import base64, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
pub = bytes.fromhex(json.load(open("release_public_key.json"))["public_hex"])
sig = base64.b64decode(json.load(open("SHA256SUMS.sig"))["sig_b64"])
Ed25519PublicKey.from_public_bytes(pub).verify(sig, open("SHA256SUMS", "rb").read())
print("release signature OK")
PY
```
