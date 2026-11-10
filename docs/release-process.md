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

## 2. Publish to PyPI (needs a token, manual)

```
pip install twine
python -m twine check dist/*
TWINE_USERNAME=__token__ TWINE_PASSWORD=<pypi-token> python -m twine upload dist/*
```

The name `canari-mcp` is registered on PyPI by this project's first upload; verify
`https://pypi.org/project/canari-mcp/` afterwards. This repo currently holds no PyPI
token, so the upload waits for the owner.

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
