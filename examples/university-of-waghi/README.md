# University of Waghi demo

Synthetic transcript fixtures for trying Sealim locally. The issuer name is fictional. The Ed25519 signing material is the **public test vector only** (deterministic seed `0x01` through `0x20`). Never use this key for real credentials.

## Regenerate fixtures

```bash
./generate.sh
```

The script writes `transcript.txt`, `trust.json`, `qr.txt`, and `qr.png` in this directory. No private key file is stored in the repository.

## Verify with the CLI

From the repository root:

```bash
sealim verify \
  --qr-file examples/university-of-waghi/qr.txt \
  --file examples/university-of-waghi/transcript.txt \
  --trust examples/university-of-waghi/trust.json
```

## Verify in the browser

Build WASM, serve the repository root on loopback, and open the verifier page:

```bash
web/build.sh
python3 -m http.server 8765 --bind 127.0.0.1
```

Open `http://127.0.0.1:8765/web/`, click **Try University of Waghi demo**, choose `transcript.txt`, then **Verify**.