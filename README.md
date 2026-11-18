# Sealim

Seal certificates and transcripts with signed QR codes that anyone can verify offline.

[![Licence](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## How it works

An issuer hashes the digital credential file, attaches optional signed **visible claims** for paper checks, and signs a compact binary payload with Ed25519. The payload is base45-encoded behind an `SL1:` prefix and printed as a QR code. A verifier decodes the QR, checks the signature against a local **trust file** of known issuer keys, optionally compares a supplied file’s SHA-256, and may query a **registry** for revocation status. Basic authenticity checks do not require live network access.

```mermaid
flowchart LR
  Issuer["Issuer"] --> Sign["sealim seal"]
  Sign --> QR["QR on document"]
  QR --> Verifier["Verifier<br/>(CLI or browser, offline)"]
  Trust["Trust file"] --> Verifier
  Registry["Registry<br/>(optional status)"] -.-> Verifier
```

## Quick start

Requires Rust (stable) and Go 1.25 or newer.

```bash
git clone https://github.com/Emmanue707/sealim.git
cd sealim
cargo test --workspace
cargo run -p sealim-cli -- --version
```

Minimal issue-and-verify flow (uses a temporary directory):

```bash
WORKDIR=$(mktemp -d)
echo 'choose-a-strong-passphrase' > "$WORKDIR/pass.txt"
cargo run -p sealim-cli -- keygen \
  --name "University of Waghi" \
  --out "$WORKDIR/issuer.key" \
  --passphrase-file "$WORKDIR/pass.txt" \
  --trust-out "$WORKDIR/trust.json"

printf '%s' 'Synthetic transcript for Jane Kila' > "$WORKDIR/document.bin"
QR=$(cargo run -p sealim-cli -- seal \
  --key "$WORKDIR/issuer.key" \
  --passphrase-file "$WORKDIR/pass.txt" \
  --file "$WORKDIR/document.bin" \
  --claim "n=Jane Kila" \
  --claim "t=BSc Computing" | tail -1)

cargo run -p sealim-cli -- verify \
  --qr "$QR" \
  --file "$WORKDIR/document.bin" \
  --trust "$WORKDIR/trust.json"
```

```bash
cd registry && go test ./...
```

## Usage

Subcommands: `keygen`, `seal`, `verify`, `inspect`. Global options: `--help`, `--version`.

**`sealim keygen`** — create an encrypted issuer key (`sealim-key` v1: Argon2id KDF + age ciphertext over the 32-byte Ed25519 seed; never a raw seed on disk):

```bash
sealim keygen --name "University of Waghi" \
  --out issuer.key \
  --passphrase-file pass.txt \
  --trust-out trust.json
```

**`sealim seal`** — sign a file and print `SL1:` QR text (optional PNG/SVG):

```bash
sealim seal --key issuer.key --passphrase-file pass.txt \
  --file document.bin \
  --claim "n=Jane Kila" --claim "t=BSc Computing" \
  --png qr.png
```

**`sealim verify`** — decode and verify (trust via `--trust` or `SEALIM_TRUST_FILE`):

```bash
sealim verify --qr "$QR" --file document.bin --trust trust.json
sealim verify --image scan.png --trust trust.json
```

**`sealim inspect`** — decode payload only (no trust file):

```bash
sealim inspect --qr "$QR"
```

### Verify exit codes

| Exit | When |
|------|------|
| 0 | `VALID` or `VALID_CLAIMS_ONLY` |
| 1 | Any other verification result (`HASH_MISMATCH`, `BAD_SIGNATURE`, …) |
| 2 | Usage error, missing input, I/O, or bad trust file |

## Repository layout

| Path | Role |
|------|------|
| `crates/sealim-core` | Payload format and cryptography |
| `crates/sealim-cli` | `sealim` command |
| `crates/sealim-wasm` | WebAssembly bindings for the browser verifier |
| `registry/` | Document status registry (Go) |
| `testvectors/` | Known-answer verification test cases |
| `SPEC.md` | Normative format and APIs |
| `THREAT_MODEL.md` | Threat model |
| `SECURITY.md` | Vulnerability reporting |

Known-answer test vectors are in [`testvectors/`](testvectors/).

## Roadmap

- [x] Core library: encode, sign, verify payloads
- [x] CLI: keygen, seal, verify, inspect
- Registry: SQLite-backed API from `SPEC.md`
- Browser verifier: WASM plus static UI

Normative details: [SPEC.md](SPEC.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

## Security status

Sealim has **not** been independently audited. It is early-stage software and **must not** be used for real credentials or legal decisions yet. See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright Emmanuel Kokele.

## Author

Emmanuel Kokele — software engineer from Papua New Guinea, founder and lead developer of [Waghi Tech](https://waghitech.com).

- Portfolio: https://kokele.waghitech.com
- Waghi Tech: https://waghitech.com
- GitHub: [@Emmanue707](https://github.com/Emmanue707)
- Email: ekokele707@gmail.com