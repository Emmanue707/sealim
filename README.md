# Sealim

Seal certificates and transcripts with signed QR codes that anyone can verify offline.

[![Licence](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## How it works

An issuer hashes the digital credential file, attaches optional signed **visible claims** for paper checks, and signs a compact binary payload with Ed25519. The payload is base45-encoded behind an `SL1:` prefix and printed as a QR code. A verifier decodes the QR, checks the signature against a local **trust file** of known issuer keys, optionally compares a supplied file’s SHA-256, and may query a **registry** for revocation status. Basic authenticity checks do not require live network access.

```mermaid
flowchart LR
  Issuer["Issuer"] --> Sign["sealim sign"]
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
cd registry && go test ./...
```

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
- CLI: `keygen`, `sign`, `verify`, `revoke`
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
