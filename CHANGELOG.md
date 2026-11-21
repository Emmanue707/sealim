# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-21

First public release of Sealim.

### Added

- **Rust core and CLI (`sealim-cli`)** — issue Ed25519-signed QR payloads (`SL1:`), verify offline against trust files, optional registry lookups, and encrypted issuer key handling. Payload layout is defined in [SPEC.md](SPEC.md).
- **Go registry** — small HTTP service for document status (`valid`, `revoked`, `superseded`) keyed by `doc_id`.
- **WASM browser verifier** — static `web/` page and `sealim-wasm` crate for in-browser verification without installing the CLI.
- **Demo fixtures** — University of Waghi example under `examples/university-of-waghi/`.
- **Test vectors** — JSON fixtures under `crates/sealim-core/tests/vectors/`.

### Notes

This release is early work in progress. It has not been independently audited and is **not** suitable for production credentials or high-assurance use. Treat keys, trust files, and registry data as experimental.

Project site and hosted verifier: [https://sealim.waghitech.com](https://sealim.waghitech.com).

[0.1.0]: https://github.com/Emmanue707/sealim/releases/tag/v0.1.0