# Contributing

Thank you for helping improve Sealim. Read [SPEC.md](SPEC.md) before changing on-wire behaviour.

## Build and test

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd registry && gofmt -w . && go vet ./... && go test ./...
```

Use synthetic data only (fictional issuers such as the University of Waghi, names such as Jane Kila). Do not commit real keys, `.env` files, or production databases.

## Code style

- **Rust:** edition 2021, `rustfmt`, Clippy with `-D warnings`, small focused modules, clear error types.
- **Go:** standard `gofmt`, `go vet`, table-driven tests where they add clarity.
- Comments should be sparse; public items may have short doc comments.

## Pull requests

- Commit messages: short, imperative (e.g. “Add payload length check”).
- Keep PRs small and include tests when behaviour changes.
- Any change to payload layout, result codes, trust-file format, or registry API **must** update `SPEC.md` and add or update test vectors when they exist.
- Do not introduce new cryptographic primitives without discussion; stick to the stack listed in `SPEC.md`.

## Legal

By contributing, you agree that your contributions are licensed under the Apache License 2.0, the same as the project.
