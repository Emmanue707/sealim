# Known-answer test vectors

JSON files in this directory exercise `sealim_core::verify` end-to-end. They use a **deterministic TEST Ed25519 key** (seed bytes `0x01` through `0x20`). Never use that key for real credentials.

## File format

Each `*.json` file is one object with these fields:

| Field | Type | Meaning |
|-------|------|---------|
| `description` | string | Human-readable case name |
| `seed_hex` | string | 64 hex chars, issuer test seed |
| `public_key_b64url` | string | Issuer public key (base64url, no pad) |
| `trust` | object | Inline `sealim-trust` v1 JSON |
| `qr_text` | string | Full QR payload text including `SL1:` |
| `file_hex` | string or null | Optional file bytes as hex |
| `registry_status` | string or null | `valid`, `revoked`, `superseded`, `unreachable`, or null |
| `expected_code` | string | SPEC result code (e.g. `VALID`) |
| `expected_claims` | array | `[key, value]` pairs when claims should be returned |

Regenerate vectors from the repo root:

```bash
cargo test -p sealim-core --test generate_vectors write_vectors -- --ignored --nocapture
```

The integration test `load_vectors` loads every file here and checks `expected_code`.

Issuer request (SPEC section 7.1) known-answer files `registry_request_valid.json` and `registry_request_bad_signature.json` use a different schema (method, path, body, signature). They are checked by Rust and Go tests, not by `load_vectors`.
