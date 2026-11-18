# Sealim specification v0.1

**Status:** draft  
**Format version byte:** `0x01`  
**QR prefix:** `SL1:`

## Conventions

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when they appear in capitals.

## 1. Terms

- **Payload** — Binary structure signed by the issuer and carried in a QR code (after encoding).
- **Visible claims** — Optional UTF-8 facts (name, title, etc.) signed so paper documents can be checked without hashing the paper.
- **Trust file** — JSON file listing trusted issuer Ed25519 public keys and validity windows.
- **Registry** — Optional HTTPS service holding document status (`valid`, `revoked`, `superseded`) keyed by `doc_id`.
- **Verifier** — Software that decodes a QR, validates the payload, checks signatures, and returns a **result code**.

## 2. Payload v1 binary layout

All multi-byte integers are **big-endian**. Offsets are zero-based.

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 1 | `version` | **MUST** be `0x01` for this document |
| 1 | 1 | `flags` | bit0 = visible claims present; bit1 = issuer uses registry for this document; bits 2–7 reserved, **MUST** be 0 |
| 2 | 8 | `key_id` | First 8 bytes of SHA-256(issuer Ed25519 public key, 32 raw bytes) |
| 10 | 16 | `doc_id` | 128-bit random identifier (CSPRNG), registry primary key |
| 26 | 8 | `issued_at` | `u64` Unix seconds UTC |
| 34 | 32 | `doc_hash` | SHA-256 of exact bytes of issued digital file (v1: raw bytes only, no canonicalisation) |
| 66 | 2 | `claims_len` | `u16`, 0..=160; **MUST** be 0 if bit0 clear, **MUST** be >0 if bit0 set |
| 68 | *n* | `claims` | UTF-8; see section 3 |
| 68+*n* | 64 | `signature` | Ed25519 over the signed message (section 4) |

**Total size:** 132 bytes fixed plus `claims_len`. Maximum 292 bytes (with `claims_len` = 160). Typical claims (~45 bytes) yield ~177 bytes binary.

### 2.1 QR encoding

The QR text **MUST** be the ASCII prefix `SL1:` immediately followed by the **base45** encoding of the full payload bytes (RFC 9285 alphabet). All base45 characters are in the QR alphanumeric set. Error correction **SHOULD** be level **M**. Typical payloads fit QR version 10–11; implementers **MUST** choose a version that fits.

Base45 length is 3 characters per 2 bytes plus 2 for a trailing odd byte: 258 characters for the 172-byte example in section 8, 438 at the 292-byte maximum.

## 3. Visible claims

**Purpose:** A printed document has no stable bytes to hash, and embedding a QR in a PDF changes its bytes. A valid QR could be copied onto forged paper. The issuer therefore signs human-readable facts the verifier displays; the checker compares them to the paper.

**Format:** Records `key=value` separated by byte `0x1F` (UNIT SEPARATOR). Keys: lowercase ASCII `a`–`z`, length 1–3.

| Key | Meaning |
|-----|---------|
| `n` | Holder name |
| `t` | Title or award (e.g. `BSc Computing`) |
| `d` | Date `YYYY-MM-DD` |
| `i` | Issuer display name (optional) |
| `r` | Reference number (optional) |

Unknown keys **MUST** be shown to the user unchanged, not dropped.

**Values:** non-empty UTF-8, NFC normalised, no control characters (U+0000–U+001F, U+007F–U+009F), no leading or trailing whitespace. A record is split at its first `=`; values MAY contain `=`.

Keys **MUST** be unique and sorted in ascending byte order (canonical encoding). Verifiers **MUST** reject non-canonical claims with `MALFORMED`. Total `claims` length **MUST NOT** exceed 160 bytes.

**Example (bytes as text):** `d=2026-01-15\x1Fn=Jane Kila\x1Ft=BSc Computing`

## 4. Signed message

```
msg = "SEALIM-SIG-v1" || 0x00 || payload[0 .. 68+n)
```

- The domain-separation label is 13 ASCII bytes, followed by one zero byte.
- The appended segment is every payload byte before the `signature` field.

The `signature` field **MUST** be pure Ed25519 (RFC 8032, not prehashed) over `msg`. Verifiers **MUST** use strict verification: reject non-canonical `S` values and small-order or non-canonical public keys. Rust implementations **SHOULD** use `ed25519-dalek` `verify_strict`. Go implementations using `crypto/ed25519` **MUST** reject small-order public keys when loading them, since `Verify` does not.

## 5. Trust file (`sealim-trust` v1)

JSON object:

```json
{
  "format": "sealim-trust",
  "version": 1,
  "updated_at": "2026-01-01T00:00:00Z",
  "issuers": [
    {
      "name": "University of Waghi",
      "key_id": "a1b2c3d4e5f60708",
      "public_key": "<base64url-no-pad, 32 bytes>",
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": null,
      "registry_url": "https://registry.example.invalid/v1"
    }
  ]
}
```

- `key_id` **MUST** equal the first 8 bytes of SHA-256(decoded `public_key`) encoded as lowercase hex (16 hex chars). Verifiers **MUST** reject entries where this does not hold.
- `valid_until` **MAY** be `null` for open-ended keys.
- `registry_url` **MAY** be `null`. When set, `registry_public_key` (base64url-no-pad, 32 bytes) **MUST** also be present; it verifies signed revocation lists (section 7).
- Distribution: bundled with verifiers and refreshable online. Signed trust files are out of scope for v0.1.

Verifiers **MAY** read the default path from the `SEALIM_TRUST_FILE` environment variable.

## 6. Verification procedure

Given QR text, trust file, optional digital file bytes, and optional registry access:

1. The text **MUST** start with `SL1:`; otherwise return `MALFORMED`.
2. Base45-decode the remainder; on failure, or if the result is empty, return `MALFORMED`.
3. If `version` is not `0x01`, return `UNSUPPORTED_VERSION`.
4. Check that the total length equals `132 + claims_len`, that reserved `flags` bits are zero, that `claims_len` agrees with bit0, and that claims follow section 3; otherwise return `MALFORMED`.
5. Look up `key_id` in the trust file; if absent, return `UNKNOWN_ISSUER`.
6. Rebuild the signed message (section 4) and verify the signature with the issuer key; on failure return `BAD_SIGNATURE`.
7. Check that `issued_at` lies within the issuer's `valid_from`/`valid_until`; otherwise return `KEY_NOT_VALID_AT_ISSUE`. This check follows signature verification because `issued_at` is only trustworthy once signed.
8. If a file is supplied, compare its SHA-256 with `doc_hash`; on difference return `HASH_MISMATCH`.
9. If bit1 is set and the registry is reachable, query the document status and return `REVOKED` or `SUPERSEDED` when applicable.
10. If bit1 is set and the registry is unreachable, return `STATUS_UNKNOWN`.
11. Otherwise return `VALID` when a file was supplied, or `VALID_CLAIMS_ONLY` when it was not.

Verifiers **MUST** display the visible claims and the issuer name for every result from step 7 onwards.

### 6.1 Result codes

Stable string identifiers for CLI, WASM, and registry documentation:

| Code | Meaning |
|------|---------|
| `VALID` | Signature good; file hash matches if supplied; registry (if checked) says valid |
| `VALID_CLAIMS_ONLY` | Signature good; no file supplied (paper check) |
| `STATUS_UNKNOWN` | Signature good; registry flag set but registry unreachable |
| `HASH_MISMATCH` | Supplied file SHA-256 differs from `doc_hash` |
| `BAD_SIGNATURE` | Ed25519 verification failed |
| `UNKNOWN_ISSUER` | `key_id` not in trust file |
| `KEY_NOT_VALID_AT_ISSUE` | `issued_at` outside key validity window |
| `REVOKED` | Registry reports revoked |
| `SUPERSEDED` | Registry reports superseded (may include replacement `doc_id`) |
| `MALFORMED` | Bad prefix, base45, length, reserved bits, or claims encoding |
| `UNSUPPORTED_VERSION` | Unknown `version` byte |

**Precedence** (first match wins, matching the order of section 6): `MALFORMED` (prefix or base45), `UNSUPPORTED_VERSION`, `MALFORMED` (layout or claims), then `UNKNOWN_ISSUER`, `BAD_SIGNATURE`, `KEY_NOT_VALID_AT_ISSUE`, `HASH_MISMATCH`, `REVOKED` / `SUPERSEDED`, then `VALID`, `VALID_CLAIMS_ONLY`, or `STATUS_UNKNOWN`.

## 7. Registry API v1

JSON over HTTPS. Stores only `doc_id`, `doc_hash`, `key_id`, `issued_at`, `status` (`valid`|`revoked`|`superseded`), reason code, `superseded_by`, and timestamps. **MUST NOT** store full documents, names, or claims.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness; **MUST** return `200` and `{"status":"ok"}` |
| GET | `/v1/issuers` | Public issuer list in trust-file shape |
| GET | `/v1/documents/{doc_id_hex}` | Document status JSON; `404` if unknown |
| POST | `/v1/documents` | Register `{doc_id, doc_hash, key_id, issued_at}`: hex strings and Unix seconds (authenticated) |
| POST | `/v1/documents/{doc_id_hex}/revoke` | Body `{reason}`; reason ∈ `key_compromise`, `issued_in_error`, `withdrawn`, `other` |
| POST | `/v1/documents/{doc_id_hex}/supersede` | Body `{superseded_by}` |
| GET | `/v1/revocations?since=RFC3339` | Non-valid entries for offline cache; signed by the registry key, see 7.2 |

`GET /v1/documents/{doc_id_hex}` response shape:

```json
{
  "doc_id": "<hex32>",
  "status": "valid",
  "reason": null,
  "superseded_by": null,
  "updated_at": "2026-01-01T00:00:00Z"
}
```

The registry process **MAY** bind listen address via `SEALIM_REGISTRY_ADDR` and use `SEALIM_DB` for its SQLite path.

### 7.1 Issuer authentication (POST)

Headers:

- `Sealim-Key-Id` — hex `key_id`
- `Sealim-Timestamp` — Unix seconds
- `Sealim-Signature` — base64url Ed25519 signature

The signature covers this UTF-8 string, with `\n` as a single line feed byte and no trailing newline:

```
"SEALIM-REQ-v1\n" + METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + lowercase_hex(SHA-256(body))
```

`PATH` is the request path without query string. `TIMESTAMP` is the decimal value of `Sealim-Timestamp`.

Servers **MUST** reject timestamps more than 300 seconds from server time and **MUST** reject replay of the same signature within that window. Issuers **MAY** only modify documents whose `key_id` matches their key.

Clients **MAY** set base URL via `SEALIM_REGISTRY_URL`.

### 7.2 Signed revocation lists

`GET /v1/revocations` responses carry header `Sealim-Registry-Signature`: a base64url-no-pad Ed25519 signature by the registry key over `"SEALIM-REV-v1" || 0x00 || body`, where `body` is the exact response bytes. Verifiers **MUST** check it against `registry_public_key` from the trust file before caching the list.

## 8. Size example

Claims `d=2026-01-15␟n=Jane Kila␟t=BSc Computing` (␟ is `0x1F`) are 40 bytes.

| Part | Bytes |
|------|-------|
| Fixed header (offsets 0–67) | 68 |
| Claims | 40 |
| Signature | 64 |
| **Payload** | **172** |
| Base45 text (3 characters per 2 bytes) | 258 characters |
| QR text with `SL1:` | 262 characters |

Known-answer test vectors are in [`testvectors/`](testvectors/).

## 9. Versioning

Any change to binary layout **MUST** increment the payload `version` byte and be documented in a new SPEC revision. Verifiers **MUST** return `UNSUPPORTED_VERSION` for unknown versions.

## 10. Privacy

The QR exposes only data the issuer encodes (hash, ids, chosen claims). The registry **MUST NOT** hold personal data or claim text. Issuers **SHOULD** minimise claims printed on public documents.
