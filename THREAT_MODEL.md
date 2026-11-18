# Threat model

This document complements [SPEC.md](SPEC.md). It describes assets, actors, assumptions, and how design choices respond to threats. Sealim has **not** been independently audited; treat residual risks accordingly.

## Assets

- **Issuer signing keys** — Ed25519 private keys used to seal documents.
- **Digital issued files** — PDFs, transcripts, exports whose integrity is bound via `doc_hash`.
- **QR payloads** — Signed data on paper or screen; may include visible claims.
- **Trust files** — JSON lists of issuer public keys and metadata used offline.
- **Registry data** — Document identifiers, hashes, status, and timestamps (no document bodies or personal claims).

## Actors

| Actor | Goal |
|-------|------|
| Forger | Present a fake credential as genuine |
| Dishonest holder | Reuse a valid QR on a different document or file |
| Compromised issuer | Sign fraudulent documents with a stolen key |
| Malicious registry operator | Hide revocations or publish false status |
| Network attacker | MITM registry or trust-file download |

## Assumptions

- Verifiers run unmodified Sealim software and a trust file from a trusted distribution path.
- Ed25519 and SHA-256 behave as standard primitives; implementations use strict signature verification.
- Human checkers performing paper verification actually compare visible claims to the physical document when no file is supplied.
- CSPRNGs on issuer systems produce unpredictable `doc_id` values.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|--------|------------|---------------|
| Altered digital file | `doc_hash` in payload; verifier returns `HASH_MISMATCH` | User must supply the correct file |
| Forged QR without private key | Ed25519 signature verification | Broken crypto or implementation bug |
| QR copied onto another printed document | Signed visible claims shown to checker; compare to paper | Checker neglects comparison; issuers should print claims beside the QR |
| Issuer key theft | Registry revocation, key validity windows, passphrase-encrypted key files (Argon2id + age) | Offline verifiers with stale revocation cache |
| Fake trust file or fake verifier app | Distribute trust file from official issuer channels; pin trust in verifier; future signed trust files | User installs malicious app |
| Registry downtime or tampering | Offline verification still works; `STATUS_UNKNOWN` when registry unreachable; signed revocation lists (API v1) | User ignores warnings |
| Replay of registry write requests | 300 s timestamp window and replay cache per signature | Clock skew misconfiguration |
| Privacy leakage via QR | Issuer chooses minimal claims; registry stores no names or claim text | Issuer over-collects in claims field |
| Malicious QR payload | Strict parsing; reserved flag bits must be zero; length bounds | Parser bugs |

## Out of scope

- Coerced or corrupt issuers who willingly sign false documents.
- Social engineering of checkers or issuers.
- Proving the identity of the person holding a paper document (Sealim binds document/data to issuer signature, not biometrics).

## Limitations

The design reduces common forgery and tampering paths but does not replace organisational process, training for checkers, or third-party audit of this codebase.
