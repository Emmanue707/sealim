#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sealim_core::{
    key_id, seal, test_signing_key_for_tests, to_qr_text, Claims, ClaimsBuilder, Payload,
    RegistryStatus, ResultCode, FLAG_CLAIMS_PRESENT, FLAG_REGISTRY, PAYLOAD_VERSION, QR_PREFIX,
};
use sha2::{Digest, Sha256};

pub const ISSUED_AT: u64 = 1_735_689_600;
pub const DOC_ID: [u8; 16] = [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
pub const FILE_BYTES: &[u8] = b"University of Waghi synthetic transcript for Test Student";

pub fn test_signing_key() -> SigningKey {
    test_signing_key_for_tests()
}

pub fn seed_hex() -> String {
    (1u8..=32).map(|b| format!("{b:02x}")).collect()
}

pub fn public_key_b64url(sk: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(sk.verifying_key().as_bytes())
}

pub fn trust_json_for(
    sk: &SigningKey,
    valid_from: &str,
    valid_until: Option<&str>,
) -> serde_json::Value {
    let kid = key_id(&sk.verifying_key());
    serde_json::json!({
        "format": "sealim-trust",
        "version": 1,
        "updated_at": "2026-01-01T00:00:00Z",
        "issuers": [{
            "name": "University of Waghi",
            "key_id": hex::encode(kid),
            "public_key": public_key_b64url(sk),
            "valid_from": valid_from,
            "valid_until": valid_until,
            "registry_url": "https://registry.example.invalid/v1",
            "registry_public_key": public_key_b64url(sk)
        }]
    })
}

pub fn standard_claims() -> Claims {
    let mut b = ClaimsBuilder::new();
    b.insert("d", "2026-01-15").unwrap();
    b.insert("n", "Jane Kila").unwrap();
    b.insert("t", "BSc Computing").unwrap();
    b.build().unwrap()
}

pub fn seal_with(sk: &SigningKey, claims: Claims, flags: u8, doc_bytes: Option<&[u8]>) -> Payload {
    seal(sk, doc_bytes, None, claims, DOC_ID, ISSUED_AT, flags).unwrap()
}

pub fn qr_for(sk: &SigningKey, claims: Claims, flags: u8) -> String {
    to_qr_text(&seal_with(sk, claims, flags, Some(FILE_BYTES))).unwrap()
}

pub fn encode_qr_raw(bytes: &[u8]) -> String {
    format!("{QR_PREFIX}{}", base45::encode(bytes))
}

pub fn doc_hash() -> [u8; 32] {
    let d = Sha256::digest(FILE_BYTES);
    let mut h = [0u8; 32];
    h.copy_from_slice(&d);
    h
}

pub fn unsigned_prefix(sk: &SigningKey, flags: u8, claims_bytes: &[u8]) -> Vec<u8> {
    let kid = key_id(&sk.verifying_key());
    let mut out = Vec::new();
    out.push(PAYLOAD_VERSION);
    out.push(flags);
    out.extend_from_slice(&kid);
    out.extend_from_slice(&DOC_ID);
    out.extend_from_slice(&ISSUED_AT.to_be_bytes());
    out.extend_from_slice(&doc_hash());
    out.extend_from_slice(&(claims_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(claims_bytes);
    out
}

pub fn sign_bytes(sk: &SigningKey, unsigned: &[u8]) -> [u8; 64] {
    let mut msg = Vec::from(sealim_core::SIGNING_CONTEXT);
    msg.push(0);
    msg.extend_from_slice(unsigned);
    sk.sign(&msg).to_bytes()
}

pub fn registry_from_json(v: &serde_json::Value) -> Option<RegistryStatus> {
    match v {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => match s.as_str() {
            "valid" => Some(RegistryStatus::Valid),
            "revoked" => Some(RegistryStatus::Revoked),
            "superseded" => Some(RegistryStatus::Superseded),
            "unreachable" => Some(RegistryStatus::Unreachable),
            _ => None,
        },
        _ => None,
    }
}

pub fn code_from_str(s: &str) -> ResultCode {
    match s {
        "VALID" => ResultCode::Valid,
        "VALID_CLAIMS_ONLY" => ResultCode::ValidClaimsOnly,
        "STATUS_UNKNOWN" => ResultCode::StatusUnknown,
        "HASH_MISMATCH" => ResultCode::HashMismatch,
        "BAD_SIGNATURE" => ResultCode::BadSignature,
        "UNKNOWN_ISSUER" => ResultCode::UnknownIssuer,
        "KEY_NOT_VALID_AT_ISSUE" => ResultCode::KeyNotValidAtIssue,
        "REVOKED" => ResultCode::Revoked,
        "SUPERSEDED" => ResultCode::Superseded,
        "MALFORMED" => ResultCode::Malformed,
        "UNSUPPORTED_VERSION" => ResultCode::UnsupportedVersion,
        other => panic!("unknown expected_code {other}"),
    }
}

pub const FLAG_BOTH: u8 = FLAG_CLAIMS_PRESENT | FLAG_REGISTRY;
