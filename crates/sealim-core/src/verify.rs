//! Verification orchestration (SPEC section 6).

use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};

use crate::error::{PayloadError, QrTextError};
use crate::payload::{Payload, FLAG_REGISTRY, PAYLOAD_VERSION};
use crate::qrtext::{from_qr_text, QR_PREFIX};
use crate::sign::signed_message;
use crate::trust::TrustStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    Valid,
    ValidClaimsOnly,
    StatusUnknown,
    HashMismatch,
    BadSignature,
    UnknownIssuer,
    KeyNotValidAtIssue,
    Revoked,
    Superseded,
    Malformed,
    UnsupportedVersion,
}

impl ResultCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ResultCode::Valid => "VALID",
            ResultCode::ValidClaimsOnly => "VALID_CLAIMS_ONLY",
            ResultCode::StatusUnknown => "STATUS_UNKNOWN",
            ResultCode::HashMismatch => "HASH_MISMATCH",
            ResultCode::BadSignature => "BAD_SIGNATURE",
            ResultCode::UnknownIssuer => "UNKNOWN_ISSUER",
            ResultCode::KeyNotValidAtIssue => "KEY_NOT_VALID_AT_ISSUE",
            ResultCode::Revoked => "REVOKED",
            ResultCode::Superseded => "SUPERSEDED",
            ResultCode::Malformed => "MALFORMED",
            ResultCode::UnsupportedVersion => "UNSUPPORTED_VERSION",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryStatus {
    Valid,
    Revoked,
    Superseded,
    Unreachable,
}

#[derive(Debug, Clone)]
pub struct IssuerInfo {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Verification {
    pub code: ResultCode,
    pub payload: Option<Payload>,
    pub issuer: Option<IssuerInfo>,
    pub claims: Vec<(String, String)>,
    pub detail: Option<String>,
}

pub fn verify(
    qr_text: &str,
    file_bytes: Option<&[u8]>,
    trust: &TrustStore,
    registry_status: Option<RegistryStatus>,
) -> Verification {
    if !qr_text.starts_with(QR_PREFIX) {
        return Verification {
            code: ResultCode::Malformed,
            payload: None,
            issuer: None,
            claims: Vec::new(),
            detail: None,
        };
    }

    let payload = match decode_payload(qr_text) {
        Ok(p) => p,
        Err(code) => {
            return Verification {
                code,
                payload: None,
                issuer: None,
                claims: Vec::new(),
                detail: None,
            };
        }
    };

    let entry = match trust.lookup(&payload.key_id) {
        Some(e) => e,
        None => {
            return Verification {
                code: ResultCode::UnknownIssuer,
                payload: Some(payload),
                issuer: None,
                claims: Vec::new(),
                detail: None,
            };
        }
    };

    if !verify_signature(&payload, &entry.verifying_key) {
        return Verification {
            code: ResultCode::BadSignature,
            payload: Some(payload),
            issuer: None,
            claims: Vec::new(),
            detail: None,
        };
    }

    let claims_vec = claims_for_display(&payload);
    let issuer = Some(IssuerInfo {
        name: entry.name.clone(),
    });

    if !key_valid_at_issue(payload.issued_at, entry.valid_from, entry.valid_until) {
        return Verification {
            code: ResultCode::KeyNotValidAtIssue,
            payload: Some(payload),
            issuer,
            claims: claims_vec,
            detail: None,
        };
    }

    if let Some(bytes) = file_bytes {
        let hash = Sha256::digest(bytes);
        if hash.as_slice() != payload.doc_hash.as_slice() {
            return Verification {
                code: ResultCode::HashMismatch,
                payload: Some(payload),
                issuer,
                claims: claims_vec,
                detail: None,
            };
        }
    }

    if payload.flags & FLAG_REGISTRY != 0 {
        return match registry_status {
            Some(RegistryStatus::Revoked) => Verification {
                code: ResultCode::Revoked,
                payload: Some(payload),
                issuer,
                claims: claims_vec,
                detail: None,
            },
            Some(RegistryStatus::Superseded) => Verification {
                code: ResultCode::Superseded,
                payload: Some(payload),
                issuer,
                claims: claims_vec,
                detail: None,
            },
            Some(RegistryStatus::Unreachable) | None => Verification {
                code: ResultCode::StatusUnknown,
                payload: Some(payload),
                issuer,
                claims: claims_vec,
                detail: None,
            },
            Some(RegistryStatus::Valid) => {
                finish_success(payload, issuer, claims_vec, file_bytes.is_some())
            }
        };
    }

    finish_success(payload, issuer, claims_vec, file_bytes.is_some())
}

fn finish_success(
    payload: Payload,
    issuer: Option<IssuerInfo>,
    claims: Vec<(String, String)>,
    file_supplied: bool,
) -> Verification {
    let code = if file_supplied {
        ResultCode::Valid
    } else {
        ResultCode::ValidClaimsOnly
    };
    Verification {
        code,
        payload: Some(payload),
        issuer,
        claims,
        detail: None,
    }
}

fn decode_payload(qr_text: &str) -> Result<Payload, ResultCode> {
    match from_qr_text(qr_text) {
        Err(QrTextError::BadPrefix) => Err(ResultCode::Malformed),
        Err(QrTextError::BadBase45) | Err(QrTextError::Empty) => Err(ResultCode::Malformed),
        Err(QrTextError::Payload(PayloadError::UnsupportedVersion)) => {
            Err(ResultCode::UnsupportedVersion)
        }
        Err(QrTextError::Payload(_)) => Err(ResultCode::Malformed),
        Ok(p) if p.version != PAYLOAD_VERSION => Err(ResultCode::UnsupportedVersion),
        Ok(p) => Ok(p),
    }
}

fn verify_signature(payload: &Payload, key: &ed25519_dalek::VerifyingKey) -> bool {
    let msg = match signed_message(payload) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&payload.signature);
    key.verify_strict(&msg, &sig).is_ok()
}

fn key_valid_at_issue(issued_at: u64, valid_from: i64, valid_until: Option<i64>) -> bool {
    if (issued_at as i64) < valid_from {
        return false;
    }
    if let Some(until) = valid_until {
        if (issued_at as i64) > until {
            return false;
        }
    }
    true
}

fn claims_for_display(payload: &Payload) -> Vec<(String, String)> {
    payload
        .claims
        .pairs()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::ClaimsBuilder;
    use crate::payload::FLAG_CLAIMS_PRESENT;
    use crate::qrtext::to_qr_text;
    use crate::sign::key_id;
    use crate::sign::{seal, test_signing_key_for_tests};
    use crate::trust::TrustStore;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    fn test_trust(sk: &ed25519_dalek::SigningKey) -> TrustStore {
        let vk = sk.verifying_key();
        let kid = key_id(&vk);
        let pk_b64 = URL_SAFE_NO_PAD.encode(vk.as_bytes());
        let key_id_hex = hex::encode(kid);
        let json = format!(
            r#"{{
  "format": "sealim-trust",
  "version": 1,
  "updated_at": "2026-01-01T00:00:00Z",
  "issuers": [{{
    "name": "University of Waghi",
    "key_id": "{key_id_hex}",
    "public_key": "{pk_b64}",
    "valid_from": "2020-01-01T00:00:00Z",
    "valid_until": null
  }}]
}}"#
        );
        TrustStore::from_file_json(&json).unwrap()
    }

    const DOC_ID: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const ISSUED_AT: u64 = 1_735_689_600;
    const FILE: &[u8] = b"University of Waghi test transcript";

    fn sample_qr(sk: &ed25519_dalek::SigningKey, claims: bool) -> String {
        let mut b = ClaimsBuilder::new();
        if claims {
            b.insert("d", "2026-01-15").unwrap();
            b.insert("n", "Jane Kila").unwrap();
            b.insert("t", "BSc Computing").unwrap();
        }
        let flags = if claims { FLAG_CLAIMS_PRESENT } else { 0 };
        let payload = seal(
            sk,
            Some(FILE),
            None,
            b.build().unwrap(),
            DOC_ID,
            ISSUED_AT,
            flags,
        )
        .unwrap();
        to_qr_text(&payload).unwrap()
    }

    #[test]
    fn valid_with_file() {
        let sk = test_signing_key_for_tests();
        let trust = test_trust(&sk);
        let qr = sample_qr(&sk, true);
        let v = verify(&qr, Some(FILE), &trust, None);
        assert_eq!(v.code, ResultCode::Valid);
        assert_eq!(v.issuer.unwrap().name, "University of Waghi");
    }

    #[test]
    fn valid_claims_only() {
        let sk = test_signing_key_for_tests();
        let trust = test_trust(&sk);
        let qr = sample_qr(&sk, true);
        let v = verify(&qr, None, &trust, None);
        assert_eq!(v.code, ResultCode::ValidClaimsOnly);
    }
}
