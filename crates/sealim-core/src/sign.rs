//! Signing helpers (SPEC section 4).

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::claims::Claims;
use crate::error::PayloadError;
use crate::payload::{Payload, PAYLOAD_VERSION};

/// Domain-separation prefix for Ed25519 signatures (SPEC section 4).
pub const SIGNING_CONTEXT: &[u8] = b"SEALIM-SIG-v1";

/// TEST KEY ONLY — deterministic seed 0x01..0x20. Never use for real credentials.
pub fn test_signing_key_for_tests() -> SigningKey {
    let seed: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
    SigningKey::from_bytes(&seed)
}

/// Bytes signed by the issuer: context, 0x00, then unsigned payload.
pub fn signed_message(payload: &Payload) -> Result<Vec<u8>, PayloadError> {
    let unsigned = payload.encode_unsigned()?;
    let mut msg = Vec::with_capacity(SIGNING_CONTEXT.len() + 1 + unsigned.len());
    msg.extend_from_slice(SIGNING_CONTEXT);
    msg.push(0x00);
    msg.extend_from_slice(&unsigned);
    Ok(msg)
}

/// First eight bytes of SHA-256(issuer Ed25519 public key).
pub fn key_id(verifying_key: &VerifyingKey) -> [u8; 8] {
    let digest = Sha256::digest(verifying_key.as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Build and sign a v1 payload.
pub fn seal(
    signing_key: &SigningKey,
    doc_bytes: Option<&[u8]>,
    doc_hash: Option<[u8; 32]>,
    claims: Claims,
    doc_id: [u8; 16],
    issued_at: u64,
    flags: u8,
) -> Result<Payload, PayloadError> {
    let doc_hash = match (doc_bytes, doc_hash) {
        (Some(bytes), None) => {
            let digest = Sha256::digest(bytes);
            let mut d = [0u8; 32];
            d.copy_from_slice(&digest);
            d
        }
        (None, Some(h)) => h,
        (Some(_), Some(_)) | (None, None) => return Err(PayloadError::MissingDocument),
    };

    let verifying_key = signing_key.verifying_key();
    let kid = key_id(&verifying_key);

    let mut payload = Payload {
        version: PAYLOAD_VERSION,
        flags,
        key_id: kid,
        doc_id,
        issued_at,
        doc_hash,
        claims,
        signature: [0u8; 64],
    };

    let msg = signed_message(&payload)?;
    let sig = signing_key.sign(&msg);
    payload.signature.copy_from_slice(sig.to_bytes().as_ref());
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::ClaimsBuilder;
    use crate::payload::FLAG_CLAIMS_PRESENT;
    use ed25519_dalek::Signature;

    #[test]
    fn key_id_is_hash_prefix() {
        let sk = test_signing_key_for_tests();
        let kid = key_id(&sk.verifying_key());
        let digest = Sha256::digest(sk.verifying_key().as_bytes());
        assert_eq!(&kid, &digest[..8]);
    }

    #[test]
    fn seal_and_verify_strict() {
        let sk = test_signing_key_for_tests();
        let doc = b"test credential bytes";
        let doc_id = [0xab; 16];
        let mut b = ClaimsBuilder::new();
        b.insert("n", "Jane Kila").unwrap();
        let claims = b.build().unwrap();
        let payload = seal(
            &sk,
            Some(doc),
            None,
            claims,
            doc_id,
            1_735_689_600,
            FLAG_CLAIMS_PRESENT,
        )
        .unwrap();
        assert_eq!(payload.version, PAYLOAD_VERSION);
        let msg = signed_message(&payload).unwrap();
        let sig = Signature::from_bytes(&payload.signature);
        sk.verifying_key()
            .verify_strict(&msg, &sig)
            .expect("signature verifies");
    }
}
