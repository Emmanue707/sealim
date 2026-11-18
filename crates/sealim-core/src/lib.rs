//! Core types for the Sealim payload format: encode, sign, and verify.

mod claims;
mod error;
mod payload;
mod qrtext;
mod sign;
#[cfg(feature = "trust")]
mod trust;
mod verify;

pub use claims::{Claims, ClaimsBuilder, CLAIMS_MAX_LEN};
#[cfg(feature = "trust")]
pub use error::TrustError;
pub use error::{ClaimsError, PayloadError, QrTextError};
pub use payload::{
    Payload, FIXED_HEADER_LEN, FLAG_CLAIMS_PRESENT, FLAG_REGISTRY, PAYLOAD_MAX_LEN,
    PAYLOAD_MIN_LEN, PAYLOAD_VERSION, SIGNATURE_LEN,
};
pub use qrtext::{from_qr_text, to_qr_text, QR_PREFIX};
pub use sign::{key_id, seal, signed_message, test_signing_key_for_tests, SIGNING_CONTEXT};
#[cfg(feature = "trust")]
pub use trust::{IssuerEntry, TrustStore};
pub use verify::{verify, IssuerInfo, RegistryStatus, ResultCode, Verification};

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn payload_bytes_roundtrip(
            key_id in prop::array::uniform8(any::<u8>()),
            doc_id in prop::array::uniform16(any::<u8>()),
            issued_at in any::<u64>(),
            doc_hash in prop::array::uniform32(any::<u8>()),
            sig_lo in prop::array::uniform32(any::<u8>()),
            sig_hi in prop::array::uniform32(any::<u8>()),
        ) {
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&sig_lo);
            sig[32..].copy_from_slice(&sig_hi);
            let payload = Payload {
                version: PAYLOAD_VERSION,
                flags: 0,
                key_id,
                doc_id,
                issued_at,
                doc_hash,
                claims: Claims::new(),
                signature: sig,
            };
            let bytes = payload.to_bytes().unwrap();
            let again = Payload::from_bytes(&bytes).unwrap();
            assert_eq!(again.version, payload.version);
            assert_eq!(again.doc_hash, payload.doc_hash);
        }

        #[test]
        fn claims_builder_roundtrip(
            name in "[A-Za-z][A-Za-z0-9]{0,12}",
            title in "[A-Za-z0-9]{1,18}",
        ) {
            let mut b = ClaimsBuilder::new();
            b.insert("n", &name).unwrap();
            b.insert("t", &title).unwrap();
            let claims = b.build().unwrap();
            let bytes = claims.encode_canonical().unwrap();
            let parsed = Claims::parse(&bytes).unwrap();
            prop_assert_eq!(claims, parsed);
        }
    }
}
