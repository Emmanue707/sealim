//! QR text encoding (`SL1:` + base45).

use base45::decode;

use crate::error::{PayloadError, QrTextError};
use crate::payload::Payload;

pub const QR_PREFIX: &str = "SL1:";

pub fn to_qr_text(payload: &Payload) -> Result<String, PayloadError> {
    let bytes = payload.to_bytes()?;
    let encoded = base45::encode(&bytes);
    Ok(format!("{QR_PREFIX}{encoded}"))
}

pub fn from_qr_text(text: &str) -> Result<Payload, QrTextError> {
    if !text.starts_with(QR_PREFIX) {
        return Err(QrTextError::BadPrefix);
    }
    let b45 = &text[QR_PREFIX.len()..];
    let bytes = decode(b45).map_err(|_| QrTextError::BadBase45)?;
    if bytes.is_empty() {
        return Err(QrTextError::Empty);
    }
    Payload::from_bytes(&bytes).map_err(QrTextError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::ClaimsBuilder;
    use crate::payload::FLAG_CLAIMS_PRESENT;
    use crate::sign::{seal, test_signing_key_for_tests};

    #[test]
    fn qr_round_trip() {
        let sk = test_signing_key_for_tests();
        let mut b = ClaimsBuilder::new();
        b.insert("d", "2026-01-15").unwrap();
        b.insert("n", "Jane Kila").unwrap();
        b.insert("t", "BSc Computing").unwrap();
        let payload = seal(
            &sk,
            Some(b"example file"),
            None,
            b.build().unwrap(),
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
            1_735_689_600,
            FLAG_CLAIMS_PRESENT,
        )
        .unwrap();
        let qr = to_qr_text(&payload).unwrap();
        assert!(qr.starts_with(QR_PREFIX));
        let decoded = from_qr_text(&qr).unwrap();
        assert_eq!(decoded.doc_hash, payload.doc_hash);
    }
}
