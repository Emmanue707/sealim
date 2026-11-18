//! Binary payload layout (SPEC section 2).

use crate::claims::{Claims, CLAIMS_MAX_LEN};
use crate::error::PayloadError;

pub const PAYLOAD_VERSION: u8 = 1;
pub const FIXED_HEADER_LEN: usize = 68;
pub const SIGNATURE_LEN: usize = 64;
pub const PAYLOAD_MIN_LEN: usize = FIXED_HEADER_LEN + SIGNATURE_LEN;
pub const PAYLOAD_MAX_LEN: usize = FIXED_HEADER_LEN + CLAIMS_MAX_LEN + SIGNATURE_LEN;

pub const FLAG_CLAIMS_PRESENT: u8 = 0x01;
pub const FLAG_REGISTRY: u8 = 0x02;

/// Decoded Sealim payload (signature included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub version: u8,
    pub flags: u8,
    pub key_id: [u8; 8],
    pub doc_id: [u8; 16],
    pub issued_at: u64,
    pub doc_hash: [u8; 32],
    pub claims: Claims,
    pub signature: [u8; 64],
}

impl Payload {
    pub fn claims_len(&self) -> u16 {
        self.claims
            .encode_canonical()
            .map(|b| b.len() as u16)
            .unwrap_or(0)
    }

    pub fn encode_unsigned(&self) -> Result<Vec<u8>, PayloadError> {
        let claims_bytes = self.claims.encode_canonical()?;
        self.encode_with_claims(&claims_bytes, false)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PayloadError> {
        let claims_bytes = self.claims.encode_canonical()?;
        self.encode_with_claims(&claims_bytes, true)
    }

    fn encode_with_claims(
        &self,
        claims_bytes: &[u8],
        include_sig: bool,
    ) -> Result<Vec<u8>, PayloadError> {
        validate_reserved_flags(self.flags)?;
        validate_flags_and_claims(self.flags, claims_bytes)?;

        let mut out = Vec::with_capacity(FIXED_HEADER_LEN + claims_bytes.len() + SIGNATURE_LEN);
        out.push(self.version);
        out.push(self.flags);
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&self.doc_id);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.doc_hash);
        out.extend_from_slice(&(claims_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(claims_bytes);
        if include_sig {
            out.extend_from_slice(&self.signature);
        }
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PayloadError> {
        if bytes.len() < PAYLOAD_MIN_LEN {
            return Err(PayloadError::LengthMismatch);
        }
        if bytes.len() > PAYLOAD_MAX_LEN {
            return Err(PayloadError::TooLarge);
        }

        let version = bytes[0];
        if version != PAYLOAD_VERSION {
            return Err(PayloadError::UnsupportedVersion);
        }

        let flags = bytes[1];
        if flags & !0b0000_0011 != 0 {
            return Err(PayloadError::ReservedFlags);
        }

        let claims_len = u16::from_be_bytes([bytes[66], bytes[67]]) as usize;
        let expected_len = FIXED_HEADER_LEN + claims_len + SIGNATURE_LEN;
        if bytes.len() != expected_len {
            return Err(PayloadError::LengthMismatch);
        }

        let claims_start = FIXED_HEADER_LEN;
        let claims_end = claims_start + claims_len;
        let claims_bytes = &bytes[claims_start..claims_end];
        validate_flags_and_claims(flags, claims_bytes)?;

        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&bytes[2..10]);
        let mut doc_id = [0u8; 16];
        doc_id.copy_from_slice(&bytes[10..26]);
        let issued_at = u64::from_be_bytes(bytes[26..34].try_into().unwrap());
        let mut doc_hash = [0u8; 32];
        doc_hash.copy_from_slice(&bytes[34..66]);

        let claims = if claims_len == 0 {
            Claims::new()
        } else {
            Claims::parse(claims_bytes)?
        };

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[claims_end..]);

        Ok(Payload {
            version,
            flags,
            key_id,
            doc_id,
            issued_at,
            doc_hash,
            claims,
            signature,
        })
    }
}

pub fn validate_reserved_flags(flags: u8) -> Result<(), PayloadError> {
    if flags & !0b0000_0011 != 0 {
        return Err(PayloadError::ReservedFlags);
    }
    Ok(())
}

pub fn validate_flags_and_claims(flags: u8, claims_bytes: &[u8]) -> Result<(), PayloadError> {
    let claims_bit = flags & FLAG_CLAIMS_PRESENT != 0;
    if claims_bit && claims_bytes.is_empty() {
        return Err(PayloadError::ClaimsFlagMismatch);
    }
    if !claims_bit && !claims_bytes.is_empty() {
        return Err(PayloadError::ClaimsFlagMismatch);
    }
    if claims_bytes.len() > CLAIMS_MAX_LEN {
        return Err(PayloadError::TooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::ClaimsBuilder;

    fn sample_payload() -> Payload {
        let mut b = ClaimsBuilder::new();
        b.insert("d", "2026-01-15").unwrap();
        b.insert("n", "Jane Kila").unwrap();
        b.insert("t", "BSc Computing").unwrap();
        let claims = b.build().unwrap();
        Payload {
            version: PAYLOAD_VERSION,
            flags: FLAG_CLAIMS_PRESENT,
            key_id: [0x11; 8],
            doc_id: [0x22; 16],
            issued_at: 1_700_000_000,
            doc_hash: [0x33; 32],
            claims,
            signature: [0x44; 64],
        }
    }

    #[test]
    fn round_trip_bytes() {
        let p = sample_payload();
        let bytes = p.to_bytes().unwrap();
        assert_eq!(bytes.len(), 172);
        let decoded = Payload::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.key_id, p.key_id);
        assert_eq!(decoded.claims, p.claims);
    }

    #[test]
    fn rejects_reserved_flags() {
        let mut p = sample_payload();
        p.flags |= 0x04;
        assert_eq!(p.to_bytes().unwrap_err(), PayloadError::ReservedFlags);
    }
}
