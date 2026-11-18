//! Core types and constants for the Sealim payload format.

/// Payload layout version byte (v1).
pub const PAYLOAD_VERSION: u8 = 1;

/// Domain-separation prefix for Ed25519 signatures (SPEC section 4).
/// The signed message is this slice, one zero byte, then payload bytes before the signature field.
pub const SIGNING_CONTEXT: &[u8] = b"SEALIM-SIG-v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_version_is_one() {
        assert_eq!(PAYLOAD_VERSION, 1);
    }

    #[test]
    fn signing_context_length() {
        assert_eq!(SIGNING_CONTEXT.len(), 13);
    }
}
