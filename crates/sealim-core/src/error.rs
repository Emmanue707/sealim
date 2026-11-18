//! Error types for encode, decode, and trust-file parsing.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClaimsError {
    #[error("claim key must be 1–3 lowercase letters a–z")]
    InvalidKey,
    #[error("duplicate claim key")]
    DuplicateKey,
    #[error("claim value must be non-empty UTF-8")]
    EmptyValue,
    #[error("claim value contains control characters")]
    ControlCharacter,
    #[error("claim value has leading or trailing whitespace")]
    UntrimmedValue,
    #[error("claims exceed maximum length of 160 bytes")]
    TooLong,
    #[error("claims encoding is not canonical")]
    NonCanonical,
    #[error("malformed claims record")]
    Malformed,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PayloadError {
    #[error("unsupported payload version")]
    UnsupportedVersion,
    #[error("payload length does not match claims_len")]
    LengthMismatch,
    #[error("reserved flag bits are set")]
    ReservedFlags,
    #[error("claims_len inconsistent with flags")]
    ClaimsFlagMismatch,
    #[error("{0}")]
    Claims(#[from] ClaimsError),
    #[error("payload exceeds maximum size")]
    TooLarge,
    #[error("document bytes or hash required")]
    MissingDocument,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QrTextError {
    #[error("QR text missing SL1: prefix")]
    BadPrefix,
    #[error("invalid base45 encoding")]
    BadBase45,
    #[error("empty payload after decode")]
    Empty,
    #[error("{0}")]
    Payload(#[from] PayloadError),
}

#[cfg(feature = "trust")]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustError {
    #[error("invalid trust file format")]
    Format,
    #[error("unsupported trust file version")]
    Version,
    #[error("issuer key_id does not match public key hash")]
    KeyIdMismatch,
    #[error("invalid issuer public key")]
    InvalidPublicKey,
    #[error("registry_url set without registry_public_key")]
    MissingRegistryKey,
    #[error("invalid base64 in trust file")]
    InvalidBase64,
    #[error("invalid timestamp in trust file")]
    InvalidTimestamp,
    #[error("duplicate issuer key_id")]
    DuplicateKeyId,
}
