//! Trust file parsing (`sealim-trust` v1).

use std::collections::HashMap;

use crate::error::TrustError;
use crate::sign::key_id;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct IssuerEntry {
    pub name: String,
    pub key_id: [u8; 8],
    pub verifying_key: VerifyingKey,
    pub valid_from: i64,
    pub valid_until: Option<i64>,
    pub registry_url: Option<String>,
    pub registry_public_key: Option<VerifyingKey>,
}

#[derive(Debug, Default, Clone)]
pub struct TrustStore {
    by_key_id: HashMap<[u8; 8], IssuerEntry>,
}

impl TrustStore {
    pub fn from_file_json(json: &str) -> Result<Self, TrustError> {
        let file: TrustFile<'_> = serde_json::from_str(json).map_err(|_| TrustError::Format)?;
        if file.format != "sealim-trust" {
            return Err(TrustError::Format);
        }
        if file.version != 1 {
            return Err(TrustError::Version);
        }

        let mut by_key_id = HashMap::new();
        for issuer in file.issuers {
            let pk_bytes = decode_b64_32(issuer.public_key)?;
            let verifying_key = load_verifying_key(&pk_bytes)?;

            let computed = key_id(&verifying_key);
            let declared = parse_key_id_hex(issuer.key_id)?;
            if computed != declared {
                return Err(TrustError::KeyIdMismatch);
            }

            let valid_from = parse_rfc3339_secs(issuer.valid_from)?;
            let valid_until = match &issuer.valid_until {
                None => None,
                Some(s) => Some(parse_rfc3339_secs(s)?),
            };

            let registry_url = issuer.registry_url.map(|s| s.to_string());
            let registry_public_key = match (&registry_url, &issuer.registry_public_key) {
                (Some(_), Some(b64)) => Some(load_verifying_key(&decode_b64_32(b64)?)?),
                (Some(_), None) => return Err(TrustError::MissingRegistryKey),
                (None, Some(_)) => return Err(TrustError::MissingRegistryKey),
                (None, None) => None,
            };

            if by_key_id.contains_key(&declared) {
                return Err(TrustError::DuplicateKeyId);
            }

            by_key_id.insert(
                declared,
                IssuerEntry {
                    name: issuer.name.to_string(),
                    key_id: declared,
                    verifying_key,
                    valid_from,
                    valid_until,
                    registry_url,
                    registry_public_key,
                },
            );
        }

        Ok(TrustStore { by_key_id })
    }

    pub fn lookup(&self, key_id: &[u8; 8]) -> Option<&IssuerEntry> {
        self.by_key_id.get(key_id)
    }

    pub fn issuers(&self) -> impl Iterator<Item = &IssuerEntry> {
        self.by_key_id.values()
    }
}

#[derive(Debug, Deserialize)]
struct TrustFile<'a> {
    format: &'a str,
    version: u32,
    #[allow(dead_code)]
    updated_at: &'a str,
    issuers: Vec<TrustIssuer<'a>>,
}

#[derive(Debug, Deserialize)]
struct TrustIssuer<'a> {
    name: &'a str,
    key_id: &'a str,
    public_key: &'a str,
    valid_from: &'a str,
    valid_until: Option<&'a str>,
    registry_url: Option<&'a str>,
    registry_public_key: Option<&'a str>,
}

fn decode_b64_32(s: &str) -> Result<[u8; 32], TrustError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|_| TrustError::InvalidBase64)?;
    if bytes.len() != 32 {
        return Err(TrustError::InvalidPublicKey);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn load_verifying_key(bytes: &[u8; 32]) -> Result<VerifyingKey, TrustError> {
    VerifyingKey::from_bytes(bytes).map_err(|_| TrustError::InvalidPublicKey)
}

fn parse_key_id_hex(s: &str) -> Result<[u8; 8], TrustError> {
    if s.len() != 16 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(TrustError::KeyIdMismatch);
    }
    let mut out = [0u8; 8];
    hex::decode_to_slice(s, &mut out).map_err(|_| TrustError::KeyIdMismatch)?;
    Ok(out)
}

fn parse_rfc3339_secs(s: &str) -> Result<i64, TrustError> {
    use time::format_description::well_known::Rfc3339;
    let dt = time::OffsetDateTime::parse(s, &Rfc3339).map_err(|_| TrustError::InvalidTimestamp)?;
    Ok(dt.unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::test_signing_key_for_tests;

    #[test]
    fn parse_trust_with_test_key() {
        let sk = test_signing_key_for_tests();
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
    "valid_until": null,
    "registry_url": null
  }}]
}}"#
        );
        let store = TrustStore::from_file_json(&json).unwrap();
        assert!(store.lookup(&kid).is_some());
    }

    #[test]
    fn rejects_key_id_mismatch() {
        let sk = test_signing_key_for_tests();
        let vk = sk.verifying_key();
        let pk_b64 = URL_SAFE_NO_PAD.encode(vk.as_bytes());
        let json = format!(
            r#"{{
  "format": "sealim-trust",
  "version": 1,
  "updated_at": "2026-01-01T00:00:00Z",
  "issuers": [{{
    "name": "University of Waghi",
    "key_id": "0000000000000000",
    "public_key": "{pk_b64}",
    "valid_from": "2020-01-01T00:00:00Z",
    "valid_until": null
  }}]
}}"#
        );
        assert!(matches!(
            TrustStore::from_file_json(&json),
            Err(TrustError::KeyIdMismatch)
        ));
    }
}
