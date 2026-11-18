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
    let dt = chrono_from_rfc3339(s)?;
    Ok(dt)
}

/// Minimal RFC3339 parser for trust timestamps (UTC Z suffix).
fn chrono_from_rfc3339(s: &str) -> Result<i64, TrustError> {
    if s.len() < 20 {
        return Err(TrustError::InvalidTimestamp);
    }
    let (date, time) = s.split_once('T').ok_or(TrustError::InvalidTimestamp)?;
    if date.len() != 10 || time.len() < 8 {
        return Err(TrustError::InvalidTimestamp);
    }
    let year: i64 = date[0..4]
        .parse()
        .map_err(|_| TrustError::InvalidTimestamp)?;
    let month: i64 = date[5..7]
        .parse()
        .map_err(|_| TrustError::InvalidTimestamp)?;
    let day: i64 = date[8..10]
        .parse()
        .map_err(|_| TrustError::InvalidTimestamp)?;
    let hour: i64 = time[0..2]
        .parse()
        .map_err(|_| TrustError::InvalidTimestamp)?;
    let min: i64 = time[3..5]
        .parse()
        .map_err(|_| TrustError::InvalidTimestamp)?;
    let sec: i64 = time[6..8]
        .parse()
        .map_err(|_| TrustError::InvalidTimestamp)?;
    if !time.ends_with('Z') {
        return Err(TrustError::InvalidTimestamp);
    }
    Ok(timestamp_from_utc_parts(year, month, day, hour, min, sec))
}

fn timestamp_from_utc_parts(y: i64, m: i64, d: i64, h: i64, min: i64, s: i64) -> i64 {
    // Days from civil date algorithm (Howard Hinnant).
    let civil_from = (m - 14) / 12;
    let y_adj = y + civil_from;
    let m_adj = m - 12 * civil_from - 3;
    let days = d + (153 * m_adj + 2) / 5 + 365 * y_adj + y_adj / 4 - y_adj / 100 + y_adj / 400;
    let unix_days = days - 719468;
    unix_days * 86_400 + h * 3600 + min * 60 + s
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
