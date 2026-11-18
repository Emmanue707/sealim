//! Visible claims encoding (SPEC section 3).

use std::collections::BTreeMap;

use unicode_normalization::UnicodeNormalization;

use crate::error::ClaimsError;

const RECORD_SEP: u8 = 0x1f;
pub const CLAIMS_MAX_LEN: usize = 160;

/// Ordered key/value visible claims.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Claims {
    records: BTreeMap<String, String>,
}

impl Claims {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns claims as sorted (key, value) pairs for display.
    pub fn pairs(&self) -> Vec<(&str, &str)> {
        self.records
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.records.get(key).map(String::as_str)
    }
}

/// Builder for validated claims; encode produces canonical bytes.
#[derive(Debug, Default)]
pub struct ClaimsBuilder {
    records: BTreeMap<String, String>,
}

impl ClaimsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), ClaimsError> {
        let key = key.as_ref();
        let value = value.as_ref();

        validate_key(key)?;
        let value = normalize_value(value)?;

        if self.records.contains_key(key) {
            return Err(ClaimsError::DuplicateKey);
        }

        self.records.insert(key.to_string(), value);
        let encoded = Claims {
            records: self.records.clone(),
        }
        .encode_canonical()?;
        if encoded.len() > CLAIMS_MAX_LEN {
            self.records.remove(key);
            return Err(ClaimsError::TooLong);
        }
        Ok(())
    }

    pub fn build(self) -> Result<Claims, ClaimsError> {
        if self.records.is_empty() {
            return Ok(Claims::new());
        }
        Ok(Claims {
            records: self.records,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ClaimsError> {
        if self.records.is_empty() {
            return Ok(Vec::new());
        }
        let claims = Claims {
            records: self.records.clone(),
        };
        claims.encode_canonical()
    }
}

impl Claims {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, ClaimsError> {
        if self.records.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for (idx, (key, value)) in self.records.iter().enumerate() {
            validate_key(key)?;
            if normalize_value(value)? != *value {
                return Err(ClaimsError::NonCanonical);
            }
            if idx > 0 {
                out.push(RECORD_SEP);
            }
            out.extend_from_slice(key.as_bytes());
            out.push(b'=');
            out.extend_from_slice(value.as_bytes());
        }
        if out.len() > CLAIMS_MAX_LEN {
            return Err(ClaimsError::TooLong);
        }
        Ok(out)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ClaimsError> {
        if bytes.is_empty() {
            return Ok(Claims::new());
        }
        if bytes.len() > CLAIMS_MAX_LEN {
            return Err(ClaimsError::TooLong);
        }

        let text = std::str::from_utf8(bytes).map_err(|_| ClaimsError::Malformed)?;
        let mut map = BTreeMap::new();
        let mut prev_key: Option<String> = None;

        for segment in text.split(char::from(RECORD_SEP)) {
            if segment.is_empty() {
                return Err(ClaimsError::Malformed);
            }
            let eq = segment.find('=').ok_or(ClaimsError::Malformed)?;
            let key = &segment[..eq];
            let value = &segment[eq + 1..];

            validate_key(key)?;
            if value.is_empty() {
                return Err(ClaimsError::EmptyValue);
            }
            if value != normalize_value(value)? {
                return Err(ClaimsError::NonCanonical);
            }

            if let Some(ref pk) = prev_key {
                if key <= pk.as_str() {
                    return Err(ClaimsError::NonCanonical);
                }
            }

            if map.insert(key.to_string(), value.to_string()).is_some() {
                return Err(ClaimsError::DuplicateKey);
            }
            prev_key = Some(key.to_string());
        }

        let encoded = Claims {
            records: map.clone(),
        }
        .encode_canonical()?;
        if encoded.as_slice() != bytes {
            return Err(ClaimsError::NonCanonical);
        }

        Ok(Claims { records: map })
    }
}

fn validate_key(key: &str) -> Result<(), ClaimsError> {
    let len = key.len();
    if len == 0 || len > 3 {
        return Err(ClaimsError::InvalidKey);
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_lowercase() && b.is_ascii_alphabetic())
    {
        return Err(ClaimsError::InvalidKey);
    }
    Ok(())
}

fn value_has_control(s: &str) -> bool {
    s.chars().any(|c| {
        let u = c as u32;
        u <= 0x1f || (0x7f..=0x9f).contains(&u)
    })
}

fn normalize_value(value: &str) -> Result<String, ClaimsError> {
    if value.is_empty() {
        return Err(ClaimsError::EmptyValue);
    }
    if value_has_control(value) {
        return Err(ClaimsError::ControlCharacter);
    }
    if value
        .chars()
        .next()
        .map(|c| c.is_whitespace())
        .unwrap_or(false)
        || value
            .chars()
            .last()
            .map(|c| c.is_whitespace())
            .unwrap_or(false)
    {
        return Err(ClaimsError::UntrimmedValue);
    }
    let nfc: String = value.nfc().collect();
    if nfc != value {
        return Err(ClaimsError::NonCanonical);
    }
    Ok(nfc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_example_from_spec() {
        let mut b = ClaimsBuilder::new();
        b.insert("d", "2026-01-15").unwrap();
        b.insert("n", "Jane Kila").unwrap();
        b.insert("t", "BSc Computing").unwrap();
        let bytes = b.encode().unwrap();
        assert_eq!(bytes.len(), 40);
        let parsed = Claims::parse(&bytes).unwrap();
        assert_eq!(parsed.get("n"), Some("Jane Kila"));
    }

    #[test]
    fn rejects_unsorted_on_parse() {
        let bad = b"n=Jane Kila\x1Fd=2026-01-15";
        assert_eq!(Claims::parse(bad), Err(ClaimsError::NonCanonical));
    }

    #[test]
    fn rejects_control_characters() {
        let mut b = ClaimsBuilder::new();
        assert_eq!(
            b.insert("n", "Jane\u{0007}"),
            Err(ClaimsError::ControlCharacter)
        );
    }

    #[test]
    fn round_trip_builder() {
        let mut b = ClaimsBuilder::new();
        b.insert("i", "University of Waghi").unwrap();
        b.insert("r", "WT-001").unwrap();
        let claims = b.build().unwrap();
        let bytes = claims.encode_canonical().unwrap();
        let again = Claims::parse(&bytes).unwrap();
        assert_eq!(claims, again);
    }
}
