use std::fs;
use std::path::Path;

use serde_json::json;
use time::OffsetDateTime;

use crate::exit::CliError;

pub fn rfc3339_now() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
    )
}

pub fn default_valid_from() -> String {
    rfc3339_now()
}

pub fn build_trust_json(
    name: &str,
    key_id_hex: &str,
    public_key_b64: &str,
    valid_from: &str,
    valid_until: Option<&str>,
) -> String {
    let updated_at = rfc3339_now();
    let issuer = json!({
        "name": name,
        "key_id": key_id_hex,
        "public_key": public_key_b64,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "registry_url": null
    });
    let doc = json!({
        "format": "sealim-trust",
        "version": 1,
        "updated_at": updated_at,
        "issuers": [issuer]
    });
    serde_json::to_string_pretty(&doc).expect("trust JSON serialises")
}

pub fn write_trust(path: &Path, json: &str) -> Result<(), CliError> {
    fs::write(path, json)
        .map_err(|e| CliError::io(format!("cannot write trust file {}: {e}", path.display())))
}
