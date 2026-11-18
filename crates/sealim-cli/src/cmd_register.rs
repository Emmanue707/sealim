use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use sealim_core::{from_qr_text, sign_request};

use crate::exit::CliError;
use crate::keys;
use crate::passphrase;
use crate::qr_input;

const MAX_RESPONSE: usize = 4096;

pub struct RegisterOptions {
    pub key: PathBuf,
    pub passphrase_file: Option<PathBuf>,
    pub qr: Option<String>,
    pub qr_file: Option<PathBuf>,
    pub image: Option<PathBuf>,
    pub registry: Option<String>,
}

pub fn run(opts: RegisterOptions) -> Result<i32, CliError> {
    let registry_url = opts
        .registry
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CliError::usage("--registry or SEALIM_REGISTRY_URL is required"))?;

    let qr_text = qr_input::load_qr_text(
        opts.qr.as_deref(),
        opts.qr_file.as_deref(),
        opts.image.as_deref(),
    )?;

    let payload = from_qr_text(&qr_text).map_err(|_| CliError::usage("malformed QR payload"))?;

    let pass = passphrase::read_passphrase(opts.passphrase_file.as_deref())?;
    let unlocked = keys::unlock_key(&opts.key, pass.as_str())?;

    let issued_at = payload.issued_at;
    let body = serde_json::json!({
        "doc_id": hex::encode(payload.doc_id),
        "doc_hash": hex::encode(payload.doc_hash),
        "key_id": hex::encode(payload.key_id),
        "issued_at": issued_at,
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| CliError::io(e.to_string()))?;

    let ts = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CliError::io(e.to_string()))?
        .as_secs();
    let sig = sign_request(
        &unlocked.signing_key,
        "POST",
        "/v1/documents",
        ts,
        &body_bytes,
    );

    let url = join_register_url(&registry_url)?;
    let sent = ureq::post(&url)
        .timeout(Duration::from_secs(10))
        .set("Content-Type", "application/json")
        .set("Sealim-Key-Id", &unlocked.key_id_hex)
        .set("Sealim-Timestamp", &ts.to_string())
        .set("Sealim-Signature", &sig)
        .send_bytes(&body_bytes);

    let (status, response) = match sent {
        Ok(r) => (r.status(), r),
        Err(ureq::Error::Status(code, r)) => (code, r),
        Err(e) => return Err(CliError::io(format!("registry request failed: {e}"))),
    };
    let mut reader = response.into_reader();
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    while out.len() < MAX_RESPONSE {
        let n = reader
            .read(&mut buf)
            .map_err(|e| CliError::io(e.to_string()))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }

    let mut stdout = std::io::stdout();
    stdout
        .write_all(&out)
        .and_then(|_| stdout.write_all(b"\n"))
        .map_err(|e| CliError::io(e.to_string()))?;

    Ok(match status {
        200 | 201 => 0,
        409 => 1,
        _ => 2,
    })
}

fn join_register_url(base: &str) -> Result<String, CliError> {
    let base = base.trim_end_matches('/');
    if base.is_empty() {
        return Err(CliError::usage("registry URL is empty"));
    }
    Ok(format!("{base}/v1/documents"))
}
