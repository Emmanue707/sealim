use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::getrandom;
use sealim_core::{seal, to_qr_text, ClaimsBuilder, FLAG_CLAIMS_PRESENT, FLAG_REGISTRY};

use crate::exit::CliError;
use crate::keys;
use crate::passphrase;
use crate::qrimg;

pub struct SealOptions {
    pub key: PathBuf,
    pub passphrase_file: Option<PathBuf>,
    pub file: PathBuf,
    pub claims: Vec<String>,
    pub png: Option<PathBuf>,
    pub svg: Option<PathBuf>,
    pub qr_text: Option<PathBuf>,
    pub doc_id: Option<String>,
    pub issued_at: Option<u64>,
    pub registry: bool,
}

pub fn run(opts: SealOptions) -> Result<(), CliError> {
    let pass = passphrase::read_passphrase(opts.passphrase_file.as_deref())?;
    let unlocked = keys::unlock_key(&opts.key, pass.as_str())?;

    let doc_bytes = fs::read(&opts.file)
        .map_err(|e| CliError::io(format!("cannot read {}: {e}", opts.file.display())))?;

    let mut builder = ClaimsBuilder::new();
    for raw in &opts.claims {
        let (key, value) = raw.split_once('=').ok_or_else(|| {
            CliError::usage(format!("invalid --claim (expected key=value): {raw}"))
        })?;
        builder
            .insert(key, value)
            .map_err(|e| CliError::usage(format!("invalid claim: {e}")))?;
    }
    let claims = builder
        .build()
        .map_err(|e| CliError::usage(format!("{e}")))?;

    let mut flags = 0u8;
    if !claims.is_empty() {
        flags |= FLAG_CLAIMS_PRESENT;
    }
    if opts.registry {
        flags |= FLAG_REGISTRY;
    }

    let doc_id = parse_or_random_doc_id(opts.doc_id.as_deref())?;
    let issued_at = opts.issued_at.unwrap_or_else(unix_now);

    let payload = seal(
        &unlocked.signing_key,
        Some(&doc_bytes),
        None,
        claims,
        doc_id,
        issued_at,
        flags,
    )
    .map_err(|e| CliError::io(format!("seal failed: {e}")))?;

    let qr = to_qr_text(&payload).map_err(|e| CliError::io(format!("QR encode failed: {e}")))?;

    if let Some(path) = &opts.qr_text {
        fs::write(path, &qr)
            .map_err(|e| CliError::io(format!("cannot write QR text {}: {e}", path.display())))?;
    }

    if let Some(path) = &opts.png {
        qrimg::write_png(path, &qr)?;
    }
    if let Some(path) = &opts.svg {
        qrimg::write_svg(path, &qr)?;
    }

    let mut out = io::stdout();
    writeln!(out, "{qr}").map_err(|e| CliError::io(e.to_string()))?;
    Ok(())
}

fn parse_or_random_doc_id(hex_str: Option<&str>) -> Result<[u8; 16], CliError> {
    match hex_str {
        Some(s) => {
            if s.len() != 32 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(CliError::usage(
                    "--doc-id must be 32 lowercase hex characters (16 bytes)",
                ));
            }
            let bytes = hex::decode(s).map_err(|_| CliError::usage("invalid --doc-id hex"))?;
            let mut id = [0u8; 16];
            id.copy_from_slice(&bytes);
            Ok(id)
        }
        None => {
            let mut id = [0u8; 16];
            getrandom(&mut id).map_err(|e| CliError::io(format!("random failed: {e}")))?;
            Ok(id)
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
