use std::io::{self, Write};
use std::path::PathBuf;

use serde_json::json;

use crate::exit::CliError;
use crate::keys;
use crate::passphrase;
use crate::trustout;

pub struct KeygenOptions {
    pub name: String,
    pub out: PathBuf,
    pub passphrase_file: Option<PathBuf>,
    pub trust_out: Option<PathBuf>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub force: bool,
    pub json: bool,
}

pub fn run(opts: KeygenOptions) -> Result<(), CliError> {
    let pass = passphrase::read_passphrase(opts.passphrase_file.as_deref())?;
    let unlocked = keys::generate_and_write_key(&opts.out, pass.as_str(), opts.force)?;

    let valid_from = opts.valid_from.unwrap_or_else(trustout::default_valid_from);
    let trust_json = trustout::build_trust_json(
        &opts.name,
        &unlocked.key_id_hex,
        &unlocked.public_key_b64,
        &valid_from,
        opts.valid_until.as_deref(),
    );

    if let Some(path) = &opts.trust_out {
        trustout::write_trust(path, &trust_json)?;
    } else {
        let mut out = io::stdout();
        writeln!(out, "{trust_json}").map_err(|e| CliError::io(e.to_string()))?;
    }

    if opts.json {
        let obj = json!({
            "key_id": unlocked.key_id_hex,
            "public_key": unlocked.public_key_b64,
            "name": opts.name,
            "key_file": opts.out,
        });
        let mut out = io::stdout();
        writeln!(out, "{}", serde_json::to_string(&obj).unwrap())
            .map_err(|e| CliError::io(e.to_string()))?;
    } else {
        let mut out = io::stdout();
        writeln!(out, "key_id: {}", unlocked.key_id_hex)
            .map_err(|e| CliError::io(e.to_string()))?;
        writeln!(out, "public_key: {}", unlocked.public_key_b64)
            .map_err(|e| CliError::io(e.to_string()))?;
    }

    Ok(())
}
