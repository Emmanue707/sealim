use std::fs;
use std::path::PathBuf;

use sealim_core::{verify, TrustStore};

use crate::exit::CliError;
use crate::output;
use crate::qr_input;

pub struct VerifyOptions {
    pub qr: Option<String>,
    pub qr_file: Option<PathBuf>,
    pub image: Option<PathBuf>,
    pub file: Option<PathBuf>,
    pub trust: Option<PathBuf>,
    pub json: bool,
    pub registry: Option<String>,
}

pub fn run(opts: VerifyOptions) -> Result<sealim_core::ResultCode, CliError> {
    let qr_text = qr_input::load_qr_text(
        opts.qr.as_deref(),
        opts.qr_file.as_deref(),
        opts.image.as_deref(),
    )?;

    let trust_path = qr_input::trust_path(opts.trust.as_deref())?;
    let trust_json = fs::read_to_string(&trust_path).map_err(|e| {
        CliError::io(format!(
            "cannot read trust file {}: {e}",
            trust_path.display()
        ))
    })?;
    let trust = TrustStore::from_file_json(&trust_json)
        .map_err(|_| CliError::usage("invalid or unsupported trust file"))?;

    let file_bytes = match &opts.file {
        Some(path) => Some(
            fs::read(path)
                .map_err(|e| CliError::io(format!("cannot read {}: {e}", path.display())))?,
        ),
        None => None,
    };

    let registry = crate::registry::registry_status_for_qr(&qr_text, opts.registry.as_deref());
    let result = verify(&qr_text, file_bytes.as_deref(), &trust, registry);

    output::print_verification(&result, opts.json)?;
    Ok(result.code)
}
