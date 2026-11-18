use std::io::{self, Write};
use std::path::PathBuf;

use sealim_core::ResultCode;

use crate::decode;
use crate::exit::CliError;
use crate::output;
use crate::qr_input;

pub struct InspectOptions {
    pub qr: Option<String>,
    pub qr_file: Option<PathBuf>,
    pub image: Option<PathBuf>,
    pub json: bool,
}

pub fn run(opts: InspectOptions) -> Result<(), CliError> {
    let qr_text = qr_input::load_qr_text(
        opts.qr.as_deref(),
        opts.qr_file.as_deref(),
        opts.image.as_deref(),
    )?;

    if let Err(code) = decode::decode_result_code(&qr_text) {
        let mut out = io::stdout();
        writeln!(out, "{}", code.as_str()).map_err(|e| CliError::io(e.to_string()))?;
        return Err(CliError::Verify(code));
    }

    let payload =
        sealim_core::from_qr_text(&qr_text).map_err(|_| CliError::Verify(ResultCode::Malformed))?;

    output::print_inspection(&payload, opts.json)?;
    Ok(())
}
