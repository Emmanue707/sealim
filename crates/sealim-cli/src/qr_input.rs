use std::fs;
use std::path::{Path, PathBuf};

use crate::exit::CliError;
use crate::qrimg;

pub fn load_qr_text(
    qr: Option<&str>,
    qr_file: Option<&Path>,
    image: Option<&Path>,
) -> Result<String, CliError> {
    let n = qr.is_some() as u8 + qr_file.is_some() as u8 + image.is_some() as u8;
    if n != 1 {
        return Err(CliError::usage(
            "exactly one of --qr, --qr-file, or --image is required",
        ));
    }

    match (qr, qr_file, image) {
        (Some(text), None, None) => Ok(text.to_string()),
        (None, Some(path), None) => fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .map_err(|e| CliError::io(format!("cannot read {}: {e}", path.display()))),
        (None, None, Some(path)) => qrimg::decode_qr_from_image(path),
        _ => unreachable!(),
    }
}

pub fn trust_path(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    std::env::var("SEALIM_TRUST_FILE")
        .map(PathBuf::from)
        .map_err(|_| CliError::usage("trust file required: use --trust or set SEALIM_TRUST_FILE"))
}
