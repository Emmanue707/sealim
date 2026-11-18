use std::fs;
use std::path::Path;

use image::Luma;
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};
use rqrr::PreparedImage;

use crate::exit::CliError;

pub fn write_png(path: &Path, qr_text: &str) -> Result<(), CliError> {
    let code = QrCode::with_error_correction_level(qr_text.as_bytes(), EcLevel::M)
        .map_err(|e| CliError::io(format!("QR encode failed: {e}")))?;
    let image = code.render::<Luma<u8>>().min_dimensions(512, 512).build();
    image
        .save(path)
        .map_err(|e| CliError::io(format!("cannot write PNG {}: {e}", path.display())))
}

pub fn write_svg(path: &Path, qr_text: &str) -> Result<(), CliError> {
    let code = QrCode::with_error_correction_level(qr_text.as_bytes(), EcLevel::M)
        .map_err(|e| CliError::io(format!("QR encode failed: {e}")))?;
    let svg = code
        .render()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();
    fs::write(path, svg)
        .map_err(|e| CliError::io(format!("cannot write SVG {}: {e}", path.display())))
}

pub fn decode_qr_from_image(path: &Path) -> Result<String, CliError> {
    let img = image::open(path)
        .map_err(|e| CliError::io(format!("cannot read image {}: {e}", path.display())))?;
    let gray = img.to_luma8();
    let mut prepared = PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();

    for grid in grids {
        let Ok((_, content)) = grid.decode() else {
            continue;
        };
        if content.starts_with("SL1:") {
            return Ok(content);
        }
    }

    Err(CliError::usage(
        "no SL1: QR code found in image (try a higher-resolution scan)",
    ))
}
