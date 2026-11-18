use sealim_core::{from_qr_text, ResultCode, FLAG_REGISTRY, PAYLOAD_VERSION};
use sealim_core::{PayloadError, QrTextError};

pub fn decode_result_code(qr_text: &str) -> Result<(), ResultCode> {
    if !qr_text.starts_with(sealim_core::QR_PREFIX) {
        return Err(ResultCode::Malformed);
    }
    match from_qr_text(qr_text) {
        Err(QrTextError::BadPrefix) => Err(ResultCode::Malformed),
        Err(QrTextError::BadBase45) | Err(QrTextError::Empty) => Err(ResultCode::Malformed),
        Err(QrTextError::Payload(PayloadError::UnsupportedVersion)) => {
            Err(ResultCode::UnsupportedVersion)
        }
        Err(QrTextError::Payload(_)) => Err(ResultCode::Malformed),
        Ok(p) if p.version != PAYLOAD_VERSION => Err(ResultCode::UnsupportedVersion),
        Ok(_) => Ok(()),
    }
}

pub fn registry_status_for_qr(qr_text: &str) -> Option<sealim_core::RegistryStatus> {
    let payload = from_qr_text(qr_text).ok()?;
    if payload.flags & FLAG_REGISTRY != 0 {
        Some(sealim_core::RegistryStatus::Unreachable)
    } else {
        None
    }
}
