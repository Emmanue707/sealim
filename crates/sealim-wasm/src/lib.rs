//! WebAssembly bindings for offline Sealim verification.

pub use sealim_core::PAYLOAD_VERSION;

/// Returns the supported binary payload version byte.
pub fn payload_version() -> u8 {
    PAYLOAD_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reexports_payload_version() {
        assert_eq!(payload_version(), 1);
    }
}
