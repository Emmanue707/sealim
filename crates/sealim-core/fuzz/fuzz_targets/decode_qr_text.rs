#![no_main]

use libfuzzer_sys::fuzz_target;
use sealim_core::from_qr_text;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = from_qr_text(text);
    }
});