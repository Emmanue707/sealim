#![no_main]

use libfuzzer_sys::fuzz_target;
use sealim_core::Payload;

fuzz_target!(|data: &[u8]| {
    let _ = Payload::from_bytes(data);
});