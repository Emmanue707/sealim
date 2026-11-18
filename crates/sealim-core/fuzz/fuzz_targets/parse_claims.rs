#![no_main]

use libfuzzer_sys::fuzz_target;
use sealim_core::Claims;

fuzz_target!(|data: &[u8]| {
    let _ = Claims::parse(data);
});