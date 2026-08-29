#![no_main]

use gantry_core::identity::ProtocolIdentity;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(value) = std::str::from_utf8(input) {
        let _ = ProtocolIdentity::parse(value);
    }
});
