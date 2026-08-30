#![no_main]

use gantry_core::canonical_json::CanonicalJson;
use gantry_core::strict_json::{JsonLimits, StrictJsonDocument};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let maximum_bytes = u64::try_from(input.len()).unwrap_or(u64::MAX);
    let limits = JsonLimits {
        maximum_bytes,
        maximum_nesting_depth: 256,
        maximum_nodes: 4_096,
        maximum_string_scalars: 65_536,
        maximum_list_items: 4_096,
    };
    if let Ok(document) = StrictJsonDocument::decode(input, limits) {
        let _ = CanonicalJson::from_document(&document);
    }
});
