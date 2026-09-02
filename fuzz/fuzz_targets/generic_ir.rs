#![no_main]

use gantry_ir::{
    CanonicalCallableIdentity, CanonicalTemplateIdentity, TypeDescriptor, TypeExpression,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Ok(value) = std::str::from_utf8(input) else {
        return;
    };
    let _ = TypeExpression::from_canonical_string(value, 256);
    let _ = TypeDescriptor::from_canonical_string_with_depth_limit(value, 256);
    let _ = CanonicalCallableIdentity::from_canonical_string(value, 256);
    let _ = CanonicalTemplateIdentity::from_canonical_string(value, 256);
});
