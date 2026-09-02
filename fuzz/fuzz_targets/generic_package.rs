#![no_main]

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use gantry_analysis::analyze_package_types_with_limits;
use gantry_core::source::{FrontendLimits, SourceLimits};
use gantry_frontend::validate_package_syntax;
use libfuzzer_sys::fuzz_target;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fuzz_target!(|input: &[u8]| {
    let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "gantry-generic-package-fuzz-{}-{suffix}",
        std::process::id()
    ));
    if fs::create_dir(&root).is_err() || fs::write(root.join("main.gnt"), input).is_err() {
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let source_limits = SourceLimits::new(1, 65_536, 65_536, 16_384, 64)
        .unwrap_or_else(|_| unreachable!("positive source limits"));
    if let Ok(phase) = validate_package_syntax(&root, source_limits, 64) {
        let limits = FrontendLimits::new(
            1, 65_536, 65_536, 16_384, 64, 262_144, 262_144, 262_144, 262_144, 64, 256,
            4_096,
        )
        .unwrap_or_else(|_| unreachable!("positive frontend limits"));
        let _ = analyze_package_types_with_limits(&phase, limits);
    }
    let _ = fs::remove_dir_all(root);
});
