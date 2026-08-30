#![no_main]

use gantry_core::source::{SourceLimits, SourceSnapshotBuilder};
use gantry_frontend::Parser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let limits = SourceLimits::new(1, 1_048_576, 1_048_576, 65_536, 64)
        .unwrap_or_else(|_| unreachable!("positive limits"));
    let mut builder = SourceSnapshotBuilder::new(limits);
    if builder.add_file("main.gnt", input).is_err() {
        return;
    }
    let mut snapshot = builder.finish();
    let (records, counters) = snapshot.records_and_counters_mut();
    let Some(record) = records.first() else {
        return;
    };
    let _ = Parser::new(record, counters).parse_module();
});
