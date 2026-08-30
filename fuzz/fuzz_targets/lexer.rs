#![no_main]

use gantry_core::source::{SourceLimits, SourceSnapshotBuilder};
use gantry_frontend::{LexContext, Lexer, TokenKind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    for context in [
        LexContext::Ordinary,
        LexContext::DirectiveInteger,
        LexContext::PromptTemplate,
    ] {
        scan(input, context);
    }
});

fn scan(input: &[u8], context: LexContext) {
    let limits = SourceLimits::new(1, 1_048_576, 1_048_576, 65_536, 65_536)
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
    let Ok(mut lexer) = Lexer::new(record, counters) else {
        return;
    };
    loop {
        match lexer.next(context) {
            Ok(token) if matches!(token.kind(), TokenKind::EndOfFile) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
}
