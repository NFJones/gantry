# Expected validation retry exhaustion

Purpose: show an unattempted action failing after its initial invalid output and
one invalid repair. This is a failure demonstration, not a successful update.

Links: [source](main.gnt), [case](case.json), [exhaustion](../../../SPEC.md#GNT-8.11),
[runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/actions/retry-exhaustion`.

Expected: the runner reports one passing **failure assertion**, two dispatches,
and terminal code `structured-output-exhaustion`. There is no Gantry result value.
