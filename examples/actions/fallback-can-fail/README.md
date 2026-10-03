# A fallback is not automatically caught

Purpose: wrap only the primary prompt in `attempt`. A fallback reached from the
error branch is a new, unattempted operation and can fail normally.

Links: [source](main.gnt), [cases](case.json), [fallback scope](../../../SPEC.md#1413-explicit-operation-failure-handling-with-attempt),
[runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/actions/fallback-can-fail`.

Expected: three passing assertions. Scenario 1 returns `"Summary ready."` in one
dispatch. Scenario 2 returns `"Summary unavailable."` in two. Scenario 3 is an
expected terminal `timeout` failure in two dispatches, not a successful fallback.
