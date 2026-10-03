# Non-idempotent send: never validation-retry

Purpose: declare a capability that could duplicate effects if repeated and set
its mandatory zero retry policy explicitly. The offline host sends no message.

Links: [source](main.gnt), [cases](case.json), [action classes](../../../SPEC.md#GNT-6.12),
[retry restriction](../../../SPEC.md#GNT-8.9), [runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/actions/non-idempotent`.

Expected: two passing assertions, one dispatch each. Scenario 1 returns
`{"number":7}`. Scenario 2 is an expected runtime failure,
`structured-output-exhaustion`, with no repair dispatch. A positive override
would be an analysis error; this package contains only valid source.
