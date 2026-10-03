# Strict output shape failures

Purpose: reject extra struct properties, unknown enum tags, a payload on a unit
variant, a missing payload, wrong tuple arity, and wrong positional types.

Links: [source](main.gnt), [cases](case.json), [tuples](../../../SPEC.md#GNT-8.4),
[tagged JSON](../../../SPEC.md#GNT-8.5), [strict validation](../../../SPEC.md#GNT-8.8),
[runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/boundaries/invalid-output`.

Expected: seven passing assertions, one dispatch each. Only scenario 1 succeeds,
returning `{"pair":[42,"ok"],"status":{"variant":"Ready"}}`. Each remaining
scenario is an expected `structured-output-exhaustion` runtime failure, not a
normalized success. Zero retries prevents accidental repair.

The runner serializes hook `output` values; it cannot supply malformed raw JSON,
duplicate object keys, trailing data, or invalid UTF-8. Those byte-level strictness
rules are specification requirements but are not validated by this package.
