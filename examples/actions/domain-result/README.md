# Domain Result is not an operation failure

Purpose: match a typed action's ordinary `Ok` and `Err` domain values. Accepted
`Err(Missing)` is successful fulfillment, not a retry or an implicit host-error catch.

Links: [source](main.gnt), [cases](case.json), [Result](../../../SPEC.md#GNT-5.8),
[tagged JSON](../../../SPEC.md#GNT-8.5), [runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/actions/domain-result`.

Expected: three passing assertions, one dispatch each. Results are `"found: 42"`
and `"missing: answer"`. The third scenario is separately classified as the
expected runtime failure `policy-denied`; it does not fabricate `Err(Missing)`.
