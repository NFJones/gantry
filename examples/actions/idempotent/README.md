# Typed idempotent update

Purpose: describe an update whose repeated fulfillment has the same intended
effect. The recovery class is a host contract, not a proof performed by Gantry;
this offline example does not modify an external service or test durable replay.

Links: [source](main.gnt), [case](case.json), [actions](../../../SPEC.md#GNT-6.12),
[runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/actions/idempotent`.

Expected: one passing scenario and one dispatch; result
`{"enabled":true,"key":"alerts"}`. Request assertions verify the typed setting,
canonical path, result descriptor, and `idempotent` class.
