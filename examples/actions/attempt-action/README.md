# Handle one action's operation failure

Purpose: distinguish an action's accepted `Int` from the sealed errors converted
by `attempt`. The default action validation retry count is zero.

Links: [source](main.gnt), [cases](case.json), [OperationError](../../../SPEC.md#GNT-5.9),
[exhaustion](../../../SPEC.md#GNT-8.11), [runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/actions/attempt-action`.

Expected: four passing scenarios, one dispatch each, returning `"found: 42"`,
then `"action unavailable"` for denial, timeout, and invalid output. The hook still expects `Int`,
not `Result<Int,OperationError>`; the wrapper constructs that Result in source.

Validation gap: inspecting individual OperationError variants triggered a current
interpreter `internal-invariant` failure. This example catches the Err branch
without inspecting the sealed payload; it does not endorse that failure as normative.
