# Attempt a sealed decision

Purpose: handle a `Decision` result or operation error without treating a false
decision as failure. An empty rationale is invalid structured output.

Links: [source](main.gnt), [cases](case.json), [Decision](../../../SPEC.md#GNT-5.10),
[validation](../../../SPEC.md#GNT-8.8), [attempt](../../../SPEC.md#GNT-5.9),
[runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/actions/attempt-decide`.

Expected: four passing scenarios, one dispatch each, returning `"review completed"`
for both true and false decisions, and `"review unavailable"` for timeout or invalid
rationale. The hook expects the
sealed `Decision` type; the entry returns only an ordinary String.

Validation gap: reading a Decision extracted from the attempt Result and inspecting
individual OperationError variants triggered current interpreter `internal-invariant`
failures. These cases validate success/error branching, not sealed payload inspection;
the defects are not normative language semantics.
