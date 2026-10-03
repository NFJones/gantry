# Attempt a prompt

Purpose: handle provider failure or invalid output from exactly one prompt as
source data. Zero retries makes invalid-output exhaustion immediate.

Links: [source](main.gnt), [cases](case.json), [attempt](../../../SPEC.md#GNT-5.9),
[failure scope](../../../SPEC.md#1413-explicit-operation-failure-handling-with-attempt),
[runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/actions/attempt-prompt`.

Expected: three passing scenarios, one dispatch each, returning `"Ready."`,
then `"summary unavailable"` for both provider failure and invalid output. No real model is contacted.
This does not catch deterministic evaluation failures or task cancellation.

Validation gap: individual OperationError variant inspection triggered a current
interpreter `internal-invariant` failure. The executable example deliberately
handles Err without inspecting its sealed payload; that defect is not normative.
