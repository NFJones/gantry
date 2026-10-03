# Prompt output repair and exhaustion

Purpose: request a typed struct with an ordered named input and allow one repair
after invalid structured output. A retry is not another source evaluation.

Links: [source](main.gnt), [cases](case.json), [repair contract](../../../SPEC.md#GNT-8.9),
[exhaustion](../../../SPEC.md#GNT-8.11), [runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/boundaries/validation-retry-prompt`.

Expected: two passing assertions, two dispatches each. Scenario 1 returns
`{"count":15,"title":"Offline examples"}` after repair; both requests carry the
same typed `topic` input. Scenario 2 is an expected terminal failure,
`structured-output-exhaustion`, after two outputs omit required `count`.
