# Strict typed entry JSON

Purpose: supply the single entry argument as its direct JSON value, not a wrapper
named `request`. Struct fields, booleans, list elements, tuple positions, and enum
tags have exact types. The result echoes the fully validated value.

Links: [source](main.gnt), [cases](case.json), [entry contract](../../../SPEC.md#GNT-4.0),
[strict JSON](../../../SPEC.md#GNT-8.1), [tagged values](../../../SPEC.md#GNT-8.5),
[runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/boundaries/typed-entry`.

Expected: two passing scenarios, zero dispatches; each result equals its input.
The runner serializes `input` as JSON and currently cannot assert pre-execution
entry rejection. Malformed bytes, duplicate keys, missing required entry fields,
extra fields, and wrong entry types therefore remain validation gaps here, not
documented successes. Hook shape failures are covered by [invalid-output](../invalid-output).
