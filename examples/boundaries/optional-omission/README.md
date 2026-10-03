# Optional omission normalizes recursively

Purpose: contrast omitted optional properties, explicit null, and present values
at entry and hook boundaries. Nested omissions without defaults become `None`;
normalized arguments and results include those properties as JSON null.

Links: [source](main.gnt), [cases](case.json), [Option JSON](../../../SPEC.md#GNT-8.5),
[recursive normalization](../../../SPEC.md#GNT-8.2), [runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/boundaries/optional-omission`.

Expected: three passing scenarios, one dispatch each. The first two return
explicit null `note` and `count`; the third preserves `"ready"` and `3`.
The first scenario asserts that entry omission was already normalized before
dispatch. This package deliberately uses optional fields without source defaults.
