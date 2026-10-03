# Typed read-only lookup

Purpose: declare a read-only harness capability with a struct argument and result.
No model agent is required; the offline host supplies the record, not a real database.

Links: [source](main.gnt), [case](case.json), [action contract](../../../SPEC.md#GNT-6.12),
[offline runner](../../../crates/gantry-conformance/examples/corpus.rs).

From the repository root, build once for all packages:
`timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/actions/read-only`.

Expected: one passing scenario, one action dispatch, result
`{"key":"answer","value":42}`. The script asserts the path, recovery class,
typed argument, and expected result type.
