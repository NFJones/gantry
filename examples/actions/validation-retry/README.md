# Repair a typed action output

Purpose: explicitly allow one validation retry on a read-only action. The first
output has a wrong field type; the second repairs it. Transport retries are not
Gantry validation retries.

Links: [source](main.gnt), [case](case.json), [captured-input repair](../../../SPEC.md#GNT-8.9),
[retry counts](../../../SPEC.md#GNT-8.10), [runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/actions/validation-retry`.

Expected: one passing scenario, two physical dispatches, result `42`. The script
checks attempts 0 and 1, repair error category, and the same captured typed
arguments, path, mapping revision, and recovery class on both requests.
