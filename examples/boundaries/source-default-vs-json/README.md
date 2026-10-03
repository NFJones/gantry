# Source defaults do not make JSON fields optional

Purpose: contrast source omission syntax (`Settings {}`) with typed entry JSON
for the same type. Non-optional fields remain required at external boundaries
even when they have source defaults. Only `note: Option<String>` may be omitted.

Links: [source](main.gnt), [cases](case.json), [source construction](../../../SPEC.md#GNT-5.11),
[entry requirements](../../../SPEC.md#GNT-4.2), [boundary normalization](../../../SPEC.md#GNT-8.2),
[runner](../../../crates/gantry-conformance/examples/corpus.rs).

Build once: `timeout 180 cargo build -p gantry-conformance --example corpus`.
Run: `timeout 120 target/debug/examples/corpus examples/boundaries/source-default-vs-json`.

Expected: two passing scenarios, zero dispatches. Results are
`{"enabled":false,"note":null,"retries":5}` and
`{"enabled":true,"note":"explicit","retries":2}`. Both inputs explicitly supply
the non-optional fields despite their source defaults; omitted `note` becomes null.

Validation gaps: the runner cannot assert pre-execution entry rejection, so missing
`enabled` or `retries` is a normative rejection requirement, not an executed assertion
here. Attempts to construct this type in source or return it from an action stopped
before dispatch in the current implementation. Omitted source-default materialization
and default-bearing hook output therefore remain unvalidated. These defects and
incomplete observed source values are not presented as normative successes.
Optional properties with declared defaults are also not exercised.
