# One-operation fork

The fork request creates a child conversation with the accepted seed prefix.
Its result does not enter the parent's transcript; the following unmodified
prompt reuses the parent with exactly the seed turn.

Spec: [fork semantics](../../../SPEC.md#GNT-7.12),
[create versus inline](../../../SPEC.md#GNT-7.5).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/sessions/operation-fork
timeout 180s target/debug/examples/corpus examples/sessions/operation-fork
```

`case.json` schema: `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Expected is exact final JSON;
hooks are ordered and fully consumed. Pointers address full dispatch envelopes.
The runner cannot compare generated session IDs across requests; assertions
check creation mode and exact parent/child transcript content instead.
See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
