# Unit generation

Omitting `-> T` requests Unit. The hook still runs and must return JSON `null`;
Unit does not mean a skipped operation or permission for external mutation.

Spec: [result kinds](../../../SPEC.md#GNT-7.5),
[read-only model work](../../../SPEC.md#GNT-7.14).

Run from the repository root (Cargo builds once, then use the binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/agents/prompt-unit
timeout 180s target/debug/examples/corpus examples/agents/prompt-unit
```

`case.json` schema: `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Explicit null is required
for this final value and hook output. Scripts are ordered and fully consumed.
See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
