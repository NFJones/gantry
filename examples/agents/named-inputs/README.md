# Named model inputs

Entry JSON supplies `topic`. Shorthand and explicitly named computed inputs
are sent in source order without insertion into the authored prompt text.

Spec: [using grammar](../../../SPEC.md#GNT-13.7),
[input protocol](../../../SPEC.md#GNT-7.5).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/agents/named-inputs
timeout 180s target/debug/examples/corpus examples/agents/named-inputs
```

`case.json` schema: `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Input is entry JSON,
expected is the exact final value, and hooks are ordered and fully consumed.
See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
