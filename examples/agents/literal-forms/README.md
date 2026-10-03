# Quoted, raw and block prompt literals

Three sequential prompts check quoted escapes, raw backslashes with active
interpolation, literal dollar markers and block dedentation. Structural block
newlines are not added to the rendered text.

Spec: [literal forms](../../../SPEC.md#GNT-7.8),
[examples](../../../SPEC.md#145-prompt-strings-interpolation-and-escaping).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/agents/literal-forms
timeout 180s target/debug/examples/corpus examples/agents/literal-forms
```

`case.json` schema: `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Hooks run in order; expected
is the final tuple encoded as a JSON array. Pointers address full requests.
See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
