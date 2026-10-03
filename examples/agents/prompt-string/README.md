# String generation with the default agent

`main.gnt` makes one visible model operation and returns its validated String.
The offline hook supplies JSON string output, not unquoted provider text.
Assertions check default selection, authored text, empty inputs and inline use.

Spec: [agents](../../../SPEC.md#GNT-7.1), [requests](../../../SPEC.md#GNT-7.5).

Run from the repository root (build once):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/agents/prompt-string
timeout 180s target/debug/examples/corpus examples/agents/prompt-string
```

`case.json` schema: one `{ "class": "host", "expected": JSON, "hooks": [
{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } } ] }`. Optional `input` is entry
JSON; `expected` is the exact final value. Hooks are ordered and fully consumed.
The runner is [support/mod.rs](../../../crates/gantry-conformance/examples/support/mod.rs).
