# Structured generation

The declared `Summary` result is decoded and validated by Gantry, not by the
hook. The script supplies the complete strict-JSON object.

Spec: [output contract](../../../SPEC.md#GNT-7.9),
[request contract](../../../SPEC.md#GNT-7.5).

Run from the repository root; the first command builds the runner once:

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/agents/prompt-structured
timeout 180s target/debug/examples/corpus examples/agents/prompt-structured
```

`case.json` schema: `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Expected is the exact final
value; hooks are ordered, and pointers address the full dispatch envelope.
See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
