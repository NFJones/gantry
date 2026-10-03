# Typed, single-pass interpolation

Checks canonical struct key order, optional String quoting, repeated typed
inputs, dollar escaping and replacement text that is never scanned again.
The ordinary String binding itself has no interpolation semantics.

Spec: [interpolation](../../../SPEC.md#GNT-7.7),
[ordered typed inputs](../../../SPEC.md#GNT-7.5).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/agents/interpolation
timeout 180s target/debug/examples/corpus examples/agents/interpolation
```

`case.json` schema: `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Expected is the final value;
ordered hooks assert pointers into the full dispatch envelope.
See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
