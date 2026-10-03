# Explicit inline continuity

Both the lexical scope and operation-local modifier reuse the active session.
The second request must contain exactly the accepted Unit seed exchange.

Spec: [canonical sessions](../../../SPEC.md#GNT-7.12),
[request session use](../../../SPEC.md#GNT-7.5).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/sessions/inline
timeout 180s target/debug/examples/corpus examples/sessions/inline
```

`case.json` schema: `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Hooks are ordered and fully
consumed; expected is exact final JSON. Pointers address full dispatch envelopes.
The runner cannot compare IDs across requests or assert session-service calls;
this package asserts inline mode and exact transcript instead.
See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
