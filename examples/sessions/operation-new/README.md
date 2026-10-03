# One-operation new conversation

After accepting a seed in the parent, `session = new` requests an empty
conversation. Its exchange is local to that operation; the following parent
request contains exactly the seed and no fresh-conversation exchange.

Spec: [new semantics](../../../SPEC.md#GNT-7.12),
[request contract](../../../SPEC.md#GNT-7.5).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/sessions/operation-new
timeout 180s target/debug/examples/corpus examples/sessions/operation-new
```

`case.json` schema: `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Expected is exact final JSON;
hooks are ordered and fully consumed. Pointers address full dispatch envelopes.
Generated-ID relationships cannot be compared by this runner; creation mode,
empty fresh history and exact restored history are checked instead.
See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
