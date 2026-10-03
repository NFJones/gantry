# Nested scopes and one-off overrides

A lexical new scope overrides a fork, then restores it. A reviewer decide
uses an operation-local new conversation, without changing the fork's history
or the surrounding agent. Explicit inline then reuses the fork; leaving it
restores the root. Exact transcript checks exclude all nested exchanges.

Spec: [agent/session independence](../../../SPEC.md#GNT-7.3),
[scope and operation-local sessions](../../../SPEC.md#GNT-7.12).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/sessions/scope-overrides
timeout 180s target/debug/examples/corpus examples/sessions/scope-overrides
```

`case.json` schema: `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Expected is exact final JSON;
hooks are ordered and fully consumed. Pointers address full dispatch envelopes.
The runner cannot compare IDs across requests or capture establishment calls;
mode, transcript isolation and restored selection are checked instead.
See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
