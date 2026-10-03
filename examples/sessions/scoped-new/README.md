# A shared lexical new conversation

The first scoped request starts empty even after the root seed. The second
reuses the scope's accepted turn. Both requests use inline because the scope
already established the session. Exiting restores the unchanged parent history.

Spec: [session creation and reuse](../../../SPEC.md#GNT-7.12),
[request session use](../../../SPEC.md#GNT-7.5).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/sessions/scoped-new
timeout 180s target/debug/examples/corpus examples/sessions/scoped-new
```

`case.json` schema: `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Expected is exact final JSON;
hooks are ordered and fully consumed. Pointers address full dispatch envelopes.
Session-service calls and cross-request ID comparisons are outside this runner;
the script checks empty initial history, continuity and exact restored history.
See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
