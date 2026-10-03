# A shared lexical fork across agents and calls

The scope establishes one fork before its prompts, so their requests say
inline, not create. A workflow call under reviewer inherits both selections;
switching agent does not clear the canonical transcript. Leaving the scope
restores the parent without merging child turns.

Spec: [orthogonal selections](../../../SPEC.md#GNT-7.3),
[lexical sessions](../../../SPEC.md#GNT-7.12).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/sessions/scoped-fork
timeout 180s target/debug/examples/corpus examples/sessions/scoped-fork
```

`case.json` schema: `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Expected is exact final JSON;
hooks are ordered and fully consumed. Pointers address full dispatch envelopes.
The runner does not capture session-service establishment calls or compare IDs;
this script validates inline reuse, inherited history and scope restoration.
See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
