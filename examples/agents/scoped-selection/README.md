# Default, scoped and nested multi-agent selection

Calls to the same workflow inherit the active agent. `with` expressions yield
values, nested selection overrides its parent, and leaving a block restores
the previous selection. The script checks writer/reviewer/editor routing at
all six sites. This is sequential multi-agent work, not parallel execution.

Spec: [dynamic selection](../../../SPEC.md#GNT-7.3),
[with expressions](../../../SPEC.md#144-inherent-methods-and-scoped-agent-selection).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/agents/scoped-selection
timeout 180s target/debug/examples/corpus examples/agents/scoped-selection
```

`case.json` schema: `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Scripts are ordered and
fully consumed; expected is the final JSON tuple. See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
