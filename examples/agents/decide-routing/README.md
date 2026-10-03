# Semantic routing with decide

Three scripts cover publish, review and revise. The second decide is dispatched
only when the first is false; a conditional chain is not itself a model call.
Decide has no result annotation and requires a sealed Decision JSON object.

Spec: [routing and Decision](../../../SPEC.md#146-reusable-model-judgments-and-conditional-chains),
[request kinds](../../../SPEC.md#GNT-7.5).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/agents/decide-routing
timeout 180s target/debug/examples/corpus examples/agents/decide-routing
```

`case.json` schema: `{ "scenarios": [CASE, ...] }` with no other outer fields.
Each full CASE is `{ "class": "host", "expected": JSON, "input"?: JSON,
"hooks": [{ "kind": "prompt" | "decide" | "action", "output": JSON,
"assert_request"?: { "JSON pointer": JSON } }] }`. Scenarios execute independently;
scripts are ordered and fully consumed. See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
