# Retain one judgment

One dispatch yields a Decision reused in two conditions. Both outcomes are
scripted; reusing the retained value never makes another model call. Only the
deterministic route crosses the entry result boundary, which excludes sealed
Decision values.

Limitation: the current evaluator fails with `InternalInvariant` when projecting
`.decision` or `.rationale`, despite those projections being specified. This
example avoids projections; it does not treat that failure as successful behavior.

Spec: [retained decisions](../../../SPEC.md#146-reusable-model-judgments-and-conditional-chains).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/agents/retained-decision
timeout 180s target/debug/examples/corpus examples/agents/retained-decision
```

`case.json` schema: `{ "scenarios": [CASE, ...] }`, where each full CASE is
`{ "class": "host", "expected": JSON, "input"?: JSON, "hooks": [{ "kind":
"prompt" | "decide" | "action", "output": JSON, "assert_request"?: {
"JSON pointer": JSON } }] }`. Expected is exact final JSON; scripts are ordered,
fully consumed and isolated per scenario. See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
