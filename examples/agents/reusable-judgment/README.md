# A reusable judgment workflow

`is_complete` visibly generates a checklist then requests a Decision with
ordered named inputs. The caller retains the returned sealed value. Both
judgments are scripted; a workflow call does not substitute for an operation.

Limitation: projecting `.rationale` from the retained value currently fails
with `InternalInvariant` in the evaluator. This example uses the returned
Decision as a condition instead, without claiming that projections work.

Spec: [judgment workflows](../../../SPEC.md#146-reusable-model-judgments-and-conditional-chains),
[named inputs](../../../SPEC.md#GNT-7.5).

Run from the repository root (build once, then direct binary):

```sh
timeout 180s cargo run --locked -p gantry-conformance --example corpus -- examples/agents/reusable-judgment
timeout 180s target/debug/examples/corpus examples/agents/reusable-judgment
```

`case.json` schema: `{ "scenarios": [CASE, ...] }`, each CASE being
`{ "class": "host", "expected": JSON, "input"?: JSON, "hooks": [{ "kind":
"prompt" | "decide" | "action", "output": JSON, "assert_request"?: {
"JSON pointer": JSON } }] }`. Scripts are ordered and fully consumed; each
scenario has independent execution state. See [runner](../../../crates/gantry-conformance/examples/support/mod.rs).
