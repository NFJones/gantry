# Classify into an enum, then route

A model produces a closed `Route`; deterministic exhaustive matching chooses the
next workflow. Classification is not a Boolean judgment or free-form parsing.
Specialist selection applies only to the selected response operation.

Offline scripts cover every enum variant. They assert the classifier contract,
input, selected specialist and branch-specific prompt; Ignore has no second hook.

From the repository root, build once and reuse:

```sh
timeout 180 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/workflows/classify_enum_route
```

Spec: [tagged values and routing](../../../SPEC.md#143-primitive-values-structs-tagged-values-and-structural-routing),
[structured validation](../../../SPEC.md#GNT-8.6),
[agent scope](../../../SPEC.md#144-inherent-methods-and-scoped-agent-selection).
