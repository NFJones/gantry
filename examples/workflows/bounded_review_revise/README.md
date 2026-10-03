# Bounded review and revision

Compose a reviewer workflow and writer workflow, retaining each returned revision
explicitly. At most two revisions occur. Reaching the bound returns `accepted:
false`; it does not claim that the last unreviewed revision is approved.

The offline scenarios cover immediate acceptance, one revision then acceptance,
and exhaustion. Request assertions verify copied draft propagation and scoped
agent selection. Full script consumption proves no third review occurs.

From the repository root, build once and reuse:

```sh
timeout 180 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/workflows/bounded_review_revise
```

Spec: [copy semantics](../../../SPEC.md#GNT-6.4),
[judgments](../../../SPEC.md#146-reusable-model-judgments-and-conditional-chains),
[bounded loops](../../../SPEC.md#147-finite-general-pre-test-and-post-test-loops).
