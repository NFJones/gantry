# Parallel compare and synthesize

Two deterministic child workflows normalize copied candidate values. Explicit
join argument order fixes the resulting list order regardless of completion.
Source compares the results, then dispatches one synthesis prompt only when they
differ. Equal candidates return without a model operation.

The multi-path scripts assert the exact joined comparison supplied to synthesis.
No sibling task dispatches a hook: the shared FIFO script never assumes a
concurrent model-operation order. This example demonstrates parallel deterministic
preparation, not simultaneous model calls.

From the repository root, build once and reuse:

```sh
timeout 180 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/workflows/parallel_compare_synthesize
```

Spec: [spawn and join](../../../SPEC.md#GNT-10.3),
[ordered homogeneous joins](../../../SPEC.md#148-parallel-homogeneous-work-and-listt-joins),
[named inputs](../../../SPEC.md#1412-explicit-harness-actions-and-named-prompt-inputs).
