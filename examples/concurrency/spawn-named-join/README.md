# Spawn and named join

Create a typed child, complete it with a task-local `return`, and consume its
handle once with `join(answer)`. One child yields its `Int` directly, not a list.
No host hooks or completion-order assumptions are needed.

Spec: [spawn forms](../../../SPEC.md#GNT-10.1),
[child returns](../../../SPEC.md#GNT-10.4),
[named joins](../../../SPEC.md#GNT-10.5).
See also [Parallel Execution](../../../docs/parallel-execution.md).

From the repository root, build the shared runner once and reuse it:

```sh
timeout 120 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/concurrency/spawn-named-join
```

Expected foreground JSON: `42`. The runner reports one passing scenario and
zero dispatches after terminal settlement. It exercises concurrent execution,
not a guarantee of physical overlap or a particular scheduling order.
