# Homogeneous named join

Three distinct hook-free `Int` tasks produce `List<Int>`. Reversing the selection
to `third, first, second` proves that positions follow join arguments, not spawn
declarations or completion time. No FIFO host-response race is involved.

Spec: [named joins](../../../SPEC.md#GNT-10.5) and
[homogeneous example](../../../SPEC.md#148-parallel-homogeneous-work-and-listt-joins).
See [Parallel Execution](../../../docs/parallel-execution.md).

From the repository root (build once; reuse the binary for other packages):

```sh
timeout 120 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/concurrency/homogeneous-join
```

Expected foreground JSON: `[30,10,20]`; one passing scenario, zero dispatches.
The example does not force or measure the children’s physical completion order.
