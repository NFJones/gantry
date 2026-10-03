# Heterogeneous named join

Join distinct `String`, `Bool`, and `Int` results into a positional tuple, then
destructure and reconstruct it. Argument order defines both types and values;
the JSON boundary encodes the tuple as an array. All children are hook-free.

Spec: [join shapes](../../../SPEC.md#GNT-10.5),
[heterogeneous example](../../../SPEC.md#149-parallel-heterogeneous-work-and-tuple-joins),
and [JSON boundary](../../../SPEC.md#GNT-8.2).

From the repository root (build once, reuse thereafter):

```sh
timeout 120 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/concurrency/heterogeneous-join
```

Expected foreground JSON: `["ready",true,7]`; one passing scenario, zero
dispatches. Nothing depends on completion order or host queue assignment.
