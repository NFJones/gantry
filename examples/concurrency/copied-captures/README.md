# Deep copied captures

Both children snapshot the same mutable nested struct before the parent edits
it. `changed` mutates its own preserved-mutability capture; `original` retains
the spawn-time value. Neither mutation leaks across task boundaries, even if a
child is scheduled after the parent updates its copy. There are no hooks.

Spec: [deep isolated captures](../../../SPEC.md#GNT-10.3) and
[named joins](../../../SPEC.md#GNT-10.5).
See [Spawn and captures](../../../docs/parallel-execution.md#spawn-and-captures).

From the repository root (build once and reuse):

```sh
timeout 120 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/concurrency/copied-captures
```

Expected foreground JSON:

```json
{"parent":{"inner":{"value":20},"label":"parent"},"changed":{"inner":{"value":8},"label":"child"},"original":{"inner":{"value":7},"label":"seed"}}
```

One passing scenario, zero dispatches. The result tests deep isolation rather
than relying on parent/child FIFO execution.
