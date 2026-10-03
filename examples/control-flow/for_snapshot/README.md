# Finite for loops use a snapshot

[main.gnt](main.gnt) sums `[1, 2, 3]` while replacing the original list
with `[99]`. The loop still visits the three snapshot items in order.
Each item binding is fresh and immutable. A second loop over an empty list
executes no body. Finite `for` loops do not take source-level limit modifiers.

From the repository root, build once and reuse the binary:

```sh
cargo build -p gantry-cli
```

Commands (exit 0, empty stderr):

```sh
target/debug/gantry check examples/control-flow/for_snapshot
target/debug/gantry analyze examples/control-flow/for_snapshot
target/debug/gantry run examples/control-flow/for_snapshot
```

Expected stdout, respectively:

```text
syntax-valid
source-valid
{"current":99,"empty_visits":0,"total":6,"visits":3}
```

See [case.json](case.json), [SPEC §9](../../../SPEC.md#GNT-9.4),
[loop grammar](../../../SPEC.md#GNT-13.8), and
[loop authoring examples](../../../SPEC.md#147-finite-general-pre-test-and-post-test-loops).
