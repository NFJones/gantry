# Lexical joinall selection

The nested block joins only its own `local` task. The outer `joinall()` includes
`first` and `second` in declaration order, excludes the already consumed
`taken`, and cannot include the later `last`. The next join selects one child
and returns `Int`; the final empty join yields `Unit`. All tasks are hook-free.

Spec: [lexical selection and empty/single joins](../../../SPEC.md#GNT-10.6),
[join shape table](../../../SPEC.md#1410-joinall-unit-tasks-and-detachment).
See [Parallel Execution](../../../docs/parallel-execution.md).

From the repository root (build once and reuse):

```sh
timeout 120 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/concurrency/lexical-joinall
```

Expected foreground JSON:

```json
{"consumed":5,"nested":33,"selected":[11,22],"later":44}
```

One passing scenario, zero dispatches. This is lexical selection, not a global
wait for every task in the execution.

Coverage boundary: the nested block runs before the outer value spawns. Current
analysis incorrectly removes outer membership when an earlier nested
`joinall()` runs while outer handles remain attached. This package avoids that
implementation gap rather than claiming to test that overlapping-scope case.
