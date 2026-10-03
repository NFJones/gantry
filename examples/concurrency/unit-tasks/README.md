# Unit tasks

Show implicit and explicit `Unit` tasks, fallthrough, `return;`, `return ();`,
and `()` completion. Named and lexical joins both yield first-class `Unit`.
No value-producing task is mixed into a Unit join. Work stays hook-free.

Spec: [Unit child completion](../../../SPEC.md#GNT-10.4),
[named joins](../../../SPEC.md#GNT-10.5),
[joinall](../../../SPEC.md#GNT-10.6),
[shape table](../../../SPEC.md#1410-joinall-unit-tasks-and-detachment).

From the repository root (build once; reuse the binary):

```sh
timeout 120 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/concurrency/unit-tasks
```

Expected foreground JSON: `null`, the Unit boundary representation. One passing
scenario, zero dispatches. Waiting is observable through completion, not logs
or a presumed execution order.
