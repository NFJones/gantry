# While tests before entering the body

[main.gnt](main.gnt) calls a counting workflow with stops `0` and `3`.
The false initial condition admits no body. The second call enters exactly
three bodies, then finishes when its condition becomes false, even though
all three permitted body entries have been used. A source limit is a ceiling,
not a requested iteration count.

From the repository root, build once and reuse the binary:

```sh
cargo build -p gantry-cli
```

Commands (exit 0, empty stderr):

```sh
target/debug/gantry check examples/control-flow/while_pretest
target/debug/gantry analyze examples/control-flow/while_pretest
target/debug/gantry run examples/control-flow/while_pretest
```

Expected stdout, respectively:

```text
syntax-valid
source-valid
[0,3]
```

See [case.json](case.json), [SPEC §9](../../../SPEC.md#GNT-9.4),
[source limits](../../../SPEC.md#GNT-9.5), and
[loop grammar](../../../SPEC.md#GNT-13.8).
