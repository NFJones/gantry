# Bounded loop, break, and continue

[main.gnt](main.gnt) counts four body entries. Odd entries `continue`,
even entries contribute to the sum, and the fourth entry `break`s normally.
Both transfers target the nearest enclosing loop. `limit = 4` counts all
body entries, including those that continue; it does not stop the loop normally.

If the final break were removed, attempting a fifth entry would fail with
`runtime-failure[loop-limit-exhausted]` on stderr, not return a partial result.
That failure variant is documentation only, not this successful CLI case.
Zero is not a valid source limit. Omitted limits or `limit = unbounded` remove
only the source ceiling, not finite budgets selected by an embedding.

From the repository root, build once and reuse the binary:

```sh
cargo build -p gantry-cli
```

Commands (exit 0, empty stderr):

```sh
target/debug/gantry check examples/control-flow/loop_limit
target/debug/gantry analyze examples/control-flow/loop_limit
target/debug/gantry run examples/control-flow/loop_limit
```

Expected stdout, respectively:

```text
syntax-valid
source-valid
{"entries":4,"total":6}
```

See [case.json](case.json), [SPEC source limits](../../../SPEC.md#GNT-9.5),
[execution budgets](../../../SPEC.md#GNT-9.7), and
[loop grammar](../../../SPEC.md#GNT-13.8).
