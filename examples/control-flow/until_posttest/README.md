# Until tests after the body

[main.gnt](main.gnt) demonstrates `until { ... } when CONDITION;`.
The first loop's `continue` goes to the post-test, not straight to the next
body. It finishes on its third entry. The second loop runs once even though
`once >= 10` would have been true before entry: there is no pre-test.

From the repository root, build once and reuse the binary:

```sh
cargo build -p gantry-cli
```

Commands (exit 0, empty stderr):

```sh
target/debug/gantry check examples/control-flow/until_posttest
target/debug/gantry analyze examples/control-flow/until_posttest
target/debug/gantry run examples/control-flow/until_posttest
```

Expected stdout, respectively:

```text
syntax-valid
source-valid
{"count":3,"once":11,"recorded":1}
```

See [case.json](case.json), [SPEC §9](../../../SPEC.md#GNT-9.4),
[loop grammar](../../../SPEC.md#GNT-13.8), and
[authoring loops](../../../SPEC.md#147-finite-general-pre-test-and-post-test-loops).
