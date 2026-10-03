# If/else chains and early returns

[main.gnt](main.gnt) calls one workflow with inputs selecting every branch
of an `if` / `else if` / `else` chain. Each branch returns explicitly:
conditional blocks are statements, not value expressions in Gantry v1.
No source follows an unconditional return in the same block.

The negative input is written as `0 - 2`: the current CLI failed execution
with `runtime-failure[internal-invariant-failure]` for the otherwise equivalent
`classify(-2)` call. This package avoids that unary-negative argument shape;
it does not change or test a fix to the implementation.

From the repository root, build once and reuse the binary:

```sh
cargo build -p gantry-cli
```

Commands (exit 0, empty stderr):

```sh
target/debug/gantry check examples/control-flow/early_returns
target/debug/gantry analyze examples/control-flow/early_returns
target/debug/gantry run examples/control-flow/early_returns
```

Expected stdout, respectively:

```text
syntax-valid
source-valid
["negative","zero","small","large"]
```

See [case.json](case.json), [SPEC §9](../../../SPEC.md#GNT-9.11),
[return grammar](../../../SPEC.md#GNT-13.5), and
[authoring conditional chains](../../../SPEC.md#146-reusable-model-judgments-and-conditional-chains).
This CLI example uses deterministic `Bool` conditions rather than `decide`.
