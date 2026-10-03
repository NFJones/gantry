# Recursive and pure workflows

[main.gnt](main.gnt) uses direct recursion for factorial and mutual recursion
for parity, including a reference to a later declaration. All calls here use
nonnegative inputs and decrease toward a base case. Negative parity inputs
would not reach that base case; this is not an unrestricted numeric library.

Every function asserts `pure fn`. Analysis checks that its transitive effect
set is empty, including through recursive call cycles. `pure` does not mean
memoized, constant-evaluated, or exempt from runtime depth/resource policy.
There are no model operations or task/session effects in this package.

From the repository root, build once and reuse the binary:

```sh
cargo build -p gantry-cli
```

Commands (exit 0, empty stderr):

```sh
target/debug/gantry check examples/control-flow/recursive_pure
target/debug/gantry analyze examples/control-flow/recursive_pure
target/debug/gantry run examples/control-flow/recursive_pure
```

Expected stdout, respectively:

```text
syntax-valid
source-valid
{"base":1,"even":true,"factorial":120,"odd":true}
```

See [case.json](case.json), [SPEC recursion](../../../SPEC.md#GNT-4.10),
[checked purity](../../../SPEC.md#GNT-6.5), and
[workflow grammar](../../../SPEC.md#GNT-13.4).
