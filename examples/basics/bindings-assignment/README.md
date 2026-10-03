# Bindings and assignment

Immutable bindings retain their value; `mut` enables same-type assignment
and compound assignment. A mutable parameter changes only the callee's copy.
See [logical copies and mutability](../../../SPEC.md#GNT-5.13) and
[deterministic arithmetic](../../../SPEC.md#GNT-5.15).

From the repository root:

```sh
just run check examples/basics/bindings-assignment
just run analyze examples/basics/bindings-assignment
just run run examples/basics/bindings-assignment
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints `[original, current, changed]`:

```json
[3,14,19]
```
