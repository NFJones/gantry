# Checked arithmetic

Exercise exact Int boundary arithmetic, unary negation, division truncating
toward zero, dividend-signed remainder, and same-type Float arithmetic.
See [numeric domain](../../../SPEC.md#GNT-5.1) and
[checked primitives](../../../SPEC.md#GNT-5.15). Overflow and division by zero
fail deterministically; this successful example stays in range and uses nonzero
divisors. The Float result is canonically rendered as `2`, not `2.0`.

Implementation limitation: validation found an `internal-invariant-failure`
with the combined expression `(1.5 + 2.5) * 2.0 / 4.0`. Named intermediate
bindings execute successfully and keep each checked operation explicit.

From the repository root:

```sh
just run check examples/basics/checked-arithmetic
just run analyze examples/basics/checked-arithmetic
just run run examples/basics/checked-arithmetic
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
[9007199254740991,-3,-2,17,true,2]
```
