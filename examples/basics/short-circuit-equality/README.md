# Short-circuit logic and equality

The skipped right operands would divide by zero if evaluated. Deep struct
equality compares nested lists and preserves list order. Numeric
ordering and negation produce ordinary Bool values, without truthiness.
See [Boolean algebra, ordering, and exact equality](../../../SPEC.md#GNT-5.15).

Implementation limitation: validation found that reversing constructor field
order made otherwise equal structs compare unequal. This example uses matching
field order; the spec requires equality over normalized values.

From the repository root:

```sh
just run check examples/basics/short-circuit-equality
just run analyze examples/basics/short-circuit-equality
just run run examples/basics/short-circuit-equality
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
[false,true,true,true,true]
```
