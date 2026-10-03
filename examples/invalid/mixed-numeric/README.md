# Mixed numeric operands

Failure phase: **type/body analysis**. Verified diagnostic: `invalid-primitive`.
`1 + 2.0` combines Int and Float without an implicit numeric promotion.

Correction: use operands of the same type, for example `1 + 2`, or an explicit
conversion; see [checked arithmetic](../../basics/checked-arithmetic/main.gnt)
and [conversions](../../basics/conversions/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
