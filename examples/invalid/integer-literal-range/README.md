# Integer literal outside the canonical domain

Failure phase: **type/body analysis**. Verified diagnostic: `integer-literal-out-of-range`.
`9007199254740992` exceeds the maximum Int value, `9007199254740991`.
This is a source rejection, not the runtime overflow of two valid operands.

Correction: choose an in-range value, following
[boundary arithmetic](../../basics/checked-arithmetic/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
