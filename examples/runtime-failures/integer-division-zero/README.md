# Integer division by zero

Failure phase: **runtime evaluation**; parsing and analysis succeed.
Verified error code: `integer-division-by-zero`.
The divisor is zero; checked evaluation fails rather than producing a value.

Correction: use a nonzero divisor, such as `1 / 1`; see
[checked arithmetic](../../basics/checked-arithmetic/main.gnt).

Validate this expected failure with the [shared runner](../README.md).
