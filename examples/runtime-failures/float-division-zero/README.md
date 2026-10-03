# Float division by zero

Failure phase: **runtime evaluation**; parsing and analysis succeed.
Verified error code: `float-division-by-zero`.
The checked Float operation does not expose an infinity result.

Correction: use a nonzero Float divisor, such as `1.0 / 1.0`; see
[same-type Float arithmetic](../../basics/checked-arithmetic/main.gnt).

Validate this expected failure with the [shared runner](../README.md).
