# Integer remainder with a zero divisor

Failure phase: **runtime evaluation**; parsing and analysis succeed.
Verified error code: `integer-remainder-by-zero`.
This exercises `%`, separately from the division failure code.

Correction: use a nonzero divisor, such as `1 % 1`; see
[division and remainder](../../basics/checked-arithmetic/main.gnt).

Validate this expected failure with the [shared runner](../README.md).
