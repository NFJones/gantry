# Checked integer overflow

Failure phase: **runtime evaluation**; parsing and analysis succeed.
Verified error code: `integer-overflow`.
Both operands are valid Int values, but their sum exceeds `9007199254740991`.

Correction: keep the computed result in range, for example add zero here;
see [successful boundary arithmetic](../../basics/checked-arithmetic/main.gnt).

Validate this expected failure with the [shared runner](../README.md).
