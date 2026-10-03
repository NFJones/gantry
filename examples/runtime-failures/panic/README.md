# Explicit source panic

Failure phase: **runtime evaluation**; parsing and analysis succeed.
Verified error code: `source-panic`.
The intentional panic fails the enclosing callable; no host failure is scripted.

Correction: return a successful result or represent a recoverable failure as
Result, following [domain error handling](../../errors/domain-error-conversion/main.gnt).

Validate this expected failure with the [shared runner](../README.md).
