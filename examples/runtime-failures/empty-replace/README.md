# Empty replacement search pattern

Failure phase: **runtime evaluation**; parsing and analysis succeed.
Verified error code: `string-empty-pattern`.
The search pattern is empty; the replacement text itself is not the error.

Correction: choose a nonempty search pattern, such as `"v"`; see
[valid string replacements](../../strings/transforms/main.gnt).

Validate this expected failure with the [shared runner](../README.md).
