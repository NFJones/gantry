# Empty split separator

Failure phase: **runtime evaluation**; parsing and analysis succeed.
Verified error code: `string-empty-separator`.
Splitting with an empty separator is refused. This is distinct from splitting
an empty source string with a nonempty separator, which is valid.

Correction: choose a nonempty separator; see
[valid split and join cases](../../strings/split-join/main.gnt).

Validate this expected failure with the [shared runner](../README.md).
