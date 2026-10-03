# List index outside the bounds

Failure phase: **runtime evaluation**; parsing and analysis succeed.
Verified error code: `list-index-out-of-bounds`.
The one-element list has only index zero; the well-typed index one is out of bounds.

Correction: use `values[0]`, or check the length before indexing; see
[successful list projections](../../types/lists-tuples-aggregates/main.gnt).

Validate this expected failure with the [shared runner](../README.md).
