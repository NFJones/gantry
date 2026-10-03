# Non-integer list index

Failure phase: **type/body analysis**. Verified diagnostic: `projection-index-type`.
A String is used as a positional index into `List<Int>`.

Correction: use an in-bounds Int index such as `values[0]`, following
[list projections](../../types/lists-tuples-aggregates/main.gnt).
An Int index outside the bounds instead fails at runtime.

Validate this expected rejection with the [shared runner](../README.md).
