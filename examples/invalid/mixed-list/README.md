# Heterogeneous list members

Failure phase: **type/body analysis**. Verified diagnostic: `aggregate-member-type`.
The String member `"two"` cannot inhabit the declared `List<Int>`.

Correction: use `[1, 2]`, or use a tuple for deliberately heterogeneous values;
see [lists and tuples](../../types/lists-tuples-aggregates/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
