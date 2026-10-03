# Type-growing recursion

Failure phase: **generic/type analysis**. Verified diagnostic: `polymorphic-recursion`.
Each recursive call changes T to `List<T>`, requiring an unbounded sequence
of distinct workflow instantiations.

Correction: retain the same concrete type arguments on recursive calls and add
a terminating value-level condition; see
[regular generic recursion](../../generics/regular-recursion/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
