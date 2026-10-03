# Unsatisfied generic trait bound

Failure phase: **generic/type analysis**. Verified diagnostic: `missing-implementation`.
`render` requires `T: Label`, but `Missing` has no Label implementation.

Correction: implement Label for the argument type or call with a type that
satisfies the bound; see [trait bounds](../../generics/trait-bounds/main.gnt)
and [static trait implementations](../../generics/static-traits/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
