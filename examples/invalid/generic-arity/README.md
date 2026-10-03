# Too many generic type arguments

Failure phase: **generic/type analysis**. Verified diagnostic: `type-argument-arity`.
`Envelope<T>` takes one type argument, not two.
The observed diagnostic set also contains `sealed-type-boundary` for the invalid
entry annotation; the expected code targets the arity error.

Correction: use `Envelope<Int>`, following
[single-parameter generic declarations](../../generics/type-inference/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
