# Unconstrained generic inference

Failure phase: **generic/type analysis**. Verified diagnostic: `incomplete-type-inference`.
The zero-argument call supplies no evidence for the unused type parameter T.

Correction: call `missing_type::<String>()`, or expose T in an argument/result
that provides inference evidence; see
[generic inference and explicit arguments](../../generics/type-inference/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
