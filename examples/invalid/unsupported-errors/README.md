# Unsupported errors clause

Failure phase: **parsing**. Verified diagnostic: `unexpected-token`.
The Rust-like `errors { String }` signature clause is not admitted syntax.
The observed code is a parser rejection, not a guessed typed-error diagnostic.

Correction: return an explicit `Result<T, E>` and use admitted error propagation
or matching; see [domain errors](../../errors/domain-error-conversion/main.gnt)
and [Result values](../../types/results/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
