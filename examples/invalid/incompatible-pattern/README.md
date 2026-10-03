# Pattern incompatible with the scrutinee

Failure phase: **type/body analysis**. Verified diagnostic: `incompatible-pattern`.
`Some(item)` is an Option pattern, but the scrutinee is Int.
The observed diagnostic set also contains `nonexhaustive-match`; the runner
requires the named incompatibility, not an exclusive diagnostic set.

Correction: match an `Option<Int>` or use a pattern compatible with Int; see
[typed pattern matching](../../control-flow/if_let_match/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
