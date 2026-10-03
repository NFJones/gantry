# Missing result on a reachable path

Failure phase: **type/body analysis**. Verified diagnostic: `missing-result`.
When `flag` is false, the Int-returning workflow completes without an Int result.

Correction: add a final `0` or an else branch returning an Int; see
[early returns with a fallback](../../control-flow/early_returns/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
