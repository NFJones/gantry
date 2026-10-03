# Missing binding annotation

Failure phase: **parsing**. Verified diagnostic: `unexpected-token`.
The local declaration omits the required `: Int`; it never reaches type analysis.

Correction: write `let value: Int = 1;`, following
[explicit bindings](../../basics/bindings-assignment/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
