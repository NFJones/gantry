# Unsupported range syntax

Failure phase: **parsing**. Verified diagnostic: `unexpected-token`.
The Rust-like `0..3` range expression is not admitted by this parser.

Correction: iterate an explicit `List<Int>`, such as `[0, 1, 2]`, following
[snapshot iteration](../../control-flow/for_snapshot/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
