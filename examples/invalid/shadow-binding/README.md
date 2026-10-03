# Shadowed binding

Failure phase: **symbol analysis**. Verified diagnostic: `shadowed-name`.
The `if` body declares another `value` while the outer binding remains visible.
An `if` block is intentional: a standalone Rust-like block would fail parsing first.

Correction: choose a distinct inner name or assign to a mutable outer binding;
see [bindings and assignment](../../basics/bindings-assignment/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
