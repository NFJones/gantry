# Duplicate declaration

Failure phase: **symbol analysis**. Verified diagnostic: `duplicate-item`.
Two structs define the same `Item` name in the same module.

Correction: keep one declaration, rename the second, or place distinct definitions
in separate modules; see [nested modules](../../modules/inline_nested/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
