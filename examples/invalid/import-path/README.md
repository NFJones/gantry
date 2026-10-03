# Unresolved import path

Failure phase: **symbol analysis**. Verified diagnostic: `unresolved-import`.
`crate::missing::Item` names a module and item that do not exist in this package.

Correction: declare the module and import its actual item path, following
[resolved crate/self/super imports](../../modules/path_imports/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
