# Unbroken stored-type cycle

Failure phase: **type analysis**. Verified diagnostic: `recursive-type-cycle`.
Left stores Right, and Right stores Left with no admitted recursive guard.
The observed code appears for both declarations.

Correction: use an admitted guarded recursive shape, following
[recursive structs](../../types/recursive-structs/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
