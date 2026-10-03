# Source after unconditional return

Failure phase: **type/body analysis**. Verified diagnostic: `unreachable-source`.
The binding after `return;` cannot execute.

Correction: move needed work before the return or remove dead statements;
see [reachable early-return paths](../../control-flow/early_returns/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
