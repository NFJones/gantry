# Non-transferable capture in a detached task

Failure phase: **type/body analysis**. Verified diagnostic: `task-capture-ineligible`.
The spawned block references an affine Ticket from its parent. Task capture
requires an independent-copy transfer contract, which this value lacks.
The rejection occurs at capture analysis, before detach can execute; it is not
a detach-specific runtime failure. A declared Fn alias was tested and is valid,
so it is deliberately not used as the negative capture here.

Correction: capture an eligible independent scalar or ordinary copyable struct,
or construct the affine value inside the child; see
[valid isolated captures](../../concurrency/copied-captures/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
