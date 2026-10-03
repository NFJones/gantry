# Task handle left unconsumed

Failure phase: **task-ownership/effect analysis**. Verified diagnostic: `unconsumed-task-handle`.
The workflow exits without joining or detaching the spawned child.

Correction: add `discard join(child);` or `detach(child);`, following
[valid named joins](../../concurrency/spawn-named-join/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
