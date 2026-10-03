# Task handle consumed twice

Failure phase: **task-ownership/effect analysis**. Verified diagnostic: `consumed-task-handle`.
Joining child consumes its handle; the later detach attempts another consumption.

Correction: join or detach each handle exactly once, not both; see
[valid named joins](../../concurrency/spawn-named-join/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
