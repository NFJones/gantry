# Exhausted source loop limit

Failure phase: **runtime evaluation**; parsing and analysis succeed.
Verified error code: `loop-limit-exhausted`.
The loop permits three body entries and has no break. Attempting another entry
exhausts the source limit. This is not the runner's wall-clock timeout or its
task-wide loop-iteration budget.

Correction: terminate within the declared limit, following
[successful bounded loops](../../control-flow/loop_limit/main.gnt).

Validate this expected failure with the [shared runner](../README.md).
