# Transitive effect in a pure workflow

Failure phase: **effect analysis**. Verified diagnostic: `impure-workflow`.
Although `wrapper` contains no direct action syntax, its call to `leaf` carries
the action effect into a workflow declared pure. Invalid packages are not executed;
no host hook is needed.

Correction: remove `pure` from the effectful wrapper or remove the effect;
see [workflow composition](../../control-flow/workflow_composition/main.gnt)
for separating pure computations from workflow calls.

Validate this expected rejection with the [shared runner](../README.md).
