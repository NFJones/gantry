# Never in an ordinary workflow signature

Failure phase: **type analysis**. Verified diagnostic: `never-signature-refused`.
The non-entry workflow parameter uses Never in a refused signature position.

Correction: remove the uninhabited parameter or use an admitted input type;
see [ordinary workflow signatures](../../control-flow/workflow_composition/main.gnt).
This case does not claim all divergent expressions are unsupported.

Validate this expected rejection with the [shared runner](../README.md).
