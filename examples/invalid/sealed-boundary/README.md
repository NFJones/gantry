# Sealed type at the package entry boundary

Failure phase: **boundary/type analysis**. Verified diagnostic: `sealed-type-boundary`.
The entry parameter attempts to accept Decision as ordinary caller-provided data.

Correction: use an ordinary input type such as Bool at the entry boundary;
see [ordinary structs and boundaries](../../types/structs-defaults/main.gnt).
A Decision is not interchangeable with a caller-constructed Bool wrapper.

Validate this expected rejection with the [shared runner](../README.md).
