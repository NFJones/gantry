# Refused Option member type

Failure phase: **type analysis**. Verified diagnostic: `invalid-option-type`.
This revision refuses `Option<Unit>` as a stored field type.

Correction: use an admitted member type such as `Option<String>`; see
[valid options](../../types/options/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
