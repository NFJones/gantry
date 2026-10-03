# Missing Option match arm

Failure phase: **type/body analysis**. Verified diagnostic: `nonexhaustive-match`.
The match handles `Some` but not `None`.

Correction: add `None => 0`, following
[exhaustive option matching](../../types/options/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
