# None without an option type

Failure phase: **type/body analysis**. Verified diagnostic: `ambiguous-constructor-type`.
Discarding bare `None` supplies no context from which to infer its option member type.

Correction: bind it with an explicit type, for example
`let absent: Option<String> = None;`, following
[typed options](../../types/options/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
