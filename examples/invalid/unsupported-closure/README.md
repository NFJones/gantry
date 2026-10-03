# Recognized but unadmitted closure expression

Failure phase: **type/body analysis**, not parsing.
Verified diagnostic: `callable-expression-unadmitted`.
The anonymous `fn` expression is parsed, but this revision does not admit it
as a source callable value.

Correction: declare a named workflow and bind its declared Fn alias, following
[declared function aliases](../../generics/declared-fn-alias/main.gnt).

Validate this expected rejection with the [shared runner](../README.md).
