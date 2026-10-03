# Failed checked assertion

Failure phase: **runtime evaluation**; parsing and analysis succeed.
Verified error code: `source-panic`.
`assert(false)` fails the enclosing callable. The runner confirms `source-panic`,
not an invented assertion-specific wire code.

Correction: assert a condition established by the program, or handle a domain
failure explicitly; see [successful assertions](../../errors/checked-assertions/main.gnt).

Validate this expected failure with the [shared runner](../README.md).
