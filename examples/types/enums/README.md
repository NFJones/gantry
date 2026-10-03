# Enums

A unit variant has no payload; a payload variant carries exactly one value.
Use a struct when several named payload fields are needed, and use a pattern
to access the payload. See [closed tagged enums](../../../SPEC.md#GNT-5.7)
and [patterns](../../../SPEC.md#GNT-5.18).

From the repository root:

```sh
just run check examples/types/enums
just run analyze examples/types/enums
just run run examples/types/enums
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
[{"variant":"Idle"},{"value":{"count":2,"name":"jobs"},"variant":"Ready"},"idle","jobs: 2"]
```
