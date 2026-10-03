# Results

Construct, return, and match declared expected outcomes. Err is ordinary successful program
data, not a runtime failure; arithmetic failures do not automatically become Err.
See [Result](../../../SPEC.md#GNT-5.8) and [patterns](../../../SPEC.md#GNT-5.18).

Implementation limitation: a helper with `if value >= 0 { return Ok(value); }`
and tail `Err("negative")` passed analysis but failed at runtime with
`internal-invariant-failure`. This example constructs both outcomes directly.

From the repository root:

```sh
just run check examples/types/results
just run analyze examples/types/results
just run run examples/types/results
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
[{"value":7,"variant":"Ok"},{"value":"negative","variant":"Err"},"accepted: 7","rejected: negative"]
```
