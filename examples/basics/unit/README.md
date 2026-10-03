# Unit

Bind and discard completed work, then return `()`. `return;` also denotes
Unit; `None` is an Option constructor, not Unit. Unit encodes as JSON null.
See [Unit](../../../SPEC.md#GNT-5.2) and [discard](../../../SPEC.md#GNT-5.13).

From the repository root:

```sh
just run check examples/basics/unit
just run analyze examples/basics/unit
just run run examples/basics/unit
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
null
```
