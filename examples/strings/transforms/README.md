# String transforms

Trim either end, map case, replace nonoverlapping matches, and concatenate.
The original remains unchanged. Replacement text is not rescanned (`a` to `aa`
terminates), and overlapping source matches are not reused. Empty replacement
patterns are invalid and intentionally not executed here.
See [String transforms](../../../SPEC.md#GNT-5.16) and [limits](../../../SPEC.md#GNT-5.17).

From the repository root:

```sh
just run check examples/strings/transforms
just run analyze examples/strings/transforms
just run run examples/strings/transforms
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
["  Gantry  ","Gantry  ","  Gantry","gantry","GANTRY","aaaaaa","result=Xba"]
```
