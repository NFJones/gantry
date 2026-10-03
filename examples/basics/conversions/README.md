# Explicit conversions

Int-to-Float is exact. Float-to-Int returns an Option and never rounds:
fractional and out-of-Int-range values return None. Primitive-to-String uses
canonical spelling. See [conversions](../../../SPEC.md#GNT-5.15) and
[no implicit coercions](../../../SPEC.md#GNT-5.20).

From the repository root:

```sh
just run check examples/basics/conversions
just run analyze examples/basics/conversions
just run run examples/basics/conversions
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
[42,42,null,null,"true","42","3.5"]
```
