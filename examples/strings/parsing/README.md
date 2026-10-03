# Scalar parsing

Parsers return Some on valid input and None on invalid input, never a task
failure. They do not trim. Int rejects leading zeroes, `-0`, `+`, and out-of-range
values; Float accepts JSON number syntax and normalizes negative zero.
See [String parsers](../../../SPEC.md#GNT-5.16) and [numeric domain](../../../SPEC.md#GNT-5.1).

From the repository root:

```sh
just run check examples/strings/parsing
just run analyze examples/strings/parsing
just run run examples/strings/parsing
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
{"booleans":[true,false,null,null],"floats":[1,125,0,null,null,null],"integers":[0,-42,null,null,null,null],"trimmed":42}
```
