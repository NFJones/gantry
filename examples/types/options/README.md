# Options

Construct typed Some and None values and inspect them with exhaustive match
and `if let`, without an unwrap operation. At the JSON boundary Some is encoded
as its member and None as null. See [options](../../../SPEC.md#GNT-5.3),
[patterns](../../../SPEC.md#GNT-5.18), and [control flow](../../../SPEC.md#9-control-flow).

From the repository root:

```sh
just run check examples/types/options
just run analyze examples/types/options
just run run examples/types/options
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
["ready",null,"ready","missing",5,0]
```
