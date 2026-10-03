# Nested struct update and logical copy

Update a nested field of a mutable local and of a mutable parameter.
Neither operation changes the original logical value. This is field assignment,
not unsupported Rust `..original` struct-update syntax.
See [struct construction](../../../SPEC.md#GNT-5.11) and
[deep nonaliasing copies](../../../SPEC.md#GNT-5.13).

From the repository root:

```sh
just run check examples/basics/nested-struct-copy
just run analyze examples/basics/nested-struct-copy
just run run examples/basics/nested-struct-copy
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints `[original, changed, revised]`:

```json
[{"counter":{"value":1},"name":"original"},{"counter":{"value":7},"name":"changed"},{"counter":{"value":17},"name":"changed"}]
```
