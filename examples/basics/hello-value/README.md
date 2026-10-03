# Hello value

Return a deterministic String without an agent or integration hook.
See [source organization](../../../SPEC.md#4-source-organization) and
[values](../../../SPEC.md#GNT-5.1).

From the repository root:

```sh
just run check examples/basics/hello-value
just run analyze examples/basics/hello-value
just run run examples/basics/hello-value
```

CLI stdout (excluding Cargo build messages): check prints `syntax-valid`,
analyze prints `source-valid`, and run prints:

```json
"Hello, Gantry!"
```
