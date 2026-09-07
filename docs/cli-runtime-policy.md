# CLI runtime policy

`gantry run` owns a Tokio multithread runtime for the duration of one command.
The CLI constructs that runtime explicitly, passes its handle through
`TokioExecutor`, starts the execution through the public `Interpreter` facade,
waits for terminal observation, and performs interpreter shutdown before the
runtime is dropped.

Use the default worker policy with:

```sh
gantry run [PACKAGE_ROOT]
```

When `--workers` is omitted, Gantry does not calculate a worker count. It leaves
the setting unset so Tokio uses its CPU-derived default.

Use an explicit worker count with:

```sh
gantry run --workers POSITIVE_INTEGER [PACKAGE_ROOT]
```

Values such as `1`, `2`, and `4` are accepted. Zero, negative values, malformed
values, and a missing value are usage errors. The option is operational policy:
it changes physical scheduling capacity, not Gantry language semantics,
execution or task identities, durable compatibility, or portable outcomes.

Library embedders may continue to use `TokioExecutor::new` with either a
current-thread or multithread Tokio handle. The CLI-specific multithread default
does not change that executor-neutral embedding contract and does not introduce
a hidden runtime inside `Interpreter`.
