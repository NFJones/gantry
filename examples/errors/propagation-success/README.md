# Successful typed propagation with trailing steps

The `?` operand is a workflow call. Success continues through a field read and
arithmetic chain. The explicit, total `ReadError` to `WorkflowError` conversion
is required even though this run takes only the `Ok` path.

Spec: [typed domain errors and explicit `ErrorConversion`](../../../SPEC.md#GNT-38.1-typed-error-propagation)
and [distinct failure channels](../../../SPEC.md#GNT-38.0-error-and-divergence-scope).

From the repository root, build once if not already built:

```sh
cargo build -p gantry-cli --bin gantry
```

Run:

```sh
target/debug/gantry run examples/errors/propagation-success
```

Exact stdout (followed by a newline), exit status 0:

```json
42
```
