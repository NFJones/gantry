# Successful checked assertions

Exactly `Bool` comparisons guard workflow inputs, the computed total, and the
entry result. Every assertion succeeds and execution continues. A failed
assertion would settle as a failure outcome, not `Err` or an implicit domain
conversion; this example deliberately exercises only the successful path.

Spec: [checked assertions and failure semantics](../../../SPEC.md#GNT-38.2-assertions-and-panic)
and [failure-channel separation](../../../SPEC.md#GNT-38.0-error-and-divergence-scope).

From the repository root, build once if not already built:

```sh
cargo build -p gantry-cli --bin gantry
```

Run:

```sh
target/debug/gantry run examples/errors/checked-assertions
```

Exact stdout (followed by a newline), exit status 0:

```json
42
```
