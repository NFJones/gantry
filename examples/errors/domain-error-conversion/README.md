# Explicit domain-error conversion

`?` reads a struct-member place containing `Result<Int, ValidationError>`.
The `Ok` path continues to the next statement. The `Err` path returns early
through one explicit `ErrorConversion`, preserving the code and adding domain
context. `main` handles both outcomes as values, so this is a successful CLI
run, not an operational failure converted into a domain error.

Spec: [domain-error propagation and conversion](../../../SPEC.md#GNT-38.1-typed-error-propagation)
and [failure-channel separation](../../../SPEC.md#GNT-38.0-error-and-divergence-scope).

From the repository root, build once if not already built:

```sh
cargo build -p gantry-cli --bin gantry
```

Run:

```sh
target/debug/gantry run examples/errors/domain-error-conversion
```

Exact stdout (followed by a newline), exit status 0:

```json
[42,{"code":7,"stage":"validation"}]
```
