# Reusable generic workflows

`preserve` is instantiated explicitly for `Int` and inferred for `String`.
`replace` infers `T` from its arguments and mutates only its parameter copy.

Spec: [parametric types and exact inference](../../../SPEC.md#GNT-5.20-parametric-types),
[workflow copy semantics](../../../SPEC.md#GNT-6.4), and
[generic workflows](../../../SPEC.md#GNT-6.12-static-traits).

From the repository root, build once if not already built:

```sh
cargo build -p gantry-cli --bin gantry
```

Run:

```sh
target/debug/gantry run examples/generics/generic-workflows
```

Exact stdout (followed by a newline), exit status 0:

```json
[4,9,"reused"]
```
