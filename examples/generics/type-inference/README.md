# Generic types and local inference

An argument closes `wrap<T>`, an annotated result closes `empty<T>`, and the
expected enum type supplies both constructor arguments. The typed scrutinee
then closes the unqualified enum patterns. No trait implementation guesses a type.

Spec: [parametric types and inference](../../../SPEC.md#GNT-5.20-parametric-types)
and [structural patterns](../../../SPEC.md#GNT-5.18).

From the repository root, build once if not already built:

```sh
cargo build -p gantry-cli --bin gantry
```

Run:

```sh
target/debug/gantry run examples/generics/type-inference
```

Exact stdout (followed by a newline), exit status 0:

```json
["ready",true]
```
