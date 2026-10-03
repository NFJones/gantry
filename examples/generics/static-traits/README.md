# Static trait reuse and trait `Self`

A `Label` bound supplies the generic workflow and implementation contracts.
`Repack` returns contextual `Self` for a generic receiver. Both postfix trait
lookup and explicit `Trait::method(receiver)` lower to concrete direct calls;
the original receiver remains available. There are no trait objects or vtables.

Spec: [static traits, predicates, qualified calls, and `Self`](../../../SPEC.md#GNT-6.12-static-traits)
and [receiver copies](../../../SPEC.md#GNT-6.4).

From the repository root, build once if not already built:

```sh
cargo build -p gantry-cli --bin gantry
```

Run:

```sh
target/debug/gantry run examples/generics/static-traits
```

Exact stdout (followed by a newline), exit status 0:

```json
["release","release"]
```
