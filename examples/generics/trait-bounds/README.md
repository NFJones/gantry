# Sealed capability bounds

The declared type and both reusable workflows require `Equatable` explicitly.
The wrapper carries the callee's bound, and closed struct equality checks stored
fields structurally. Equal and unequal inputs exercise both results.

Spec: [sealed capabilities, structural proofs, and bound forwarding](../../../SPEC.md#GNT-5.20-parametric-types)
and [generic workflow predicates](../../../SPEC.md#GNT-6.12-static-traits).

From the repository root, build once if not already built:

```sh
cargo build -p gantry-cli --bin gantry
```

Run:

```sh
target/debug/gantry run examples/generics/trait-bounds
```

Exact stdout (followed by a newline), exit status 0:

```json
[true,false]
```
