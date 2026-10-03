# Regular generic recursion

`count<T>` calls itself with the same ordered type substitution while an integer
counter decreases to zero. The entry argument infers `String`; each recursive
call explicitly retains `T`. This is regular workflow recursion, not polymorphic
recursion. No recursive runtime value is constructed.

Spec: [generic workflows](../../../SPEC.md#GNT-6.12-static-traits),
[callable instantiation closure](../../../SPEC.md#GNT-3-F-INSTANTIATION), and
[source organization and recursion](../../../SPEC.md#GNT-4.5).

From the repository root, build once if not already built:

```sh
cargo build -p gantry-cli --bin gantry
```

Run:

```sh
target/debug/gantry run examples/generics/regular-recursion
```

Exact stdout (followed by a newline), exit status 0:

```json
3
```
