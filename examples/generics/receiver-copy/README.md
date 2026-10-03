# Receiver copies and contextual `Self`

A generic receiver exposes an immutable `self` reader and a `mut self` update
returning `Self`. Updating the callee copy leaves both earlier values unchanged;
an explicit caller assignment retains the next update.

Spec: [receivers](../../../SPEC.md#GNT-6.2),
[compound assignment](../../../SPEC.md#GNT-6.3),
[deep-copy calls](../../../SPEC.md#GNT-6.4), and
[contextual `Self`](../../../SPEC.md#GNT-6.12-static-traits).

From the repository root, build the default CLI once for this collection:

```sh
cargo build -p gantry-cli --bin gantry
```

Run:

```sh
target/debug/gantry run examples/generics/receiver-copy
```

Exact stdout (followed by a newline), exit status 0:

```json
[2,7,10]
```
