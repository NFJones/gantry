# Narrow declared `Fn` binding aliases

An explicitly annotated `Fn(Int) -> Int` binding names one declared workflow;
a second annotated binding aliases that same identity. Invocations are direct
calls, including in an arithmetic operand. This supported slice is not a
closure, dynamic callable, capture, generic callable argument, or std API.

Spec: [admitted binding annotations](../../../SPEC.md#GNT-37.0-callable-values-and-frame-admission),
[direct alias invocation](../../../SPEC.md#GNT-37.10-direct-call-and-receiver-compatibility),
and [callable non-claims](../../../SPEC.md#GNT-37.12-callable-non-claims).

From the repository root, build once if not already built:

```sh
cargo build -p gantry-cli --bin gantry
```

Run:

```sh
target/debug/gantry run examples/generics/declared-fn-alias
```

Exact stdout (followed by a newline), exit status 0:

```json
[42,3]
```
