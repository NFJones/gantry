# Expected runtime failure corpus

These 10 packages parse and analyze successfully, then intentionally fail during
execution. Each contains `main.gnt`, a phase-specific `README.md` with the observed
wire code and valid correction link, and `case.json` with class `runtime-failure`
and `expected_error`. No model, network, or external operation is needed.

The shared runner in
[`support/mod.rs`](../../crates/gantry-conformance/examples/support/mod.rs)
requires execution acceptance, a terminal foreground failure with the exact wire
code, and orderly shutdown. A start rejection or wall-clock timeout does not
count as the expected failure. Codes were confirmed by execution through this
runner. Assertions and explicit panic both report `source-panic`.

From the repository root, validate all packages or one package:

```sh
timeout 180 cargo run --offline -p gantry-conformance --example corpus -- --all examples/runtime-failures
timeout 180 cargo run --offline -p gantry-conformance --example corpus -- examples/runtime-failures/loop-limit
```

Each scenario has a 30-second wall-clock deadline, two Tokio worker threads, and
a one-second shutdown bound. The unchanged runner uses finite frontend and value
limits, 1 MiB entry/hook byte bounds, 1,000,000 deterministic transitions,
100,000 loop iterations per task, 100,000 operations, and a deterministic-transition
yield quantum of 1,000. Async capacity bounds are 64 per configured category. The loop example
uses a smaller explicit source limit of three entries, so it tests
`loop-limit-exhausted`, not a host timeout or global iteration budget.

Coverage and exact codes:

| Package | Expected error |
| --- | --- |
| [integer-overflow](integer-overflow/) | `integer-overflow` |
| [integer-division-zero](integer-division-zero/) | `integer-division-by-zero` |
| [integer-remainder-zero](integer-remainder-zero/) | `integer-remainder-by-zero` |
| [float-division-zero](float-division-zero/) | `float-division-by-zero` |
| [list-index-bounds](list-index-bounds/) | `list-index-out-of-bounds` |
| [empty-split](empty-split/) | `string-empty-separator` |
| [empty-replace](empty-replace/) | `string-empty-pattern` |
| [assertion](assertion/) | `source-panic` |
| [panic](panic/) | `source-panic` |
| [loop-limit](loop-limit/) | `loop-limit-exhausted` |
