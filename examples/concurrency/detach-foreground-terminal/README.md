# Detach: foreground versus terminal

Detach a value-producing child, intentionally discarding its eventual `9`.
The root returns `42` whether the child succeeds or divides by zero. A detached
failure cannot change foreground success; it belongs to terminal execution.
There are no hooks or assumptions about whether the child finishes first.

Spec: [transfer of ownership](../../../SPEC.md#GNT-10.8),
[detached failure and terminal precedence](../../../SPEC.md#GNT-10.9).
See [Attached and detached ownership](../../../docs/parallel-execution.md#attached-and-detached-ownership).

From the repository root (build once and reuse):

```sh
timeout 120 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/concurrency/detach-foreground-terminal
```

Both input scenarios expect foreground JSON `42`; two passing scenarios, zero
dispatches. The shared runner independently checks terminal categories:
`success` is the default for the `false` scenario, and the `true` scenario
explicitly requires `"expected_terminal":"detached-task-failure"`. Omitting
that expectation would reject the intentional detached failure even though
foreground JSON still matches. Terminal expectations use the closed public
runtime-error, terminal-only, and `cancellation` wire categories. Failure cases
default to their foreground failure's portable terminal category, which can
differ from the narrower `expected_error` code. The same terminal check applies
to durable execution and resume. These checks do not force foreground completion
to occur before child settlement.
This nondurable package makes no process-survival or recovery claim.
