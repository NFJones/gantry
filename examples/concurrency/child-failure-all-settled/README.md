# Child failure and all-settled joins

One child fails deterministically with integer division by zero; the other
completes an offline read-only action. Both named (`false`) and lexical (`true`)
joins must wait for all selected children, then fail the parent with the stable
`task-join-failure` code. Only the successful sibling dispatches a hook, so the
single response cannot be assigned to the wrong child by FIFO scheduling.

Spec: [named all-settled join](../../../SPEC.md#GNT-10.5),
[lexical all-settled join](../../../SPEC.md#GNT-10.6),
[failure does not cancel siblings](../../../SPEC.md#GNT-10.7).
Current contract evidence: `public_joinall_waits_for_all_and_reports_source_order`
in `crates/gantry-conformance/tests/concurrent_handle_ownership.rs`.

From the repository root (build once, reuse for all packages):

```sh
timeout 120 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/concurrency/child-failure-all-settled
```

Both scenarios expect runtime error `task-join-failure`, not successful JSON.
Each consumes exactly one action response. The runner must support
`expected_error` on `class: concurrent` (the parent owns that shared-runner
extension). These finite immediate tasks test aggregate failure plus sibling
completion, but do not force a failure-before-sibling-dispatch schedule or
inspect ordered aggregate details. Cancellation-token signaling, bounded
draining, and executor abort require a controllable blocking host and are not
claimed by this package.
