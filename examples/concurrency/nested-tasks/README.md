# Nested task ownership

The outer child owns and joins its inner child. The root joins only the handles
it created, forming a heterogeneous tuple in declaration order. The grandchild
copies both the outer capture and a child-local binding; its mutation does not
alter the root's later `seed = 100`. All values are distinct and hook-free.

Spec: [task ownership](../../../SPEC.md#GNT-10.2),
[captures](../../../SPEC.md#GNT-10.3),
[lexical joinall](../../../SPEC.md#GNT-10.6).
Current source evidence: `nested_task_bodies_preserve_captures_and_joinall_order`
in `crates/gantry-conformance/tests/executable_bridge.rs`.

From the repository root (build once, then reuse):

```sh
timeout 120 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/concurrency/nested-tasks
```

Expected foreground JSON: `{"parent":100,"outer":10,"sibling":"independent"}`.
One passing scenario, zero dispatches. Cross-task consumption of another
task's handle is deliberately not demonstrated because it is invalid.
