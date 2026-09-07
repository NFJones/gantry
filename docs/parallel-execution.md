# Parallel Execution

Gantry makes task creation, waiting, and background ownership visible in
source. Use `spawn` to overlap independent work, then consume every spawned
handle with a named `join`, lexical `joinall()`, or explicit `detach` on every
normal path. These forms are task control, not integration operations: they do
not invoke an agent or action hook by themselves.

The complete hook-free example is
[`examples/parallel-execution/main.gnt`](../examples/parallel-execution/main.gnt).
Analyze it from the repository root with:

```sh
just run -- analyze examples/parallel-execution
```

The package needs no agent mapping or external action implementation, so it is
suitable for syntax checking and semantic analysis without integration setup.
Running concurrent source additionally requires a concurrent-evaluator host.

## Spawn and captures

`spawn name -> T { ... }` creates an attached child returning `T`.
`spawn name { ... }` creates an attached `Unit` child. The name is a linear,
lexically scoped task handle owned by the task that executed the spawn; it is
not a source value and cannot be passed to another task.

Spawned blocks capture referenced outer values by deep copy when the spawn is
executed. The copy is an isolated snapshot: later parent mutation cannot alter
the child copy, and child mutation cannot alter the parent. Capture mutability
is preserved, so a captured `mut` binding may be changed inside the child while
an immutable capture may not. In the example, `incremented` captures `seed`
while it is `7`, increments only its child-local copy to `8`, and is unaffected
when the parent later assigns `20`.

Each spawned child also starts with a distinct forked child of the spawning
task's active logical session. An unmodified or `session(inline)` model
operation in that task uses the child session; siblings do not share one
mutable conversation. An explicit session directive inside the block may
override the inherited session.

## Waiting with `join` and `joinall()`

A named join selects handles explicitly:

```rust
let child_value: Int = join(incremented);
```

It consumes the handle and waits for every selected child to settle. One
non-`Unit` task yields its declared type. Multiple homogeneous value tasks
yield `List<T>` in argument order; heterogeneous value tasks yield a positional
`Tuple<...>`. A join containing only `Unit` tasks yields `Unit`. Value and
`Unit` tasks cannot be mixed in one join. Joins are all-settled: one child
failure does not stop waiting for the other selected children, and failures
are reported in source selection order rather than completion order.

`joinall()` is lexical rather than global. At its program point it selects the
still-attached, definitely available handles from direct earlier spawns in the
current block. It excludes later spawns, nested-block spawns, handles owned by
other tasks, and handles already joined or detached. Results follow declaration
order. In the example it selects the homogeneous `label` and `marker` tasks,
producing `List<String>`. Heterogeneous value tasks instead produce a positional
`Tuple<...>`. An empty `joinall()` is valid and yields `Unit`, but still
contributes the `join` effect.

## Attached and detached ownership

An attached task remains structured work owned through its handle. Every
normal path leaving the handle's scope must consume it with `join`,
`joinall()`, or `detach`; Gantry never detaches a task implicitly. Attached
descendants remain part of cancellation and cleanup even after a join has
consumed their source handles but before they settle.

`detach(task);` consumes an attached handle without waiting and transfers it
to Gantry's execution-scoped background ownership. The detached task may
outlive its lexical parent and root `main`. In a nondurable concurrent
evaluator this ownership lasts only for the interpreter lifetime. With the
durable-runtime profile, unfinished detached work remains in the execution
journal and can be reconstructed by a later execution owner.

This creates two observation boundaries:

- the **foreground outcome** is root `main` completing;
- the **terminal outcome** is known only after foreground and all detached
  work settle (and, for durable execution, after required terminal state is
  committed).

Foreground success can therefore precede terminal failure from detached work.
Callers that need complete execution status must observe the terminal outcome,
not only the foreground result.

## Execution ownership and operational policy

Accepted new and resumed roots are automatically submitted as Gantry-owned
tasks through the configured executor. Spawned children use the same executor
capability. Callers observe handles, await outcomes, query state, cancel, and
shut down; they do not poll a `Machine` or manually drive accepted source
work. The embedding owns the executor that polls Gantry's submitted futures,
while Gantry owns their interpreter lifecycle and semantic transitions.

Implementations bound asynchronous and blocking work. Capacity limits cover
owned roots, child tasks, hooks, event delivery, frontend/analysis jobs, and
the dedicated blocking-work service. Blocking jobs use owned immutable
snapshots, nonblocking bounded admission, cancellation-before-start, and
retain-to-completion semantics once started. Capacity refusal is reported as
`implementation-resource-exhaustion`; generic unbounded blocking helpers are
not a conforming substitute, and serialized storage workers remain separate
from the generic blocking pool.

For the reference CLI, `gantry run` uses a multithread Tokio runtime. Omitting
`--workers` leaves the count unset so Tokio chooses its CPU-derived default;
`gantry run --workers POSITIVE_INTEGER [PACKAGE_ROOT]` selects an explicit
positive count. Worker count, executor implementation, queue topology, and
physical schedule are operational policy. They must not change portable
results, task identity, or durable compatibility.

## Durable resume

Durable resume reconstructs unfinished attached and detached task state from
committed execution evidence. It reuses stable task, handle, operation,
session, event, and evidence identities. Resume requires the exact recorded
canonical IR identity and protocol selections; candidate source is acceptable
only when analysis produces the same canonical IR digest. Cosmetic source
changes may therefore be compatible, while a different lowered program is a
`source-or-configuration-incompatibility` resume-start failure. V1 defines no
workflow migration.

Executor implementation and worker count may change on resume because they
are excluded from durable identity, but the new policy must admit the complete
reconstructed runnable set before resume is accepted. Recovery provides
exactly-once logical transition application, **not** exactly-once physical
executor submission. A crash can make a previous submission unknowable, so a
replacement future may be physically resubmitted while retaining the same
logical task identity and committed state. External hook dispatch has its own
indeterminate-dispatch recovery rules; executor-submission evidence must not
be used to infer exactly-once external effects.

For the normative details, see `SPEC.md` Sections 3, 10, 11, 12, and 15. The
CLI worker contract is also summarized in
[`cli-runtime-policy.md`](cli-runtime-policy.md), and bounded frontend and
blocking-work policy in
[`frontend-resource-policy.md`](frontend-resource-policy.md).
