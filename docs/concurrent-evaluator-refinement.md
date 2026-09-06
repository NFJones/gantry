# Concurrent evaluator refinement argument

## Scope and claim

This document gives Gantry v1's repository-owned argument that the concurrent
evaluator schedules the same explicit-frame machine used by the sequential
evaluator. It covers task creation and submission, linear handle ownership,
all-settled joins, detachment, spawned sessions, cancellation, split
foreground and terminal completion, executor abort, and shutdown. It does not
define another evaluator or another source-language transition system.

The argument is profile-scoped to `concurrent-evaluator`. Durable commit,
recovery, fencing, event replay, and combined concurrent-durable obligations
remain outside this claim.

The async source-execution adoption is narrower than that full refinement
argument. `protocol/conformance/source-spawn-v1.json` establishes native
executor-owned child submission, publication gates, child-session ordering,
and the live concurrent-durable commit order at source `spawn` edges.
`protocol/conformance/source-join-v1.json` establishes integrated source
`join`, `joinall()`, and `detach`: all-settled waiting, source/declaration-order
results, ordered aggregate failure, the empty `joinall()` case, Join event
causality, and the foreground/terminal split for detached work. Descendant
cancellation and failure draining are frozen separately by
`protocol/conformance/async-cancellation-v1.json`: owner failure waits for
attached descendants, leaves siblings and detached work isolated, retains a
dropped cancellation control owner, distinguishes confirmed and failed abort,
uses the existing graph controller to bound cancellation-resistant durable
dispatch, retains durable ownership across failed physical abort, and reuses
one owner across cancellation/shutdown handoff. Resumed task-graph
reconstruction and child resubmission remain with `GNT-ASYNC-REC-001`. This
additional evidence does not advertise or publish a profile.

For the generics-and-static-traits amendment, every spawned machine already
contains only closed applied descriptors and direct selected call targets.
The concurrent refinement covers copying those values through captures and
task results, ordered join reconstruction, and schedule independence of the
analyzer-selected implementation. It does not add concurrent inference,
monomorphization, or trait lookup.

## Assumptions, fairness, and bounds

The executable package is well typed, the base sequential machine invariants
hold for every task-local transition, and the embedding executor satisfies the
weak-fairness boundary in `GNT-3.15-liveness`. A continuously runnable Gantry
task is eventually polled; yielding makes another runnable task eligible; and
a ready executor or adapter response is eventually observable. No assumption
fixes cross-task order, equal CPU allocation, maximum latency, timestamps, or
completion of genuinely pending integration work.

The checked model is bounded to one accepted execution, one root task, two
possible child tasks, one dynamic handle per child, the declared finite action
set, and the maximum trace depth recorded in
`protocol/goldens/concurrent-refinement-model-v1.json`. The executor companion
model exhausts the fourteen six-poll schedules in which both continuously
runnable tasks receive three polls and neither is selected more than twice
consecutively. These searches are not an unbounded proof over all Gantry
programs, values, task graphs, host futures, or schedules.

The amended lifecycle model carries one representative closed generic
descriptor and one statically selected concrete trait-call target as immutable
ghost coordinates. Every explored scheduling, ownership, cancellation, and
settlement transition must preserve both. Concrete public tests establish the
actual `Envelope<String>` value, operation schema, direct target, and executor
behavior; the finite coordinates do not model analyzer algorithms.

## Refinement mapping

- `task-created` first records a submitting child and hidden pending handle;
  submission success makes that same child runnable and exposes the attached
  handle, while submission failure settles that same child without allocating
  a replacement.
- Every runnable child is an instance of the shared `Machine`. Scheduling
  chooses which child takes its next transition but cannot reorder transitions
  within that child.
- `task-ownership-changed(..., join)` moves an attached handle to joined before
  waiting. `task-ownership-changed(..., detach)` moves it to detached execution
  ownership before the parent continues. Neither state has a transition back
  to attached.
- `task-settled` changes each task once. A blocked join resolves only after all
  selected tasks settle and uses source or declaration order rather than
  settlement order.
- Cancellation monotonically marks its target set. Marked tasks cannot perform
  a later source-consuming action, and a confirmed executor stop is represented
  by ordinary cancelled settlement rather than a fourth task status.
- Foreground completion requires root settlement and attached-descendant
  cleanup. Terminal completion additionally requires detached work to settle
  and applies the specified failure/cancellation precedence exactly once.
- Shutdown uses the same cancellation, settlement, and terminal rules over its
  monotonic cohort. Required-delivery failure remains a separate observation
  coordinate and cannot rewrite a fixed language outcome.

## Property argument

**Progress and fairness.** The bounded model checks that every nonterminal
state not waiting on executor submission has an enabled Gantry transition.
The executor model checks every admitted bounded fair schedule, repeated
self-wakes, submission failure, sibling failure, confirmed abort, and stale
wake. Genuinely pending integration and executor prerequisites remain outside
wall-clock termination claims.

**Preservation and one machine.** Child construction validates the same typed
program, value limits, session state, and execution identity consumed by the
sequential machine. Scheduler steps return ordinary `MachineStep` values; no
adapter result or schedule introduces a second semantic transition path.

**Linear ownership and all-settled joins.** The abstract handle algebra has
only `pending`, `attached`, `joined`, and `detached` after creation. Join and
detach are enabled only from `attached`, so no explored trace consumes or
transfers a handle twice. Executable permutations show that joins wait for all
members and preserve source/declaration ordering despite settlement order.

**Cancellation and abort.** Cancellation markers are monotonic and disable
later source actions in marked tasks. A cancellation-resistant durable dispatch
is cooperatively polled for the configured drain and then stopped only through
its supervised executor handle. Executor abort failure publishes an
executor-failure semantic outcome separately from still-live physical
supervision; confirmed stop removes the future and permits one cancelled
settlement. Late wakes after stop cannot make the task runnable or mutate its
settlement.

**Durable recovery projection.** Concurrent journal snapshot version seven
uses `gantry.concurrent-recovery-snapshot/v1` as a canonical compaction base.
It retains the accepted execution start and program, latest version-four or
version-five graph checkpoint, typed cancellation, event-delivery obligations,
operation-cut history, retained causal identities, and the represented
frontier. Recovery validates a contiguous suffix against that state; public
query, open, and resume use the same concurrent projection as full prefixes.

**Foreground, terminal, and shutdown uniqueness.** Foreground and terminal
coordinates are optional monotonic fields fixed at most once. Detached failure
cannot rewrite foreground state but participates in terminal precedence.
Shutdown publishes one immutable non-orderly report when bounded physical
cleanup remains pending, preserving each cleanup blocker separately. Durable
owners receive identity-ordered frozen release coordinates and are processed
independently: safe owners release once even when another owner remains unsafe,
while exact release errors and bounded observation failures remain separate
from the final shutdown-event result. Shutdown does not release a durable owner
while failed-abort work remains physically live, and a barrier failure cannot
refinalize either language outcome.

## Generics and static-trait refinement

**Closed task transfer.** Spawn captures are logical copies of already closed
values. Child inputs, suspended frames, operation requests, task settlement,
join results, detached state, cancellation snapshots, and shutdown reports
retain the complete concrete descriptor. Join construction preserves source
or declaration order and never erases or re-infers type arguments. The
existing value and schema boundaries reject an open descriptor before a task
can be submitted or an operation can be observed.

**Schedule-independent static selection.** Each call instruction names the
same analyzer-selected concrete callable in every task. Scheduler admission,
polling, wakeup, abort, settlement, join, detach, cancellation, and shutdown
have no transition that rewrites that identity or enters a trait solver.
Consequently, different fair schedules may change inter-task observation order
but cannot instantiate another template, choose another implementation, alter
the per-task direct-call order, or change the exact concrete effect and
operation-site inventory.

**Evidence boundary.**
`closed_generic_tasks_are_executor_neutral_across_schedules` exercises direct
generic and trait calls under deterministic schedule permutations and the
caller-owned executor. `concrete_generic_capture_result_and_join_preserve_exact_application`
checks capture and ordered join isolation;
`concrete_generic_operation_schema_and_result_survive_task_boundary` checks
the concrete schema and rejects a wrong closed operation result; and
`concrete_generic_descriptors_survive_mixed_join_detach_cancel_and_shutdown`
covers the remaining ownership and lifecycle paths. The public open-artifact
negative remains
`generic_ir_contracts_reject_open_runtime_and_noncanonical_inputs`.

## Requirement and trace links

The machine-readable mapping is
`protocol/conformance/concurrent-refinement-v1.json`. Its model evidence links
the formal lifecycle and property clauses to the bounded search. Its trace
list links task creation/submission, ownership transfer, joins, detachment,
sessions, cancellation, terminal precedence, events, shutdown, Tokio task
services, and schedule replay to supported public or adapter-contract tests.
The separate current-specification source manifests divide the executable
surface by ownership: `source-spawn-v1.json` links native child submission and
its live concurrent-durable ordering slice, while `source-join-v1.json` links
integrated JOIN, JOINALL, and DETACH behavior. Neither manifest claims owner
failure/cancellation draining: `async-cancellation-v1.json` binds that separate
owner's exact frozen requirement rows to deterministic durable isolation,
Tokio descendant-drain, dropped-owner, submitted-unpolled abort, abort-failure,
and shutdown-handoff regressions. Resumed graph resubmission remains with
`GNT-ASYNC-REC-001`, and no profile publication claim follows from these
evidence links.

The generics amendment is mapped separately by
`protocol/conformance/generics-traits-refinements-v1.json`. It links
`GNT-2.1`, `GNT-3-F-DOMAINS`, `GNT-3.15-generic-profiles`, `GNT-3-F-GENERICS`,
`GNT-3-F-INSTANTIATION`, `GNT-3-F-TRAITS`,
`GNT-3-T-GENERIC-CALL`, `GNT-3-T-PARAMETRIC-PACKAGE`,
`GNT-5.19`, `GNT-5.20-parametric-types`, `GNT-6.1`,
`GNT-6.12-static-traits`, and
`GNT-8.13-concrete-generic-schemas` to the immutable model coordinates and the
public schedule, transfer, lifecycle, schema, and rejection evidence above.
The manifest separately classifies grammar, static-analysis, diagnostics, and
artifact-construction clauses as frontend/analyzer prerequisites, so schedule
preservation is not overstated as another static proof.

## Counterexample replay

Each checked counterexample records a valid prefix, a rejected next action,
and the invariant that requires rejection. Replays cover child execution before
submission, double settlement, double join, detach after join, root settlement
before attached-failure drain, source action after cancellation, source action
while a join remains pending, foreground completion with an unsettled attached
child, terminal completion with unfinished detached work, terminal completion
twice, and shutdown completion before terminal state. The companion executor model
replays stale wakes after abort, sibling failure isolation, and submission
failure without task creation.

An attempted schedule-dependent call-target rewrite or an open generic task
payload has no transition from an admitted model state. Those invalid
boundaries are checked respectively by preservation of the immutable selected
target in every modeled step and by the linked public IR rejection case.

