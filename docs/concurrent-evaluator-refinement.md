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
later source actions in marked tasks. Executor abort failure leaves task state
unsettled; confirmed stop removes the future and permits one cancelled
settlement. Late wakes after stop cannot make the task runnable or mutate its
settlement.

**Foreground, terminal, and shutdown uniqueness.** Foreground and terminal
coordinates are optional monotonic fields fixed at most once. Detached failure
cannot rewrite foreground state but participates in terminal precedence.
Shutdown cannot terminate before the cohort reaches terminal state, and a
barrier failure cannot refinalize either language outcome.

## Requirement and trace links

The machine-readable mapping is
`protocol/conformance/concurrent-refinement-v1.json`. Its model evidence links
the formal lifecycle and property clauses to the bounded search. Its trace
list links task creation/submission, ownership transfer, joins, detachment,
sessions, cancellation, terminal precedence, events, shutdown, Tokio task
services, and schedule replay to supported public or adapter-contract tests.

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

