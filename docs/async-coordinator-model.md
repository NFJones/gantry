# Async coordinator bounded-model argument

## Scope and bounded claim

This argument records `GNT-ASYNC-MODEL-001` partial property evidence for a
finite projection of the implemented async coordinator. It is not a
full-clause proof of `GNT-3.6` or `GNT-15.4-owned-work`, does not advertise a
profile, and adds no REC/PROOF scope.

The model is exhaustive only over its explicit finite state and action domains.
It is not an unbounded proof over arbitrary programs, task graphs, host futures,
integrations, or schedules. It preserves causal and per-task ordering but does
not require deterministic sibling order for execution, completion, events, or
settlement. Its coordinator-guard projection is not a global lock-order proof.

## State-space decomposition and counts

The checked golden retains the pre-existing depth-14 refinement search and adds
three coordinator projections. Every projection runs to queue exhaustion under
a safety ceiling; each records a zero frontier and `fixed_point=true`.

| Search | States | Terminal | Maximum shortest depth | Boundary |
| --- | ---: | ---: | ---: | --- |
| `integrated-coordinator-lifecycle` | 488 | 6 | 17 | One composed child lifecycle: create/publish/submit/register/gate; join or detach; optional cancellation followed by cooperative semantic and physical settlement, with abort as an independent post-cancellation action; permit release; waiter registration/notification; child event; root, foreground, and terminal completion. |
| `auxiliary-resource-identity` | 729 | 1 | 7 | Two finite actors, two task identities, two operation identities, and independent capacity-one admission, transition-budget, and operation-budget projections. |
| `coordinator-guard-external-call` | 16 | 1 | 10 | An abstract transaction-boundary sequence: register a waiter, release a modeled guard, run an external call, reacquire to publish and take waiters, then wake after release. |

The JSON records all finite fields, values, actions, initial assignments,
terminal assignments, ceilings, checked counts, and closure results. The guard
model deliberately contains no invented ranked locks.

## Invariant-to-implementation mapping

The dedicated manifest maps only properties with focused implementation
evidence:

- `creation-publication-before-submission` and
  `gate-release-after-registration` map to immediate-poll source-child tests.
- `handle-ownership-linearization` maps to the focused public join test and the
  direct join/detach race.
- `no-lost-wakeup`, `successor-publication-before-notification`, and
  `waiter-notification-after-guard-release` map to focused waiter-registration,
  publication, and unlocked-wake probes.
- `permit-release-after-physical-settlement` maps to supervision capacity held
  through physical reaping.
- `attached-drain-before-root-settlement` maps to actual current-thread and
  multithread Tokio descendant-drain tests.
- `one-unit-admission-bound`, `shared-transition-budget-bound`, and
  `shared-operation-budget-bound` map to runtime capacity-one and final-unit
  race tests plus public-surface budget tests.
- `task-identity-uniqueness` maps to concurrent production allocation from two
  distinct live parents. `operation-identity-uniqueness` maps to the
  task-qualified identity test and the native Tokio stress, which observes
  distinct same-site operation identities from concurrently running children.
- `foreground-before-terminal` maps to the focused detached Tokio lifecycle
  test, the deterministic committed-cancellation case, and both native Tokio
  stress runtimes. The deterministic case holds all three dispatches pending
  until cancellation is published, then requires cancelled foreground and one
  terminal publication after foreground and all four task completions. The
  randomized stress retains nondeterministic cancel/completion races.

The `coordinator-external-call-after-guard-release` sequence remains a
model-only invariant. `interrupted_commit_keeps_old_state_and_fences_publication`
shows that a snapshot remains possible and old state remains published while a
journal commit is pending; it does not prove the model's abstract
release/call/reacquire guard sequence. Other finite-model invariants likewise
remain model-only checks and are not promoted to implementation or clause-wide
claims.

## Normative assignment authentication

The manifest authenticates the existing assignment rows from
`protocol/conformance/async-execution-contract-v1.json`:

1. `GNT-3.6` / `clause-001` for `concurrent-evaluator`, `durable-runtime`,
   `embedding`, and `evaluator`.
2. `GNT-15.4-owned-work` / `clause-001` for `embedding`.

The test requires byte-for-byte equivalent requirement, clause, and profile
lists. These rows identify the surrounding normative context; this artifact is
partial property evidence and not a full-clause proof.

## Validation and gate integration

The manifest records the focused model, coordinator, operation-budget, and
native Tokio stress tests together with `rustfmt --check` and generated
protocol freshness. A failing stress diagnostic records the selected runtime,
iteration, deterministic input-reconstruction seed, planned release order, and
observed dispatch, release, and completion orders. Selecting one test symbol
and `GANTRY_SOURCE_STRESS_ITERATION` reconstructs those inputs; it does not
replay a Tokio schedule. The implementation anchors are supporting evidence,
not proof expansion. Commits and tracker operations remain outside this task.
