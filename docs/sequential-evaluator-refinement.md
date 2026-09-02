# Sequential evaluator refinement argument

This document is the repository-owned semantic argument required for the
nondurable sequential evaluator and its embedding composition. It is bound to
the exact `SPEC.md` revision recorded in
`protocol/conformance/sequential-evaluator-refinement-v1.json` and is checked
by `crates/gantry-conformance/tests/sequential_refinement_model.rs`.

## Scope and claim

The argument covers one accepted execution with the base evaluator's single
root task, explicit-frame machine, operation lifecycle, cancellation,
foreground and terminal completion, public lifecycle admission and
observation, required-delivery failure isolation, and shutdown coordination.
It covers the embedding role only where that role composes these same public
lifecycle and executor contracts.

The base evaluator has no spawned task and therefore no dynamic task handle.
The handle-ownership property is vacuous in this profile: no `task-created` or
`task-ownership-changed` transition is reachable. Concurrent scheduling,
join/detach ownership, durable commit cuts, recovery, resume, and journal-owner
state are excluded and remain obligations of later profile arguments.
The reviewed `M-Spawn`, `M-Detach`, and join-resolution clauses are therefore
explicitly not applicable to the base evaluator; root settlement remains
applicable and is covered directly.

The bounded model strengthens this written argument but is not an unbounded proof.
This issue supplies evidence for later gate verification; it does not
advertise the evaluator or embedding profile by itself.

For the generics-and-static-traits amendment, the base evaluator consumes only
the analyzer-produced closed executable projection. Generic free calls,
inherent methods, and statically selected trait methods therefore refine the
existing ordinary call rule: dispatch names one concrete callable and performs
no inference, monomorphization, trait lookup, integration operation, event, or
journal action of its own.

## Assumptions, fairness, and bounds

- The package has passed syntax and semantic analysis, lowering produced a
  well-typed `MachineProgram`, and start preflight accepted one execution.
- The selected protocol versions and `SPEC.md` digest are the reviewed v1
  values checked by the repository protocol and requirement suites.
- The host provides the weak fairness required by `GNT-3.15-liveness`: a
  runnable Gantry future is eventually polled, a cooperative yield makes other
  runnable work eligible, and ready timers or completed adapters are
  eventually observed.
- A prepared operation may remain genuinely pending on `DispatchOperation`
  indefinitely when no integration timeout, cancellation, or shutdown applies.
  A retry-waiting state is likewise genuinely pending until its timer or
  cancellation is observable. These are not enabled Gantry transitions.
- Host allocation failure, process termination, non-unwind abort, and a host
  that violates its polling or cancellation contract are outside this
  nondurable semantic model. Structured executor, adapter, budget, and runtime
  failures remain in scope.

The checked model starts with both `Unit` and `Int` result types. It explores
all unique states reachable within the recorded maximum trace depth over
deterministic work, operation preparation/outcome/acceptance/retry/failure,
cancellation, task settlement, foreground and terminal completion, required
barrier failure, and shutdown. The exact state and terminal-state counts are
recorded in `protocol/goldens/sequential-evaluator-model-v1.json`. The finite
depth, one-operation abstraction, and two representative result types are
explicit bounds; no unconditional termination or all-program proof is claimed.

The amended model also carries one representative closed generic descriptor,
one direct statically selected trait-call target, one exact concrete effect
summary, and one concrete operation-schema identity as immutable ghost
coordinates. Every explored transition preserves them. Public executable
tests establish the corresponding concrete `Envelope<String>` values, call
targets, operation result schema, and failure behavior; the ghost coordinates
do not model or stand in for source-level analyzer algorithms.

## Refinement mapping

The implementation relation uses the existing owners rather than a second
evaluator:

- abstract machine `M` is `gantry_runtime::Machine`; `Running`,
  `YieldRequired`, `WaitingSessionScope`, `WaitingOperation`, and terminal
  statuses identify enabled work, cooperative yield, genuine host work, and
  fixed outcomes;
- abstract operation state `Q(o)` is `OperationLifecycleState`; `Absent`,
  `Prepared`, `Outcome`, `RetryWaiting`, `Accepted`, and `Failed` preserve the
  formal lifecycle without conflating logical operation IDs and physical
  dispatch IDs;
- `operation-prepared` maps to `MachineLabel::OperationPrepared`, accepted
  `operation-result` maps to `MachineLabel::OperationResult`, and retained
  outcome/retry/failure states map to the versioned operation lifecycle and
  operation event owners;
- `cancellation`, `task-settled`, `foreground-completion`, and
  `terminal-completion` map to the correspondingly typed `MachineLabel`
  variants and the monotonic coordinates in `ExecutionSnapshot`;
- interpreter state `I`, admitted calls `A`, and accepted execution map `X`
  are owned by `InterpreterLifecycle`; admission and rejection linearize under
  one lifecycle lock, while query and waiter registration are source-machine
  stuttering steps;
- required-delivery failure is retained beside, not in place of, foreground
  and terminal language outcomes; and
- shutdown uses the same cancellation and settlement coordinates. The first
  admitted shutdown owns one coordinator and snapshots effective durations;
  repeated calls join or return its immutable report.

The final shutdown event and physical operation/delivery events are
observations of these transitions, not additional source-machine labels.

## Property argument

**Enabled progress.** For every modeled nonterminal root-task state that is
not waiting on an integration result or retry timer, at least one Gantry action
is enabled: a deterministic step, operation transition, cancellation
settlement, failure settlement, or successful settlement. The implementation
either takes that step, requests the configured cooperative yield, or fixes a
typed budget/runtime error. Finite transition, operation, loop, and call-depth
budgets prevent an infinite admitted sequence of deterministic source steps.
This says nothing about wall-clock completion while host work is genuinely
pending.

**Preservation.** `MachineProgram` retains analyzed types on parameters,
bindings, instructions, and operation occurrences. Deterministic primitives
construct only their declared result type; complete operation results validate
limits and type before replacing the suspended operation; assignment validates
the complete replacement before publication. The model carries an immutable
result-type coordinate through every transition, while the linked machine
tests exercise typed bindings, primitives, calls, aggregates, operation
completion, and atomic root replacement.

**Operation single consumption.** Preparation spends the logical operation
budget once and creates one pending occurrence. `complete_operation` removes
that occurrence before making its value available. `OperationLifecycle`
enters `Accepted` only after matching validated output is consumed, and no
accepted or failed state has a dispatch transition. Retry creates a fresh
physical dispatch but retains the same captured logical request. Both the
model and public operation tests reject a second acceptance or redispatch.

**Cancellation nonconsumption.** Cancellation is monotonic. Once marked, the
machine checks cancellation before source-consuming work, clears a pending
operation on settlement, and rejects later completion. The operation owner
also checks cancellation after a host outcome and before validation. The model
snapshots source progress and accepted-result count at cancellation and proves
both remain unchanged in every later reachable state.

**Lifecycle and observation.** New-work admission is allowed only while the
interpreter is running. Existing cohort operations remain separately
admissible during shutdown. Foreground and terminal coordinates each change
from absent to fixed once, terminal requires foreground, and query observes one
consistent snapshot without advancing `M`. Required-delivery failures can
start cancellation before terminal, but after terminal they remain a separate
record and cannot replace the fixed language outcome.

**Shutdown and terminal uniqueness.** The interpreter phase is monotonic from
running to shutting down to terminated. A single coordinator owns the phase
change; repeated shutdown calls share its report. In the base evaluator the
root settlement fixes foreground and terminal to the same language outcome.
The model permits neither terminal completion before foreground nor a second
foreground, terminal, shutdown-begin, or shutdown-finish transition.

## Generics and static-trait refinement

**Direct-call preservation.** A retained generic instantiation has already
closed every descriptor, selected each trait implementation, and fixed each
call edge before `MachineProgram` construction. Call execution therefore uses
the existing frame, argument-copy, receiver-copy, return, cancellation, and
failure transitions. Contextual `Self` is the concrete receiver in the closed
signature; no runtime state contains its source placeholder. Ordinary dispatch
adds no effect or semantic label beyond effects and operations reached in the
selected body.

**Value, effect, operation, and failure preservation.** Parameters, mutable
and immutable bindings, receivers, returns, operation requests and results,
and public terminal values retain their full concrete descriptors. Logical
copies preserve nonaliasing even when immutable storage is shared internally.
The selected callable's exact effect summary and static operation sites are
immutable program facts. Operation output is validated against the concrete
schema before the suspended machine can consume it; a wrong closed type, open
artifact, runtime failure, cancellation, or `attempt` outcome follows the
existing transition and precedence rules rather than triggering inference or
fallback dispatch.

**Evidence boundary.** `analyzed_closed_generic_application_executes_as_a_direct_call`
and `generic_methods_and_static_trait_calls_preserve_logical_copy_isolation`
exercise direct calls, receiver copying, returns, and selected trait methods.
`generic_trait_method_returning_self_executes_with_the_closed_receiver_type`
covers contextual `Self`. `generic_operation_uses_the_concrete_result_type_and_schema`
covers exact operation metadata and failure before source consumption, while
`evaluator_program_contains_only_closed_direct_calls_and_no_analyzer_dependency`
checks the absence of runtime solver machinery. The externally visible
negative is `generic_ir_contracts_reject_open_runtime_and_noncanonical_inputs`.

## Requirement and trace links

- Progress, fairness, genuine host pending, and finite budgets:
  `GNT-3.15`, `GNT-3.15-liveness`,
  `executor_contract_bounds_and_failures_are_exact`, and
  `public_budgets_cancellation_and_dynamic_identities_are_exact`.
- Machine state and abstract labels: `GNT-3-M-STATE`, `GNT-3-M-LABELS`,
  `public_deterministic_values_and_failures_match_the_machine_contract`, and
  `public_interpreter_drives_and_observes_one_sequential_execution`.
- Lifecycle/admission/observation/shutdown: `GNT-3-M-LIFECYCLES`,
  `shutdown_races_transfer_admission_and_snapshot_first_durations`, and
  `public_required_delivery_failure_is_isolated_nonrecursive_and_post_terminal_safe`.
- Root task settlement and unique execution completion:
  `GNT-3-M-TASK-SETTLE` clause 1 and
  `public_interpreter_drives_and_observes_one_sequential_execution`; spawn,
  join-resolution, and detach clauses are recorded as base-profile exclusions.
- Operation transitions and exactly-once acceptance: `GNT-3-M-OPERATION` and
  `public_operation_lifecycle_is_lazy_serial_and_single_consumption`.
- Cancellation and failure propagation: `GNT-3-M-CANCEL`, `GNT-3-M-FAIL`, and
  `public_cancellation_after_outcome_prevents_source_consumption`.
- Profile-scoped proof obligation: `GNT-3-D-PROPERTIES`, checked by the bounded
  model and replay test named in the evidence manifest.

The generics amendment is mapped separately by
`protocol/conformance/generics-traits-refinements-v1.json`. It links
`GNT-2.1`, `GNT-3-F-DOMAINS`, `GNT-3.15-generic-profiles`, `GNT-3-F-GENERICS`,
`GNT-3-F-INSTANTIATION`, `GNT-3-F-TRAITS`,
`GNT-3-T-GENERIC-CALL`, `GNT-3-T-PARAMETRIC-PACKAGE`,
`GNT-5.19`, `GNT-5.20-parametric-types`, `GNT-6.1`,
`GNT-6.12-static-traits`, and
`GNT-8.13-concrete-generic-schemas` to the immutable model coordinates and the
public direct-call, copy, operation, failure, and rejection evidence above.
The manifest separately classifies grammar, static-analysis, diagnostics, and
artifact-construction clauses as prerequisites discharged by the frontend and
analyzer arguments, rather than pretending that runtime transitions re-prove
them.

The manifest lists every reviewed clause changed from planned to covered by
this issue and every exact public conformance-test anchor used by the argument.

## Counterexample replay

The model fixture records invalid traces for admission after shutdown,
reaccepting or redispatching an accepted operation, validating after
cancellation, source progress after cancellation, duplicate foreground or
terminal completion, terminal completion before foreground, barrier-driven
refinalization, and shutdown completion before execution terminal state. Each
trace must reach its reviewed prefix and reject the named next action. A future
implementation or model change that admits one of these traces must update the
argument and reviewed requirement evidence rather than silently weakening the
property.

An attempted runtime trait-selection step, direct-target rewrite, or open
generic boundary has no transition from an admitted model state. The bounded
model checks preservation of the immutable generic coordinates on every
existing transition, while the linked public negative rejects malformed or
open executable artifacts before machine construction.
