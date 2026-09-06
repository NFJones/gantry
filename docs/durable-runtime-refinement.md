# Durable runtime refinement argument

## Scope and claim

This document gives Gantry v1's repository-owned argument that sequential
durability refines the same explicit-frame machine used by the nondurable
evaluator. It covers authoritative committed prefixes, semantic commit points,
crash recovery, checkpoints and compaction, operation and event-delivery
indeterminacy, recorded retry delays, cancellation, foreground and terminal
completion, delivery barriers, journal-owner release, and shutdown.

The argument is profile-scoped to `durable-runtime` without the concurrent
refinement. Physical SQLite tables and write behavior are not semantic inputs.
Combined concurrent-durable task-graph recovery remains outside this claim.

The separate combined-checkpoint/v4 codec retains first-class root status,
pending and settled outcomes, and root/child driver-ownership bookkeeping.
It also preserves child pending outcomes rather than reconstructing them as
absent. Its `GNTCDP04` bytes and concurrent-durable-evidence/v4 envelopes replace
the superseded v3 graph formats; no legacy decoder is provided. Recorded driver
bookkeeping is evidence, not a restored executor capability. The live
source-spawn evidence now establishes coherent task-creation, operation, and
settlement commit ordering through those graph envelopes. Fenced task-graph
reconstruction and executor resubmission remain separate recovery obligations.

`ExecutionCoordinator::stage_graph` provides an exclusive quiescent transaction
primitive over borrowed root and child machines. Its private copies share one
isolated budget; ordinary coordinator semantic writers are rejected until
publication is released. An owned graph checkpoint crosses the existing fenced
journal boundary before machine, task, session, and budget state are installed
and settlement observers are notified. No coordinator guard crosses storage
awaits. Physical completion remains separate and is merged monotonically.
Dropping an unsubmitted stage rolls back; an interrupted or failed submitted
commit leaves semantic publication fenced because storage may have committed.
This primitive requires a must-settle execution owner. `set_event` freezes the
causal event and delivery plan; publication waits for the existing event journal
owner to commit them. Event failure leaves the graph unpublished and fenced.
The journal retains graph and event evidence as a causal prefix, not necessarily
one physical record. Delivery remains with the existing event worker.

The live sequential durable driver retains an isolated authoritative projection
while its private machine advances. Semantic and event commits refresh that
projection; settlement, foreground, and terminal publication install root state,
sessions, budgets, and retained evidence together through
`publish_committed_root`, then notify observers outside the lock. Cancellation
commit failure retains the last committed machine and budget rather than its
speculative successor.

The issue-scoped evidence in `protocol/conformance/durable-coordination-v1.json`
binds these mechanisms to the frozen DUR-001 requirement assignments. It does
not restore profile claims. `protocol/conformance/source-spawn-v1.json` binds
native executor-owned child submission and live concurrent-durable spawn and
child-operation ordering to the current specification. Source JOIN, JOINALL,
DETACH, broad task-graph cancellation, fenced process reconstruction, and
replacement submission remain separate obligations.

For the generics-and-static-traits amendment, the durable prefix retains the
canonical analysis artifacts and the distinct closed executable projection
selected at start. Recovery reconstructs that same projection and machine
without parsing source, inferring type arguments, proving bounds, selecting an
implementation, or discovering an instantiation.

## Assumptions, crash choices, and bounds

The package is well typed, the base sequential-machine invariants hold, and
every storage read returns one causally closed authoritative prefix accepted by
the public recovery projection. A crash may occur before or after each modeled
semantic commit point. Uncommitted physical tails are absent from that prefix.
Fenced acquisition ensures a superseded owner cannot extend it.

The checked model is bounded to one accepted execution, one root task, one
logical operation, one event delivery, one immutable language outcome, one
required-delivery barrier, one journal owner, and the maximum trace depth in
`protocol/goldens/durable-refinement-model-v1.json`. Host outcomes and delivery
results are nondeterministic choices. Genuinely pending host work is not a
wall-clock termination claim. The search is not an unbounded proof over every
program, prefix length, operation, event, checkpoint, crash, or adapter.

The amended model carries immutable identities for one retained closed generic
descriptor, selected trait-call target, concrete effect summary, operation
schema, and executable projection. Recovery from full and compacted prefixes
must preserve those coordinates exactly. Public fresh-process, candidate-source,
tamper, and source-free recovery tests establish the corresponding concrete
artifact bytes and failure boundaries; the finite coordinates do not model
source analysis.

## Recovery-prefix refinement mapping

- A committed operation preparation recovers as a redispatch with a new
  physical dispatch number for prompt, decision, read-only, and idempotent
  work. The same cut recovers as unknown outcome for a non-idempotent action.
- A committed host outcome recovers for deterministic validation or failure
  conversion and is never redispatched. A committed accepted result recovers
  as source-consumable exactly once and is never validated twice.
- A committed retry-waiting state retains its selected delay and retry budget.
  Recovery waits that complete delay before committing another preparation.
- A committed cancellation mark disables later source-consuming transitions.
  Task, foreground, and terminal settlement are each monotonic and recovered
  without replaying their causal label.
- A committed event cause without its occurrence requires one replacement
  occurrence. A committed occurrence is delivered from its frozen plan. A
  dispatched delivery without settlement is indeterminate; a committed retry
  delay is reused; success and terminal settlement are not redelivered.
- Required-delivery barrier and journal-owner status remain separate from the
  fixed foreground and terminal language outcomes. Release invalidates the
  owner after terminal and finite delivery obligations settle.
- Serial full-prefix and snapshot-plus-suffix representations have one logical
  projection. Compaction may change representation but cannot change recovered
  machine, operation, event, barrier, or owner state. Concurrent journal
  snapshot version seven uses `gantry.concurrent-recovery-snapshot/v1` to
  retain the immutable execution start and program, latest version-four or
  version-five graph checkpoint, operation-cut history, typed cancellation,
  event and delivery evidence, retained evidence identities, and the compacted
  frontier. Public query, open, and resume dispatch that representation through
  concurrent recovery and validate any contiguous suffix against the retained
  graph, event, and operation state. Serial snapshot versions five and six are
  unchanged. Legacy version-four graph cancellation records remain rejected
  because they cannot reconstruct the typed cancellation category and causal
  identity without guessing.

## Property argument

**Causal-prefix simulation.** Every modeled action is either a stutter with no
semantic observation or one atomic logical commit whose prerequisites are
already in the prefix. For every reachable state, the model compares recovery
from full and compacted representations and requires identical projections.

**Commit-before-observation.** Operation preparation precedes dispatch;
outcome precedes validation; accepted result precedes consumption;
cancellation precedes signalling and settlement; event occurrence precedes
delivery; task settlement precedes foreground and terminal completion; and
terminal completion plus delivery settlement precede owner release.

**Crash classification and retry reuse.** Recovery classification is a pure
function of committed state. Prepared read-only work redispatches, prepared
non-idempotent work becomes unknown outcome, committed outcomes and results are
reused, and operation and delivery retry delays are retained without
resampling or budget consumption.

**Cancellation and unique outcomes.** Cancellation is monotonic and prevents a
later source-consuming operation or accepted result. Task settlement,
foreground completion, and terminal completion each occur at most once.
Barrier failure and owner-release status cannot replace either fixed language
outcome.

**Lifecycle and shutdown.** Admission and observation are stuttering steps for
the source machine. Shutdown is monotonic, uses the same cancellation and
terminal coordinates, waits for the modeled owner/delivery obligations, and
publishes one immutable terminal report.

## Generics and static-trait refinement

**Retained-versus-fresh projection equivalence.** Start records the canonical
analysis IR, closed instantiation set, selected implementation identities,
exact effects, concrete schemas, source origins, and closed executable
projection under the selected specification and protocol revisions. A fresh
analysis of an equivalent candidate source must produce the same execution
identity inputs and executable projection even when cosmetic source provenance
differs. Recovery decodes and validates the retained projection and cannot add
or replace a concrete instantiation.

**Source-free recovery and crash cuts.** Every committed cut retains either
the complete accepted start metadata or no accepted execution. Once accepted,
the generic descriptor, direct target, schema identity, and effect summary are
part of immutable recovered program state. Operation preparation, outcome,
accepted result, cancellation, settlement, compaction, and owner release may
advance around crashes, but none may invoke the analyzer or rewrite those
program facts. Full-prefix and snapshot-plus-suffix recovery therefore drive
the same concrete machine to the same logical value and failure outcome.

**Fail-closed artifact boundary.** Missing, open, malformed, tampered, stale,
or mixed-revision generic artifacts fail as
`source-or-configuration-incompatibility` before recovered interpretation,
journal acquisition for new work, or authoritative-prefix mutation. The
failure is not catchable by source `attempt`, and no compatibility migration
or old-format fallback is inferred.

**Evidence boundary.** `durable_generic_artifacts_reconstruct_without_runtime_analysis_and_reject_tampering`
compares retained and freshly lowered artifacts, compacted and full recovery,
candidate-source resume, source-free fresh-process recovery, and tampered or
malformed rejection with no journal mutation. The ordinary durable recovery
and event suites supply the crash-cut and commit-order argument. The shared
externally visible open-artifact negative is
`generic_ir_contracts_reject_open_runtime_and_noncanonical_inputs`.

## Requirement and trace links

The machine-readable mapping is
`protocol/conformance/durable-refinement-v1.json`. Its model evidence closes
the durable-runtime projection of `GNT-3-D-PROPERTIES` and the resolved
lifecycle kernel. Its trace list points to executable recovery, commit-cut,
event-gap, delivery, cancellation, shutdown, fencing, and compaction cases
owned by the existing durable implementation suites.

The generics amendment is mapped separately by
`protocol/conformance/generics-traits-refinements-v1.json`. It links
`GNT-2.1`, `GNT-3-F-DOMAINS`, `GNT-3.15-generic-profiles`, `GNT-3-F-GENERICS`,
`GNT-3-F-INSTANTIATION`, `GNT-3-F-TRAITS`,
`GNT-3-T-GENERIC-CALL`, `GNT-3-T-PARAMETRIC-PACKAGE`,
`GNT-5.19`, `GNT-5.20-parametric-types`, `GNT-6.1`,
`GNT-6.12-static-traits`,
`GNT-8.13-concrete-generic-schemas`, and
`GNT-11.11-generic-artifact-recovery` to the immutable recovery coordinates,
fresh-process/crash-cut evidence, and fail-closed rejection boundary above.
The manifest separately classifies grammar, static-analysis, diagnostics, and
artifact-construction clauses as frontend/analyzer prerequisites; durable
recovery preserves their accepted outputs rather than rerunning those phases.

## Counterexample replay

Each checked counterexample records a valid committed-prefix trace, one
rejected next commit, and the invariant requiring rejection. Replays cover
outcome acceptance before a committed outcome, double result consumption,
source work after cancellation, settlement before cancellation, event delivery
before occurrence, duplicate occurrence, delivery settlement before dispatch,
retry continuation before a recorded delay, foreground and terminal
duplication, owner release before terminal delivery closure, and shutdown
completion before owner release.

An attempted post-recovery inference, selected-target rewrite, open generic
projection, or tampered-artifact commit has no transition from an admitted
model state. Preservation of the immutable generic coordinates is checked at
every modeled crash cut, and the linked public negative cases reject such
inputs before they can affect the authoritative prefix.

