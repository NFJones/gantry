# Executor-backed durable recovery

`Interpreter::resume_durable_execution` reconstructs retained concurrent graphs
and submits process-local replacement drivers through the configured executor.
Callers observe the returned execution handle; they do not drive recovered
machines themselves. The journal owner is acquired before replacement work is
prepared, and submitted drivers remain gated until the resume handoff completes.

Concurrent resume keeps the interpreter's durable-owner registry entry pending
until the graph runtime is installed, graph ownership is active, and completion
observation and control ownership are transferred. Registry consumers wait during
that interval rather than receiving an inactive owner. The public result-gap
regression pauses this handoff and checks that owner lookup remains pending;
replacement gates open only after the ready owner is published.

Logical task and source-handle identities are retained. Executor handles are
process-local and are not checkpointed. A replacement driver is another physical
submission for the existing logical task, not a second task-creation event or
an exactly-once physical-submission guarantee.

## Committed operation state

Recovery retains the latest operation policy independently for each task:

- Indeterminate read-only or idempotent dispatch uses a fresh dispatch identity
  and advances the recovery-dispatch coordinate.
- Indeterminate non-idempotent action dispatch becomes an unknown outcome.
- A committed hook outcome is processed without invoking the hook again.
- Committed results are not consumed twice.
- Recorded retry waits retain their delay, validation errors, and retry budget.

For recovered model requests, the committed active session is reused. In
particular, a prompt with `session = fork` must not create a new conversation
when processing an already committed outcome. Session ownership, creation site,
parent, and mode are checked against the reconstructed operation context.

The public regression
`durable_child_prompt_resume_reuses_committed_outcome_without_hook` in
`crates/gantry-conformance/tests/source_spawn.rs` rejects result commitment after
the model outcome is durable, resumes with no hook configured, checks successful
completion, and compares session identities before and after resume. It also
validates every committed prefix in that fixture. This is bounded evidence, not
a claim that every crash edge is qualified.

## Event identity and current qualification boundary

Under [GNT-12.2](../SPEC.md#GNT-12.2), only a committed event occurrence reserves
its event ID, activity ID, and timestamp across recovery. If a causal transition
committed but its event did not, the replacement must use the resume activity
and its actual creation time. It must commit before dependent work proceeds.
An uncommitted event draft cannot reserve its previous identity.

The runtime regression
`task_creation_event_failure_recovers_cause_without_reserving_event_identity`
checks detection of this causal gap. For a child still awaiting submission,
the recovered driver repairs a missing spawn occurrence through the fenced
event owner before publishing submission resolution or releasing its parent.
Existing occurrences are reused without allocating replacement metadata.
The public `source_spawn/recovery.rs` regression checks this ordering and
retention of the original creation cause through compaction.

For a recovered committed operation result, the driver repairs a missing
operation-result occurrence before taking its first machine step. It reconstructs
the event from the retained result type and normalized bytes without invoking
the hook again. The public result-gap regression rejects the original event
commit and checks that its replacement is the next committed journal entry.

For a retained hook outcome, action and model drivers repair a missing
operation-completion occurrence before processing that outcome. The original
dispatch identity and attempt coordinates remain unchanged, and recovery does
not invoke the hook again. The completion-gap regression checks that the
replacement precedes subsequent result commitment.

Recovered joins and detaches reuse the original event checkpoint rather than appending a
second no-op checkpoint. Recovery matches the exact pending control and uses
committed event ownership when available. A missing event with multiple eligible
owners is rejected rather than attributed by guessing. The join-gap and
detach-gap regressions check replacement before source continuation and strict
recovery of the resulting journal; detach coverage also checks compaction.

Already-terminal graph resume repairs a missing terminal-execution occurrence
under journal ownership before publishing the recovered lifecycle state. It
then refreshes the recovered delivery obligations without submitting another
language task. The terminal-gap regression checks that the replacement is
committed before resume returns.

The same prepublication repair restores missing foreground and task-completion
events in committed causal order while replacement drivers remain gated.
Successful and cancelled child outcomes and exact retained root outcomes can
be reconstructed. Failed-child completion events reuse the exact outcome from
the committed pre-settlement machine, checked against the settled failure code.
The failed-child crash regression covers a declined operation. Failure details
absent from that predecessor are still rejected rather than fabricated.
Restart fixtures use distinct identity streams so ordinary recovery is tested
separately from the allocator's bounded collision-failure policy.

Typed execution-wide cancellation records also participate in prepublication
event repair. Recovery preserves the committed reason and restores its event
before replacement drivers progress. The cancellation crash regression checks
the cancelled outcome, causal ordering, and event retention through compaction.
Recovery also restores task-target cancellation labels identified by newly
cancelled machines in committed cuts. Each task label has a distinct occurrence
key within its cause, separate from the execution request; duplicate labels for
the same task remain rejected. The public cancellation fixture checks both root
and child labels, and a runtime regression verifies duplicate rejection.
Live execution-wide cancellation stages its execution occurrence and each newly
emitted task cancellation occurrence in the same graph transaction. All event
commits precede graph publication and cancellation signalling. Descendant-only
cancellation also stages newly emitted task labels before publishing its cut;
the parent-failure regression checks that the attached child's cancellation
event precedes child settlement without cancelling detached work.

For an indeterminate operation, recovery restores a missing dispatch occurrence
from the original committed request before physical redispatch. Its event keeps
the original dispatch coordinates; any permitted replacement dispatch receives
a fresh dispatch identity. The public dispatch-gap regression verifies that the
replacement event is the next journal entry before redispatch proceeds.

Replacement of other missing causal events remains unfinished in
GNT-ASYNC-REC-001, alongside complete crash-edge, whole-graph
admission rollback, stale-owner, terminal-delivery, and changed-worker-count
qualification. The async publication and release claims remain blocked; passing
the current workspace suite does not close those acceptance criteria.
