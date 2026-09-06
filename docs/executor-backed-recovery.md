# Executor-backed durable recovery

`Interpreter::resume_durable_execution` reconstructs retained concurrent graphs
and submits process-local replacement drivers through the configured executor.
Callers observe the returned execution handle; they do not drive recovered
machines themselves. The journal owner is acquired before replacement work is
prepared, and submitted drivers remain gated until the resume handoff completes.

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
checks detection of this causal gap. It does **not** establish end-to-end
replacement-event creation by resumed graph drivers. That integration remains
unfinished in GNT-ASYNC-REC-001, alongside complete crash-edge, whole-graph
admission rollback, stale-owner, terminal-delivery, and changed-worker-count
qualification. The async publication and release claims remain blocked; passing
the current workspace suite does not close those acceptance criteria.
