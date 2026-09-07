# Async execution refinement

## Scope and claim

This document composes Gantry's sequential, concurrent, and durable refinement
arguments for the executor-backed execution baseline. It does not replace their
bounded models. It relates those models to the completed owned-driver,
all-settled source-task, cancellation, stage-commit-publish, and fenced recovery
evidence required by `GNT-ASYNC-PROOF-001`.

The sequential argument preserves the synchronous `Machine` transition order
inside one owned `Send + 'static` root driver. The concurrent argument preserves
that per-task order while allowing independently scheduled siblings, all-settled
joins, detach ownership, cancellation and drain, and distinct foreground and
terminal coordinates. The durable argument preserves one coherent committed cut
across those coordinates and permits replacement physical submissions only after
fenced reconstruction and complete runnable-set admission.

## Assumptions and proof boundaries

The executor is weakly fair for continuously runnable Gantry tasks. Ready host
futures are eventually observable, while genuinely pending integration work has
no wall-clock completion guarantee. Hook, executor, journal, and event services
obey their published panic and failure boundaries. Admission and must-settle
ownership use the bounded classes defined by the embedding contract.

The finite models are not unbounded proofs over all programs, task graphs,
prefix lengths, adapters, or schedules. They do not assume deterministic sibling
order, equal CPU allocation, bounded scheduling latency, or exactly-once physical
executor submission.

## Composed refinement

1. Accepted work is published once, submitted behind a closed gate, registered
   with supervision, and then allowed to make source progress. Semantic task
   settlement is distinct from later physical executor settlement, and capacity
   remains owned until physical reaping.
2. Each task runs the same explicit-frame `Machine`; scheduling can interleave
   siblings but cannot reorder one task's transitions. Join and detach consume
   source handles linearly, joins wait for all selected tasks, and result or
   failure ordering follows source/declaration order rather than completion order.
3. Cancellation fixes an ownership-scoped target set, prevents later source
   consumption by affected tasks, drains attached descendants, and does not
   rewrite unrelated sibling or detached outcomes. Foreground and terminal
   coordinates are monotonic and terminal additionally waits for detached work.
4. Durable stage-commit-publish installs only committed successors. Recovery
   validates one authoritative full or snapshot-plus-suffix cut, acquires a new
   owner epoch, reconstructs the complete bounded graph, admits and registers the
   runnable set behind closed gates, and only then releases replacement work.
5. Replacement submission may increase a physical submission count for an
   unfinished logical task. Stable task, handle, operation, event, result,
   settlement, foreground, and terminal identities and transitions remain
   exactly-once logically. A superseded owner cannot publish after fencing.

## Requirement and evidence mapping

`protocol/conformance/async-execution-refinement-v1.json` copies the seven exact
requirement rows assigned to `GNT-ASYNC-PROOF-001`. Its capabilities link the
three bounded model checks and representative executable evidence for root-driver
ownership, all-settled joins, cancellation/drain, coherent durable cuts, complete
recovered admission, stale-owner fencing, and worker-policy-independent resume.

Detailed implementation ownership remains in the linked issue manifests. This
argument establishes their composed refinement boundary; it does not broaden a
focused model into a complete release or platform claim.

## Counterexample classes

The sequential companion model rejects source progress before registration or
gate release, permit release before physical settlement, duplicate physical
observation, semantic outcome rewrite, and observer-drop abandonment. The
concurrent model rejects duplicate or conflicting handle disposition, settlement
before required drain, source progress after cancellation, premature foreground
or terminal completion, and schedule-dependent target rewriting. The durable
companion model additionally rejects incomplete recovered-graph admission,
premature gate opening, stale-owner publication, and duplicate logical creation,
ownership, result, settlement, foreground, or terminal commits.
