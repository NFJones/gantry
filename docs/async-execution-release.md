# Executor-backed async execution publication

The checked-in seven-artifact publication is the amended Gantry v1 baseline
for executor-backed source execution. Its immutable identity is the
`publication_revision` in
[`protocol/publication/index-v1.json`](../protocol/publication/index-v1.json),
and the independent digest report is
[`protocol/publication/verification-v1.json`](../protocol/publication/verification-v1.json).
The publication bundles the current specification, protocol catalogs and
schemas, goldens, requirement ledger, conformance evidence, and public
authoring material; no file under `docs/reference/` is a publication input.

Publication assembly is not release adoption. The adoption gate remains
blocked only by `GNT-ASYNC-REL-001`, which owns the clean release matrix,
platform qualification, final profile advertisement, and sign-off. Until that
gate closes, the public facade reports no advertised profiles. In particular,
the assembled set does not claim a hosted macOS release environment and does
not claim stable-media power-loss qualification for the SQLite adapter.

## Embedding migration

The amendment replaces the pre-async manual-driving draft in place; there is
no compatibility mode that restores caller polling of a root `Machine`.
Embeddings migrate as follows:

1. Supply an executor-neutral `ExecutorAdapter` through interpreter
   configuration. The embedding owns the executor and its shutdown; Gantry
   owns interpreter lifecycle, task supervision, cancellation, and semantic
   transitions.
2. Start or resume through the asynchronous lifecycle API. A successful
   request transfers accepted root work to the configured executor and returns
   an execution handle; callers await outcomes, query state, cancel, or invoke
   orderly shutdown rather than manually advancing interpreter steps.
3. Provide bounded blocking-work capacity separately from async executor
   workers. Package I/O, analysis, and SQLite journal work do not become
   unbounded executor tasks.
4. Treat the CLI policy as an integration choice: `gantry run` owns a
   multithread Tokio runtime and accepts a positive `--workers` value, while
   the library never constructs a hidden runtime.

See [`parallel-execution.md`](parallel-execution.md) for source task ownership
and the embedding execution model, [`cli-runtime-policy.md`](cli-runtime-policy.md)
for CLI runtime ownership, and
[`executor-backed-recovery.md`](executor-backed-recovery.md) for recovered
graph submission and fencing.

## Durable compatibility

The executor-backed baseline does not migrate durable artifacts from the
superseded pre-async draft. Resume uses the retained current-version protocol,
configuration, canonical IR, source-map, and recovery-projection identities.
Candidate source is only a compatibility audit and must lower to the recorded
canonical IR identity; source-free resume reconstructs the retained closed
projection without restoring manual driving or rerunning source-level
analysis. An incompatible or malformed retained artifact is rejected before
recovered source execution and must not be rewritten as if it belonged to the
current baseline.

The reference SQLite adapter documents process-restart evidence and effective
durability settings in
[`sqlite-journal-storage.md`](sqlite-journal-storage.md). Those checks are not
evidence of power-loss survival on stable media. Hosted macOS validation and
any stable-media qualification remain explicit release evidence for
`GNT-ASYNC-REL-001`, not conclusions inferred from publication assembly.
