# SQLite journal storage

`gantry-storage-sqlite` is Gantry's reference local implementation of the
backend-neutral `JournalStorage` contract. SQLite tables, error details, and
locking choices are private adapter behavior; portable journal semantics remain
defined by `SPEC.md` and the public host contracts.

## Ownership and fencing

Before advancing any journal generation, the adapter acquires two database-wide
liveness guards:

1. a process-local registry entry keyed by the opened database's device and
   inode; and
2. a nonblocking exclusive `flock` on a stable adjacent
   `.gantry-owner.lock` descriptor.

The sidecar is opened with no symlink following, must be a regular file, and is
never unlinked or replaced by the adapter. The descriptor and process registry
entry remain held while the store has active journal owners. Ownership tokens
remain journal-local: acquisition transactionally advances the journal's
generation, and every commit verifies both the in-process active token and the
persisted current token. Orderly release first invalidates the persisted token
and only then drops the journal's active lease. A process death closes the
sidecar descriptor; a later process can acquire the lock, advance the
generation, and fence the stale token.

## Effective database settings

Every opened worker connection selects the locked bundled SQLite engine and the
`unix` VFS on Linux and macOS. Startup sets and reads back:

- SQLite `3.53.2`;
- rollback `journal_mode=DELETE`;
- `synchronous=EXTRA` (numeric readback `3`);
- `fullfsync=ON` on macOS and `OFF` elsewhere;
- extension loading disabled;
- defensive mode enabled and trusted-schema evaluation disabled; and
- memory mapping and auxiliary SQLite worker threads disabled.

An engine, VFS, pragma, schema, or defensive-setting mismatch fails closed.
The adapter identifies the database filesystem for evidence and policy, but a
filesystem name alone is not a durability proof.

## Current evidence and claim boundary

The public conformance suite verifies the common atomic fenced-store contract,
same-process and cross-process owner exclusion, stable sidecar identity,
transactional release ordering, stale-token rejection, process-death lock
reclamation, and recovery of a committed prefix in a fresh process. It also
checks all effective settings listed above.

The current repository does **not** contain a test VFS or equivalent filesystem
shim capable of demonstrating short writes, torn writes, database-file sync
failure, or rollback-journal directory-sync failure. Consequently every
environment reports `power_loss_qualified = false`; configuration that requires
that qualification is rejected with `sqlite-unsupported-environment`.
Transaction and restart tests must not be presented as power-loss evidence.
The durable-profile release gate remains blocked on a platform-specific fault
matrix that records the SQLite engine, VFS, filesystem, and flush behavior for
each qualified environment.
