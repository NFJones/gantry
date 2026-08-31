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

## Physical fault evidence and claim boundary

The public conformance suite verifies the common atomic fenced-store contract,
same-process and cross-process owner exclusion, stable sidecar identity,
transactional release ordering, stale-token rejection, process-death lock
reclamation, and recovery of a committed prefix in a fresh process. It also
checks all effective settings listed above.

The physical-fault matrix runs an isolated C subprocess compiled from the exact
bundled SQLite `3.53.2` amalgamation. Its `gantry-fault` VFS delegates ordinary
I/O and locking to SQLite's `unix` VFS while deterministically injecting one of
four commit-boundary failures:

- a reported partial database write, which SQLite must complete and commit;
- an unreported partial database write followed by immediate process death,
  which hot-journal recovery must roll back;
- a main-database `xSync` failure; and
- rollback-journal deletion followed by a synthetic directory-sync failure.

Every case reopens the database, runs `quick_check`, and requires the journal's
sequence and protected-payload rows to form exactly the complete old prefix or
the complete new prefix. The short-write case must produce the new prefix, and
the torn-write crash must recover the old prefix. The helper is a subprocess C
boundary because SQLite's VFS ABI is a C interface; all workspace Rust remains
under `unsafe_code = "forbid"`.

This deterministic matrix establishes the adapter's transaction and recovery
behavior under the four injected cuts. It does **not** establish that a
particular host filesystem, storage device, VFS implementation, or flush path
actually provides stable-media power-loss guarantees. Consequently current
environments still report `power_loss_qualified = false`; configuration that
requires qualification is rejected with `sqlite-unsupported-environment`.
Transaction, restart, and synthetic-fault tests must not be presented as a
host-environment power-loss claim. A future qualified environment must add a
platform record for the exact engine, VFS, filesystem, mount/storage behavior,
and flush evidence rather than changing this boundary by inference.
