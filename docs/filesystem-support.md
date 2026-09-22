# Filesystem support (`std.fs`)

`std.fs` is the capability-backed filesystem family of `GNT-34.1-canonical-hierarchy-and-package-names`.
`SPEC.md` Section 47 is its normative text - its scope clause is
`GNT-47.0-filesystem-foundation-scope`; this note is a reader's index to what the section declares
and what it deliberately does not. The section is a declaration contract: it creates no path value,
descriptor, adapter, capability grant, runtime availability, or machine behavior.

## Declared surface

- **Modules and applicability** (`GNT-47.1-filesystem-modules-and-item-rows`): `std.fs::action`,
  `std.fs::path`, and `std.fs::resource`, in that canonical order, at the stable tier, applicable to
  the application semantic mode over the library and binary target kinds.
- **Path values** (`GNT-47.2-filesystem-path-values`): one declared root plus 1..=256 declared
  segments; a path spelling is never authority; the reserved components `.` and `..` are refused
  under `fs-path-escape` and every other root, segment, or count refusal under `fs-path-invalid`; a
  refusal names a zero-based position within the declared value, and a count or root refusal names
  zero.
- **Whole-object actions** (`GNT-47.3-filesystem-action-values`): `create`, `read`, `replace`, and
  `remove`; a read is `read_only`, the other three are `non_idempotent`, and no deduplication is
  claimed.
- **Resource operations** (`GNT-47.4-filesystem-resource-operations`): `open`, `read`, `write`,
  `seek`, `flush`, `sync`, `truncate`, `close`, `lock`, and `watch`; a read, a write, and a seek each
  consume exactly one `GNT-45.1-bounded-one-call-io-contract` request and publish exactly the
  `GNT-45.3-io-progress-derivation` observation, a completed flush publishes `committed-progress`,
  and no other operation consumes a request or publishes progress.
- **Resource state** (`GNT-47.5-filesystem-resource-state`): the closed `GNT-28.4` lifetime
  vocabulary, one `GNT-20.2` generation and one `GNT-20.10` owner generation per admitted instance,
  `write` and `truncate` as the content-mutating pair, and the rule that an admitted instance is
  never carried in durable state.
- **Traversal** (`GNT-47.6-filesystem-traversal`): declared entry names in ascending Unicode
  scalar-value order, each checked against the declared segment domain and refused by its zero-based
  position; no entry bound, no link rule, and no observation of entry kind, size, or content.
- **Action grants** (`GNT-47.7-filesystem-action-grants`): a read-only grant refuses `create`,
  `replace`, and `remove`.
- **Link policy** (`GNT-47.8-filesystem-link-policy`): exactly one resolution per operation
  (`FS_RESOLUTION_COUNT`), a symbolic link, junction, or reparse point is never followed and is
  refused without publishing a diagnostic spelling of its own, and a traversal resolves nothing.
- **Replacement** (`GNT-47.9-filesystem-replacement`): exactly one declared outcome, published by
  `FsReplacementOutcome` with no spelling of its own; no staging and no partial object. This bullet
  counts success outcomes only: the refusals a replacement can meet stay with the clauses that
  declare them.
- **Declared limits** (`GNT-47.10-filesystem-declared-limits`): exactly three quantitative bounds —
  256 segments per path value, one `GNT-45.1` request for each of read, write, and seek, and one
  resolution per operation; the clause's silence is not a limit.
- **Case identity** (`GNT-47.11-filesystem-case-identity`): path-value identity is scalar-value
  sequence equality, exactly case-sensitive, never folded; a target's own case behaviour is a
  declared host fact and is never identity, a lookup key, a merge, a rename, or a substitution.
- **Operation refusals** (`GNT-47.12-filesystem-operation-refusals`): exactly two declared
  conditions — an unadmitted target state and a collision a folding target reports. The clause adds
  no third diagnostic spelling, no refusal position, count, or bound, and no refusal procedure.
- **Partial progress** (`GNT-47.13-filesystem-partial-progress-and-settlement`): a read and a write
  publish exactly the derived observation for the octets they committed, so a short transfer stays
  `short-read` or `short-write` progress and never becomes a completion, and a seek publishes exactly
  the derived observation for its declared target position and the position it observed; no remainder
  is carried, no retry is performed, and a following transfer is a new declared operation.
- **Durable carriers** (`GNT-47.14-filesystem-durable-carriers`): the declared reconstruction record
  of `GNT-28.7-durable-resource-reconstruction` is the one admissible carrier for an admitted
  instance; ordinary serialization and ordinary durable state are not records of this section.

## What the section does not declare

No descriptor, open handle, adapter, host trait, capability grant, runtime availability, snapshot,
receipt, quota, cancellation safe point, journal schema, or recovery procedure. The frozen
diagnostics of the section are exactly `fs-path-escape` and `fs-path-invalid`, both owned by
`GNT-47.2-filesystem-path-values`, and no other clause adds a spelling. The section claims no
performance, storage layout, or physical representation, and it neither narrows nor widens the
host contracts of `GNT-29.5-filesystem-and-environment-contracts`.
