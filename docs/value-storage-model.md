# Value storage model

This note publishes the storage contract that `GNT-GP-VALUE-PERF-001` must satisfy while it
introduces shared or persistent value representations. It grants nothing: the normative text is
`SPEC.md`, and every anchor below is declared there.

## Declared storage strategies

`crates/gantry-ir/src/scalar.rs` declares the closed physical-strategy vocabulary
`StorageStrategy` with exactly three members, spelled by `StorageStrategy::ALL` and
`as_str`:

| Strategy | Spelling | Duplication work | Write-after-alias work |
| --- | --- | --- | --- |
| `StorageStrategy::EagerCopy` | `eager-copy` | copies the value's octets | none |
| `StorageStrategy::CopyOnWrite` | `copy-on-write` | none | copies the value's octets |
| `StorageStrategy::Reuse` | `reuse` | none | none |

Physical work is nonsemantic: `duplication_work` and `write_work` publish the octets a strategy
copies on duplication and on a write that follows an alias, and no source program observes either.

## Nonsemantic physical work and semantic charges

The model separates the two layers exactly as the specification does (`GNT-35.11`):

- `ByteBufferValue` carries a declared `StorageStrategy`, its octets, an `aliased` flag, and a
  physical-work counter; `strategy`, `octets`, `len`, `is_empty`, and `alias` publish that
  physical state.
- `ScalarQuota` is the semantic layer: `charged` and `reserve` publish the charge, and every
  strategy carries the identical quota state, so charges and refusals do not depend on the
  storage strategy. A strategy divergence that a source program could observe is refused under
  `scalar-storage-strategy-divergence`, whose owning clause is `GNT-35.11`.

The specification anchors for that separation are `GNT-28.2-logical-measures-and-representation-equivalence`
(logical measures and representation equivalence: valid representations of one value agree on every
logical measure and on every release point) and `GNT-28.5-closed-quota-families-and-owners` (each
quota family has one owner and one exhaustion category, and the live-value budget is independent of
physical storage).

## Budget separation

The live-value budget is separate from journals, artifacts, transcripts, events, caches, adapter
records, and physical storage; reclamation timing and collector or cache state are never
semantic. A value's release point is decided by the ownership contract (moves, loans, captures,
tasks, channels, replacement, scope exit, pending operations) and is identical for every valid
strategy, including across restart.

## Non-claims

This note publishes no allocation identity, no reference count, no collector phase or timing, no
physical reclamation schedule, no sharing layout, no cache state, and no address as portable
behavior; it publishes no new diagnostic, no quota family, and no change to any value contract. It
records a declared contract only, and the implementation slices that follow it must preserve every
logical measure, charge, refusal, and release point it names.
