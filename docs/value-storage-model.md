# Value storage model

This note publishes the contract that `GNT-GP-VALUE-PERF-001` must satisfy while it introduces
shared or persistent value representations: the declared strategy vocabulary and the equivalence
contract of `GNT-35.11-storage-strategy-equivalence-and-round-trips`, the accounting vocabulary its
representations must preserve from Section 28, and the obligations this issue's own plan adds on top
of them. It grants nothing: the normative text is `SPEC.md`.

## Declared storage strategies

`crates/gantry-ir/src/scalar.rs` declares the closed physical-strategy vocabulary `StorageStrategy`
with exactly three members, published by `StorageStrategy::ALL` and spelled by `as_str`: `eager-copy`
(`StorageStrategy::EagerCopy`), `copy-on-write` (`StorageStrategy::CopyOnWrite`), and `reuse`
(`StorageStrategy::Reuse`). The clause spells the third member `storage-reuse`; the model's `reuse`
is that strategy.

Physical work is nonsemantic: `duplication_work` publishes the octets a strategy copies on
duplication and `write_work` publishes the octets it copies on a write that follows an alias;
`ByteBufferValue::physical_work` accumulates them, and no source program observes the result. The
semantic layer of a buffer is `ScalarQuota`: `charged`, `reserve`, and `release` publish the
charge, and every strategy carries the identical quota state.

## The equivalence contract (`GNT-35.11`)

The clause requires that eager-copy, copy-on-write, and storage-reuse implementations of these values
produce identical octets, identical quota charges, identical refusals, and identical canonical text
for the same operation sequence; physical work differs and is nonsemantic, so no observable behavior
may depend on it, and any divergence is refused under the `scalar-storage-strategy-divergence`
diagnostic, whose owning clause is `GNT-35.11`. Canonical text, external encodings, and recovery
projections round-trip exactly, and a projection that loses an octet, a width, or an identity is
refused rather than repaired.

## Accounting vocabulary preserved from Section 28

`GNT-28.2-logical-measures-and-representation-equivalence`: the closed logical measure vocabulary is
bytes, handles, and operations; a quota charges the declared logical measure and not allocation size,
pointer width, compression, encoding, cache layout, address, or another physical representation; two
representations with the same declared logical charge vector are accounting-equivalent and two
different vectors are not made equivalent by their representation; an implementation must not derive
a measure from host allocation behavior or silently exchange one measure for another.

`GNT-28.5-closed-quota-families-and-owners`: quota families are exactly bytes, handles, and
operations, mapped respectively to the same-named logical measures; quota owners are exactly
resource, owner, and durable-record; a quota key is one owner-family and quota-family pair, and
duplicate keys, unknown keys, and a charge against an undeclared key are refused rather than selected
by input order or defaulted; no quota family or owner is inferred from a host, an adapter, a task, a
journal, or a runtime configuration.

## Obligations this issue adds

These are requirements of `GNT-GP-VALUE-PERF-001` itself and not clause text: a value's release points
must be preserved exactly through moves, loans, captures, tasks, channels, replacement, scope exit,
pending operations, cancellation, and restart; the live-value budget stays separate from journals,
artifacts, transcripts, events, caches, adapter records, and physical storage; and representative
workloads must not regress into accidental quadratic copying.

## Non-claims

This note publishes no allocation identity, no reference count, no collector phase or timing, no
physical reclamation schedule, no sharing layout, no cache state, and no address as portable
behavior; it publishes no new diagnostic, no quota family, and no change to any value contract.
