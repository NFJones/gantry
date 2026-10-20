# The bounded `std.observe` telemetry contract

This note records the first bounded normative telemetry policy and admission slice of `SPEC.md`
Section 48, clauses `GNT-48.2` through `GNT-48.9`. It distinguishes the declarations from the
implementation: the repository now declares typed log, metric, and trace records, explicit context,
immutable per-sink finite limits, atomic admission, destination-specific release, required versus
best-effort delivery, bounded backpressure, cancellation, shutdown accounting, and sink-fault
containment. It does not ship a telemetry sink, adapter, queue, background task, durable record, or
runtime availability claim.

The pure model is `crates/gantry-ir/src/telemetry.rs` and the exact evidence lane is
`crates/gantry-conformance/tests/telemetry_policy.rs`. Every decision is a deterministic function
of explicit records, policies, grants, releases, and sink accounting state. No test reads a clock,
process, thread, environment, host path, or live handle.

## Typed records and explicit context

`TelemetryRecordKind` declares exactly `log`, `metric`, and `trace`. A log carries an ordinary
message; a metric carries a signed or unsigned integer and an optional ordinary unit; a trace
carries a nanosecond duration and one status from `ok`, `error`, or `unset`. Every record also
carries an ordinary name, an ordered field list, an ordered label list, one explicit context, and
zero or more protected references. Fields and labels sort by name and refuse duplicates. Names are
nonempty ASCII without whitespace or controls and within `TELEMETRY_NAME_LIMIT`; ordinary text
rejects Unicode control characters as well as ASCII controls.

`TelemetryContext` is exactly its declared entry list. There is no ambient, task, thread, process,
environment, locale, or global context, and no global record sequence. The caller declares the
record sequence explicitly. A record is never a Section 12 event and is never semantic evidence.

## Immutable per-sink finite limits

`TelemetrySinkPolicy` binds one ordinary sink identity, one delivery class, one `TelemetryLimits`
value, one optional destination release, and one finite positive wait bound. It has no setter, no
configuration fallback, and no implicit default. Absent policy refuses `telemetry-policy-absent`.
One `TelemetrySinkState` binds one sink identity and one policy; a later policy that differs in
sink, delivery class, limits, release, or wait bound refuses `telemetry-policy-mismatch` without
mutating the state. Each state creates a fresh unforgeable issuing authority; the declared instance
name is diagnostic metadata, not settlement authority.

`TelemetryLimitSet` requires all thirteen declarations. `TelemetryLimits` accepts only finite
values; an `Unlimited` declaration refuses `telemetry-unlimited-policy`. A finite zero is a
declared denial of that dimension, never an unbounded or default value.

| Dimension | Declared bound |
| --- | --- |
| record | maximum record material bytes |
| field | maximum field count and maximum field bytes |
| label | maximum label count and maximum label bytes |
| context | maximum context depth and maximum context bytes |
| cardinality | maximum active series |
| queue | maximum best-effort queue depth |
| retention | maximum retained records |
| pending emit | maximum unsettled emits |
| shutdown | maximum drain bound and maximum timeout in microseconds |

`TelemetryEmitGrant` admits an emit attempt only. It is not a release grant, never satisfies a
destination release, and never declassifies protected data.

## Atomic admission and no hidden eviction

`TelemetrySinkState::admit` runs one declared check order: poison, shutdown, policy presence, emit
grant, record bytes, field count and bytes, label count and bytes, context depth and bytes,
protected destination release, active-series cardinality, then delivery class. A refusal leaves the
queue, pending emits, retention, active-series set, drop count, and every settlement count exactly
unchanged. Over-bound records refuse rather than truncating, rewriting, or adding an overflow
label. Cardinality and retention refuse rather than evicting an older entry.

A required emit at its pending bound returns the bounded backpressure descriptor. A best-effort
emit at its queue or pending bound drops the newest whole record and increments one bounded drop
count. Queued is not delivered.

## Protected values and destination release

A protected value is never a label, record name, field or context value, series identity, sink
identity, receipt, or fault identity. `TelemetryProtectedReference` carries only the canonical
protected-value identity and declared class; it carries no payload byte or payload-derived digest.

Before export queueing, every reference must be covered by `TelemetryDestinationRelease` for this
exact sink and class, using the `GNT-15.10-release-operation` null telemetry destination and its
accepted `ReleaseProjection`. A projection naming another class refuses
`telemetry-release-class-mismatch`; a missing release refuses `telemetry-release-required`;
another sink's release refuses `telemetry-release-destination-mismatch`; an undeclared class refuses
`telemetry-release-class-not-declared`. The release check precedes series, queue, pending, and drop
mutation.

A telemetry grant or operation authority never substitutes for release, and a telemetry-destination
release never declassifies. The reference stays protected, no ordinary conversion exists, and a
further destination is a new Section 15.10 release.

## Required and best-effort delivery

Required delivery completes only at one declared sink acknowledgement. Admission and enqueue are
pending, not delivery. Best-effort admission reports `queued` or `dropped`; queued is not delivered.
`acknowledged`, `cancelled`, `ambiguous`, and `failed` are distinct terminal settlements.
`TelemetryEmit` is affine and is consumed by exactly one settlement, so no emit is settled twice.
An emit is bound to the issuing state's unforgeable authority, not a declared name. An independently
constructed state with the same declared instance name, a recreated state, or any other foreign
state refuses `telemetry-invalid-settlement` and returns the unsettled emit. A live accounting state
is not cloneable; `snapshot()` returns an immutable comparison view with no settlement authority. An
emit presented after aggregate shutdown settlement refuses `telemetry-shutdown-already-settled`. An
ambiguous write is terminal and is never silently retried. No settlement carries a business,
task, execution, or Section 12 outcome, and a delivery failure never rewrites a fixed outcome.

## Backpressure, cancellation, and shutdown

Required backpressure is bounded by the policy's finite positive wait bound and never blocks
unboundedly. Accepted cancellation settles once through the affine emit. `begin_shutdown` stops new
admissions and retentions and returns a `TelemetryShutdownPlan` with the pending emits, finite drain
bound, finite timeout, and whether the pending set fits the bound. `settle_shutdown` reports drained
and abandoned counts and never silently discards a pending emit. The declared drain bound is enforced
for the aggregate settlement and for each terminal emit settlement during shutdown; an over-budget
settlement refuses `telemetry-invalid-settlement` or `telemetry-backpressure-bound`, and a zero
drain bound abandons all pending emits at aggregate settlement. The application owns the actual drain
and flush; the model declares and accounts the bound only.

## Sink faults

A fault poisons that exact sink instance only. Later admissions and retentions on it refuse
`telemetry-sink-poisoned`; other sinks are unaffected. A fault report naming another sink refuses
`telemetry-sink-mismatch` without poisoning this instance. `TelemetrySinkFault` names the sink and one
closed class of `panic`, `error`, or `protocol`, carries no payload or backtrace, and returns fixed
redacted detail. It is not a telemetry record and cannot be recursively logged through the sink it
describes. Poisoning is not repair, eviction, reuse, or a delivery-policy change.

## Evidence separation and non-claims

Telemetry is never Section 12 semantic evidence, durable evidence, a business result, or proof that
an operation occurred. Section 12 events remain the only semantic evidence, and telemetry may be
sampled or dropped without changing a source-visible outcome.

This slice declares no telemetry sink, adapter, host trait, capability grant, queue implementation,
retention store, background task, timer, wire schema, durable record, cross-sink ordering,
exactly-once delivery, source-global context or sequence, or runtime availability. Stable module
compatibility is not stable-edition status or runtime availability. It changes no Section 12 or
Section 15 rule and claims no performance, storage layout, or physical representation.
