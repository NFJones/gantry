# Live-resource carrier and executable-ABI design record

Status: accepted design record for `GNT-GP-RESOURCE-RUNTIME-001` (`b87d011f`), first slice. The
governing consensus is `governance/issue-resolution-decisions-v1.md` D3 (source-resource identity,
ownership, and restart) and D4 (common I/O and dependency-ready consumers), with D10 for
validation and disposition. This record decides designs and boundaries. It adds no normative
specification text, admits no source handle, publishes no adapter, and asserts no qualification
verdict.

This record is deliberately narrower than the issue. It settles the carrier shape and the
executable-ABI arrangements D3 requires, records which landed runtime machinery is reused for
them, and states the explicit boundary the delivered slice keeps. Everything it defers is named
with its owning surface at the end.

## 1. What already exists and is not redesigned here

The runtime already owns the accounting, physical, lease, and cleanup machinery this design
builds on, and none of it is reimplemented or described as absent:

- Section 28 accounting admission publishes `ResourceLedger`, `DurableResourceRecord`,
  `ResourceSubjectBinding`, `LivenessRoot`, `ResourceCarrier::ReconstructionRecord`, and
  `admit_resource_carrier` through `ResourceRegistry` and `AdmittedResource`
  (`GNT-28.7-durable-resource-reconstruction`, `GNT-28.10-resource-accounting-non-claims`).
- Two distinct landed transports exist and must not be conflated. The caller-bound transport is
  `OwnedHostResource<T>`: it owns one `AdmittedResource` handle and one physical value, is created
  by `OwnedHostResource::bind`/`bind_with_charges`, invoked through `invoke`/`invoke_with_charges`,
  finalized by `finish`, and disposes its value when dropped. The registry-owned physical slot is
  separate: `ResourceRegistry::attach_host_value` installs a `HostValueSlot` inside the registry,
  presence and quiescence are inspected through `has_host_value` and `host_values_are_quiescent`,
  and extraction yields a contained `HostDisposalJob` rather than a borrow route back to the
  caller. Neither carries accounting facts: the account carries no host value.
- The exclusive receiver loan is `HostReceiverLoan`, acquired by `borrow_receiver`,
  `borrow_receiver_with_charges`, or `borrow_receiver_from_pending`, observed by `observe`,
  invoked by `invoke`, and settled by `settle` or `settle_failure`. Abandoning an unsettled loan
  fences reuse (transport poisoning) without fabricating a model settlement.
- Serviced off-worker cleanup is `ResourceCleanupObserver` over
  `submit_settled_resource_cleanup`, `submit_emergency_resource_cleanup`, and
  `submit_task_resource_cleanup`, with `ResourcePhysicalCleanupResults` reporting independent
  per-resource outcomes. It operates on registry-attached values through the coordinator, so it
  applies to the registry-owned slot and not to a caller-bound transport that was never attached.
- Section 20 pins the model: `OperationKind` (`ValueAction`, `ProtectedOperation`,
  `LiveResource`), `ReceiverOwnership` (`BorrowedLoan`, `TransferredIn`, `RetainedByCaller`),
  `LoanId::seal`, `LiveResource::{observe,settle,settle_failure,half_close,fence,interrupt}`,
  `OperationSettlement`, `PostFailureSettlement`, `ExternalOutcome`, `ProgressObservation`,
  `ProgressRecord`, and `ObservationAllowance`.
- Section 20 kind carriage is landed: `ExecutableOperation.section20_kind` and the retained
  `GNTPRG05` wire round-trip an analyzer-authenticated kind
  (`docs/operation-kind-carriage.md`). The machine derives each resource subject from that
  decoded metadata, and `GNT-6.2j` declares the `live_resource struct` classification.
- Existing live-resource transport refusals are preserved and are not relaxed by this design:
  the machine aggregation refusal `unsupported-live-resource-transport`, and the entry-input
  refusal `live-resource-entry-value-refused` for an analyzed stored-member class that is live.

## 2. Carrier design (D3)

### 2.1 One unclonable, process-local carrier backed by a registry-owned slot

A live resource is carried by exactly one unclonable, process-local machine value whose
existence and identity are bound to one registry-owned physical slot:

- The carrier is not a `LogicalValue`, not JSON, not raw hook bytes, not a prompt field, and not
  the body of any checkpoint or reconstruction record. `AdmittedResource::durable_record()`
  carries accounting facts only, and the `GNTPRG05` retained program carries metadata only.
- The registry slot is the only owner of the physical value. The carrier names its subject
  (operation identity, resource generation, site), the owner generation that currently holds it,
  and the declared receiver arrangement; it never names a host resource, a descriptor, a path, or
  a slot index.
- Authentication of a carrier requires the declaration and type, the issuing subject, the
  current owner generation and task, and the registry association to agree. Any disagreement is a
  refusal, not a repair.
- Existing guards stay in force: `OwnedHostResource::bind` refuses an inactive or non-open
  account, an unreadable admission lease, and a cancelled admission; `LiveResource::observe`
  refuses a fenced, settled, non-open, or exhausted-allowance observation; `LiveResource::settle`
  accepts one settlement of one generation only.
- Dedicated carrier admission, completion, and storage paths are added; the ordinary value,
  aggregate, capture, and durable paths are never widened to reach a carrier.

### 2.2 Declaration form: `affine live_resource struct`

The selected declaration form is `affine live_resource struct`, with the modifiers in that exact
order. `GNT-6.2j` currently states that a declaration naming `live_resource` together with
`affine` names two modifiers and MUST be rejected at syntax time, so this selection is not yet
normative and requires an explicit reviewed specification revision. That revision must decide,
as one reviewed unit:

1. the exact modifier order `affine live_resource` and its grammar production, admitting no other
   order, alias, or spelling;
2. the three independent seeds of the declaration: the `AffineDroppable` ownership class already
   defined by the `affine struct` clause, the `LiveResource` resource class already defined by
   `GNT-6.2j`, and one new declaration-level fact that ordinary recovery is unavailable for the
   declared type;
3. that bare `live_resource struct` keeps its current meaning exactly: classification only, with
   no ownership, cleanup, or transfer contract, and no admission at any boundary;
4. that a source field literal cannot forge a carrier and an ordinary copy cannot duplicate one,
   enforced through the existing ownership rules plus one live-resource-specific refusal.

The unavailable-ordinary-recovery seed is the one genuinely new semantic fact. It is what makes
an ordinary snapshot, restore, or value reconstruction of a carrier a refusal rather than a
silent reconstruction of something that cannot exist. It must be authored by the specification
owner, not inferred by the runtime from the classification or from a family declaration.

### 2.3 Authority is the exact requirement binding

Authority to perform a live-resource operation is the exact abstract requirement, signature,
family, and recovery class bound to a selected current capability, together with the capability
lineage, its current rights, the target and mode it is exercised in, and the current revocation
state. A type, a carrier, a registry key, or a descriptor grants nothing. Naming a resource is not
using it, and holding a carrier is not holding permission.

Consequently the runtime performs no authority derivation of its own. It reads the authority facts
the boundary presents, refuses when any of them is absent or contradictory, and never widens a
right because a carrier, a slot, or an adapter happened to be available.

### 2.4 Ownership moves, loans, and captures

The one atomic move commits, in one step: the source place, the destination place, the successor
owner generation, the cleanup-responsible task, and the whole explicit charge vector. Refusal
preserves every one of them, which is the landed behaviour of
`OwnedHostResource::transfer_with_charges` over `AdmittedResource::transfer_owner_with_charges`.

Receiver loans are exclusive, sealed to the declaration, site, and generation by `LoanId::seal`,
end at settlement, and cannot escape the operation that holds them. A loan is never a transfer of
ownership, and a loan of another site or generation is refused rather than reinterpreted.

Aggregates and closure captures store carriers through carrier-aware affine storage: a stored
member whose declared type is live makes the enclosing stored aggregate live by the existing
`GNT-6.2j` fold, mutation follows `FnMut` and consumption follows `FnOnce`, and a copy capture of
a carrier is never produced. The capture modes of `GNT-37.3-explicit-captures-and-capture-plans`
apply unchanged: a moved carrier is consumed, and a loaned carrier must not escape the statement
that declared it.

### 2.5 Task transfer (deferred, with eligibility decided)

Same-task transport comes first and is the only transport this record authorizes. A later explicit
same-execution task move uses its own owned-move eligibility, not `IsolatedTaskCapture`, and must
satisfy all of: both tasks eligible and uncancelled, the same execution, running tasks, no
outstanding receiver loan, no accepted pending work, and no unsettled containment. Settled
historical containment evidence remains valid evidence afterwards and is not invalidated by the
move. A bound adapter is refused until a governed rebind contract exists; an implementation may
not silently rebind a moved carrier.

## 3. Executable-ABI arrangements (D3, D4)

### 3.1 Receiver, input, and output authentication

The executable ABI authenticates the receiver arrangement, the inputs, and the outputs of every
operation that reaches a live resource. The decisive fact is that a live receiver makes
`read(handle) -> bytes` a live-resource operation even though its result contains no handle.
Therefore:

- result-only inference is insufficient, and a name, a convention, or an adapter behaviour is
  never evidence of a live-resource operation;
- contradictory or missing receiver, input, or output metadata fails preflight and fails retained
  decode, rather than defaulting to a value action;
- the authenticated Section 20 kind is read from the retained metadata, so the ABI facts and the
  carried kind cannot disagree silently.

Inputs and outputs are declared per operation: an input receiver loan carries a bounded request
and yields bytes or an error; an output receiver loan carries initialized octets and yields an
accepted-prefix receipt or an error; a flush carries no octet quantity. The exact family signature
rows stay with their owning family clauses (Sections 46 and 47 and the D5 console selection);
this record only fixes that the ABI must authenticate the arrangement, and that the accepted
prefix, not the requested quantity, is the output fact.

### 3.2 Cancellation, completion, and cleanup precedence

One completion and one cancellation can race. The settlement rule is stated once, so no caller has
to infer precedence:

- The admission lease is rechecked once, after the call returns and before any observation or
  settlement. That instant is the single linearization point of the race.
- A cancellation observed there withholds publication of octets and settles the attempt as
  cancelled with an ambiguous external outcome. Known accepted octets stay retained as protected
  evidence, and any not-ready witness the completion established is kept.
- Cancellation never erases a fault the completion established. A malformed length, a
  request-mismatched completion, a family refusal, or a protected native diagnostic keeps its own
  distinct fault kind, and the cancellation is recorded as an additional settlement fact.
- A completion of another operation, generation, owner, kind, or quantity is contained as a foreign
  completion whether or not cancellation was also observed.
- A lease that is closed by other accepted work, or unreadable, is a contained operational failure,
  not a cancellation. No cancellation fact is invented from a lease state that is not one.

### 3.3 Cleanup and recovery

Every live resource has one authoritative predecessor and one cleanup obligation:

- Cancellation or outcome and the cleanup obligation are committed before the operation is
  exposed or its physical ownership is disposed.
- Accepted work retains its lease until exactly one settlement winner exists. A second completion,
  a late completion, or a completion by another owner generation or generation cannot refund,
  release, or publish twice.
- Ordinary finish is one committed Begin, one owned off-worker finalization, and one validated
  completion. Off-worker finalization reuses the bounded blocking-work service and the landed
  cleanup observer rather than spawning an unbounded task.
- The emergency semantic disposition and the physical cleanup outcome are distinct facts: the
  former is the recorded semantic decision, the latter is the per-resource physical result.
- An indeterminate submission fences publication and redispatch until authoritative recovery
  resolves it; it is not retried optimistically.
- Dropping a carrier, dropping an observer, process exit, and a missing slot are not finish
  evidence.
- No exactly-once external destruction claim is made across a crash without family-specific
  proof.

## 4. Explicit boundary

- There is no v1 physical-handle resurrection. A durable record, an accounting state, or a
  reconstructed account never recreates a physical slot, a source cell, an adapter binding, or an
  accepted-work lease.
- Accounting recovery is not physical restoration. Reconstructing accounting facts says what was
  owed, not what still exists.
- A later family-declared immutable-content or committed-snapshot descriptor may permit fresh,
  all-or-none host reacquisition after current identity, authority, retention, target, and
  revocation validation. That is a new operation and a new physical generation, not the
  continuation of an old carrier or lease.
- The following stay ineligible for any carrier form in v1: mutable files and cursors, locks,
  watchers, sockets and TLS sessions, process pipes, the console and the native working
  directory, mutable buffers, and pending I/O. A path, digest, or receipt is not bearer
  authority.

## 5. What the first delivered slice implements

The delivered slice is the bounded settlement service in
`crates/gantry-runtime/src/io_settlement.rs`, with its unit lanes and the external conformance
lane `crates/gantry-conformance/tests/io_settlement_contract.rs`. It reuses, rather than
restates:

- the landed `IoRequest`, `IoOutcome`, `IoError`, and the 1,048,576-octet bound of
  `GNT-45.1-bounded-one-call-io-contract`;
- `borrow_receiver_from_pending` for the exclusive loan, its whole charge vector, and its
  cancellation and pending checks;
- `HostReceiverLoan::{observe,settle}` and `OperationSettlement` for the one settlement, its
  progress record, its external outcome, and the model-derived resource state;
- the machine-issued admission lease for the two admission rechecks that make the completion and
  cancellation race deterministic;
- the caller-bound `OwnedHostResource` transport for physical ownership, so the accepted octets
  survive loss of every observer of the attempt while the binding remains the physical owner;
- the model `ReadinessObservation` of `GNT-24.1-atomic-registration-and-readiness-recheck` for the
  blocked settlement fact.

Retention and cleanup boundary. This slice drives the caller-bound transport and therefore does
not claim registry-owned retention: discarding the binding disposes the endpoint, and registry
attachment plus off-worker physical cleanup of a discarded binding belong to the consumer slice
that also records the durable cleanup cut. What this slice does guarantee is that losing the
settlement service or any outcome keeps the accepted octets and the machine-issued admission
lease, because neither is owned by the attempt.

It adds no source handle, no adapter, no family integration, no durable cleanup cut, and no task
transfer. It does not edit `SPEC.md`, and it does not declare `affine live_resource struct` in any
source form.

## 6. Deferred work and owning surfaces

| Deferred item | Owning surface |
| --- | --- |
| `affine live_resource struct` declaration and its three seeds | reviewed `SPEC.md` revision, then the source frontend |
| Source live handles of any family | family issues after the carrier revision |
| Host family integration (FS `ed0e707c`, ENV `c8717957`, APP `3e1d6f75`) | those issues, consuming this carrier and the D4 settlement service |
| Durable cleanup cuts and journal receipts for cleanup obligations | durable/recovery owners under D3 |
| Same-execution task transfer and adapter rebind | a later slice with its own reviewed eligibility |
| Output and flush signatures, terminal inspection, mode control | CONSOLE `aee7225a` under D5 |
| Seek and cursor mutation | a later decision; cursor state is ineligible in v1 |

## 7. Risks and open questions

- The unavailable-ordinary-recovery seed is new semantics. If the reviewed revision chooses to
  derive it from the ownership class alone, the carrier design must be re-reviewed for the
  consequence that a bare classified type would also become non-recoverable.
- The settlement service publishes one settlement per loan, so a later call needs a new admitted
  occurrence: a closed loan root is never reopened by this slice. A blocked caller that wants a
  second attempt must therefore obtain a new occurrence rather than rely on the same account.
- Whether the two admission rechecks are enough to express interruption at a family-defined safe
  point is a Section 45 question, not a settlement-service question; this record does not claim a
  cancel-safe-point discipline.
