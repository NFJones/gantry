# Runtime resource integration

This note is a reader index of the runtime surfaces that consume the declared resource, operation,
and containment contracts. It states what the runtime publishes, where each decision is decided, and
what the runtime does not claim.

Declared semantics belong to the model: the runtime selects an account, applies a fence, and reports
the model's own reason. Two things are runtime policy over declared facts rather than model
decisions - the registry's live-account ceiling and physical reclamation - and both are named as such
below. Where a clause owns a fence rather than the runtime policy that consumes it, this note says so.

## Registry surfaces

`ResourceRegistry::with_limits` optionally declares independent live-account and pending
resource-operation ceilings under `GNT-28.11-runtime-admission-mapping`. `pending_limit` and
`pending_operations` inspect the enabled pending policy. Pending places follow admitted machine
settlement leases: accepted completion, failure, and settled cancellation release them; refused
completion and a cancellation request alone retain them. Accounting lifetime settlement and
physical reclamation do not release still-pending work. Closed leases are pruned at successful
admission; poisoned leases conservatively retain capacity. Reconstruction does not recover this
process-local pending policy, and unadmitted evaluator work is outside its scope.

`ExecutionCoordinator::new_with_resource_limits` enables both ceilings in one shared registry;
cloned handles retain the same admission refusal and machine-settlement release boundaries.
The existing `new_with_resource_limit` constructor leaves the pending policy disabled.

| Surface | Runtime route | Decided by |
| --- | --- | --- |
| Admission | `new`, `admit` | `GNT-28.11-runtime-admission-mapping`, `GNT-28.7-durable-resource-reconstruction`, `GNT-20.1-operation-kinds` |
| Reconstruction | `reconstruct`, `RecoveredResourceRecord` | `GNT-28.7-durable-resource-reconstruction`, `GNT-20.10-retirement-and-stale-owner-fencing` |
| Capture | `declared_records` | `GNT-28.7-durable-resource-reconstruction` |
| Live-account ceiling | `with_live_limit`, `live_limit`, `live_resources` | Runtime policy over the lifetimes `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` declares; the model owns no ceiling |
| Physical reclamation | `reap_deleted` | Runtime policy that removes only accounts whose lifetime already reached the terminal retention state; the fences are `GNT-28.8-retention-and-compaction-fences` and `GNT-28.9-retirement-deletion-and-stale-owner-fences` |
| Quota charging and renewal | `charge`, `renew` | `GNT-28.3-atomic-copy-move-loan-update-and-release-charging`, `GNT-28.5-closed-quota-families-and-owners`, `GNT-28.6-bounded-renewal-and-exhaustion` |
| Two-phase finish | `begin_finish`, `complete_finalization` | `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` |
| Root closure, retirement, deletion | `close_liveness_root`, `retire`, `delete` | `GNT-28.1-resource-identity-and-closed-liveness-roots`, `GNT-28.8-retention-and-compaction-fences`, `GNT-28.9-retirement-deletion-and-stale-owner-fences` |
| Failure settlement | `settle_from_post_failure`, `settle_from_emergency_cleanup` | `GNT-20.7-resource-state-after-failure-and-poisoning`, `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` |
| Operation-state projection | `project_operation_state` | `GNT-28.12-operation-state-projection`, `GNT-20.5-interruption-cancellation-and-late-completion`, `GNT-20.10-retirement-and-stale-owner-fencing` |
| Cohort emergency cleanup | `settle_cohort_from_emergency_cleanup`, `CohortEmergencyCleanup`, `CohortEmergencySettlement` | `GNT-22.6-grace-expiry-and-hard-cancellation`, `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` |
| Containment settlement | `settle_containment` | `GNT-23.4-operation-ownership-and-single-settlement` |
| Adapter binding and poisoning | `bind_adapter_instance`, `adapter_instance`, `poison_adapter_instance` | `GNT-23.5-failed-instance-poisoning-and-isolation`, `GNT-20.11-adapter-obligations-and-diagnostics` |
| Adapter-failure settlement | `poison_adapter_from_post_failure` | `GNT-20.7-resource-state-after-failure-and-poisoning`, `GNT-23.5-failed-instance-poisoning-and-isolation`; caller supplies the classified poison reason |
| Inspection | `account` | `GNT-28.7-durable-resource-reconstruction` |

## Account surfaces

`OwnedHostResource<T>` is a separate affine process-local owner under
`GNT-28.11-runtime-admission-mapping`. `bind` consumes one active `AdmittedResource` and one
host value, returning both on refusal. The embedding caller authenticates their association and
supplies authority. `invoke` fences the current owner and active lifetime before a bounded
synchronous callback, using existing `gantry-host` unwind containment. A panic poisons this
transport boundary, not the accounting lifetime. Unused callbacks are disposed under containment
on refusal, including an already-poisoned boundary, without executing their bodies; a destruction
panic takes precedence over the original refusal. `finish` enters finishing before the callback and
records finished only after callback and contained physical disposal succeed. Failure remains
finishing without implicit retry; sealed `emergency_release` settles accounting before disposal,
so destruction failure cannot undo semantic release. Disposal removes the value before destruction;
wrapper drop contains physical destruction but never fabricates semantic finish. This owner is
not automatically attached to the registry or evaluator and publishes no async cancellation,
source transfer, authority admission, or host reconstruction. Its host value is never placed in
`LogicalValue`, hook bytes, or accounting reconstruction records.

`AdmittedResource` publishes `admit`, `subject`, `ledger`, `quota`, `remaining`, `durable_record`,
`containment`, `settle_containment`, `adapter_instance`, `bind_adapter_instance`,
`begin_finish_for`, `complete_finalization_for`, `charge`, `renew`, `close_liveness_root_for`,
`retire`, `delete_for`, `settle_from_post_failure`, and `settle_from_emergency_cleanup`. The registry
routes above select an account and delegate to these, so both levels publish the same model
decisions, and the account level is the narrower surface: it mutates one account a caller already
holds rather than selecting one by subject. Operation-state projection is a registry route; it
derives its model projection from a supplied accepted `LiveResource` and applies it to the selected
ledger without exposing a mutable account.

## Fences

Every route that changes a declared fact is subject-addressed at the registry level: the account is
selected by the subject's own operation and generation rather than by caller text. The ordinary
mutation routes - `charge`, `renew`, `begin_finish`, `complete_finalization`, `close_liveness_root`,
`retire`, `delete`, `bind_adapter_instance`, and `poison_adapter_instance` - are additionally
owner-qualified: the presented owner generation must be the account's current one, as
`GNT-20.10-retirement-and-stale-owner-fencing` requires, and a superseded generation is refused
before any declared fact changes. `settle_from_post_failure` is fenced by its own operation and
resource generation, while `settle_from_emergency_cleanup` is authorized by the sealed cleanup
witness; neither uses an owner-generation argument. `poison_adapter_from_post_failure` is a distinct
adapter-failure route: the settlement selects its operation and resource generation and must declare
adapter poisoning under `GNT-20.7`, then the presented current owner generation fences the bound
adapter poison under `GNT-23.5`. Its poison reason is supplied by the fault-classification caller,
and this route changes neither the resource lifetime nor sibling adapters. Physical reclamation is
the one registry-wide mutating route and changes no declared fact.

`ResourceRegistry::project_operation_state` accepts a `LiveResource` and derives its opaque
projection internally; `ResourceLedger::project_operation_state` consumes that projection. A
projection exists only after the supplied `LiveResource` accepted its own Section 20 settlement.
That exact operation and resource generation select the account, and the accepted owner generation
must still be current. The route updates only the distinct operation-state field; it does not settle
whole-resource lifetime, change quotas or roots, or reconstruct or claim a host resource. Unsettled,
unknown-subject, or stale-owner projections leave the account unchanged, as required by
`GNT-28.12-operation-state-projection`.

- `GNT-28.11-runtime-admission-mapping` maps only accounting admission: the registry derives its
  subject from the machine's authenticated live-resource operation, admits only the declared
  reconstruction-record carrier, and refuses duplicate subjects and admissions above its declared
  live-account ceiling. This does not discover or reconstruct a physical host resource.
- `GNT-28.12-operation-state-projection` maps one accepted Section 20 operation settlement into the
  matching account's distinct operation-state fact. It does not establish evaluator-wide settlement
  uniqueness, a checkpoint format, or a journal schema.

No public route hands out a mutable registry-held account. The bounded compile-fail witnesses cover
the private subject-binding constructor, the removed mutable registry-held account route, the
unqualified finish and finalization steps, and the removed raw ledger accessor, so those specific
transitions are unnameable outside the crate rather than merely unused.

The sealed emergency-release witness is single-use, so the cohort sweep takes one witness per account
and each witness authorizes at most one settlement attempt: it is consumed by that attempt whether it
succeeds or is refused, and a witness that reaches no ledger is dropped rather than returned, so
retrying an unsettled account needs a fresh witness. The sweep settles the presented subjects in
canonical order and stops at the first refusal without rolling back an account that already settled.

## Non-claims

`ExecutionCoordinator::new_with_resource_limit` optionally owns one accounting registry shared
by cloned handles under its existing mutex (`GNT-28.11-runtime-admission-mapping`).
`admit_resource` accepts only a running task's pending operation in that execution;
`charge_resource` retains atomic vector and current-owner charging fences, and
`project_resource_operation_state` derives only accepted operation-state accounting without
settling whole-resource lifetime or releasing its live place (`GNT-28.12-operation-state-projection`).
`begin_resource_finish`, `complete_resource_finalization`, and `emergency_release_resource`
retain the registry's owner and sealed-witness fences. Reserved durable publication refuses
accounting writes. `settle_resource_from_post_failure` selects the model-issued evidence's exact
subject under `GNT-20.7-resource-state-after-failure-and-poisoning`; resource poisoning releases
the live place while retaining the record, but adapter-only failure cannot settle that lifetime.
Reserved durable publication also fences this route. Success advances publication once; refusal
changes neither records nor publication.
`ExecutionCoordinatorSnapshot::resource_records` exposes immutable inspection facts,
not committed journal state. Cleanup may settle an account after task settlement without reopening
admission. No host future is polled under this mutex. This optional owner is not automatically
connected to evaluator dispatch or durable task cuts. Its live-account ceiling bounds neither
retained records nor snapshot size; whole-execution resource integration remains outstanding.

- Account uniqueness is per registry: the runtime publishes no global uniqueness claim for one
  subject, and `GNT-28.10-resource-accounting-non-claims` is not widened here.
- The containment settlement is runtime state of one account value under
  `GNT-23.4-operation-ownership-and-single-settlement`, so one contained operation settles once for
  the lifetime of that value. A subject rebuilt from its declared capture, or reclaimed and
  readmitted, holds a fresh unsettled settlement; the runtime publishes no cross-recovery
  single-settlement claim.
- The bound adapter instance and the poison reason ledger are runtime state under
  `GNT-23.5-failed-instance-poisoning-and-isolation`. A registry rebuilt from declared
  reconstruction records holds neither, and the runtime publishes no recovery claim for either.
- A contained fault is not a settlement of the resource's accounting lifetime:
  `GNT-23.7-adapter-containment-obligations` and `GNT-23.8-containment-non-claims` declare
  containment obligations and limits only, so the runtime never derives a resource settlement from a
  containment report.
- Protected-scope containment reports are not published here:
  `GNT-23.6-protected-fault-diagnostics` leaves them to the landed protection rules.
- Physical reclamation is not semantic release: `reap_deleted` frees registry memory only, and under
  `GNT-28.9-retirement-deletion-and-stale-owner-fences` no retention state returns a released live
  place.
