# Runtime resource integration

This note is a reader index of the runtime surfaces that consume the declared resource, operation,
and containment contracts. It states what the runtime publishes, where each decision is decided, and
what the runtime does not claim.

Declared semantics belong to the model: the runtime selects an account, applies a fence, and reports
the model's own reason. Two things are runtime policy over declared facts rather than model
decisions - the registry's live-account ceiling and physical reclamation - and both are named as such
below. Where a clause owns a fence rather than the runtime policy that consumes it, this note says so.

## Registry surfaces

Registry storage keys qualify portable operation/resource-generation identity with the issuing
execution and task. Independent sibling counters can produce equal portable identities without
collapsing their accounts or physical slots; each account consumes the shared registry ceiling.
Inspection, capture and accounting reconstruction preserve that distinction. Cohort ordering and
deduplication use operation, generation, execution and task. Mutations select exact runtime ownership
first; a portable alias without matching ownership can only produce a foreign-provenance refusal.
Portable identity derivation and host authority remain unchanged.

`ResourceRegistry::with_limits` optionally declares independent live-account and pending
resource-operation ceilings under `GNT-28.11-runtime-admission-mapping`. `pending_limit` inspects
the ceiling; `pending_operations` tracks accepted work even when that ceiling is absent.
Every successful live admission retains its settlement lease. Pending places follow admitted machine
settlement leases: accepted completion, failure, and settled cancellation release them; refused
completion and a cancellation request alone retain them.
Readmitting reclaimed accounting through the same retained lease counts that work once, including
at a full pending ceiling. Genuinely new leases still require an available pending place.
Machine-local cancellation separately closes new admission through current and saved subjects
with `CancellationRequested`, without releasing accepted pending capacity. Recovery derives that
refusal from recorded cancellation. Isolated staged cancellation affects the authoritative lease
only when published, and publication retains pending capacity until settlement.
Promotion merges lease facts monotonically: cancellation or settlement recorded by a shared
authoritative clone cannot be reopened by publishing an older private projection.
Physical attachment also refuses machine-local cancellation with `HostResourceError::CancellationRequested`,
returning the input untouched. It checks the admitted account's lease, not a caller's recovered or
speculative binding, and holds that lease through acquisition. Accepted-work settlement and cleanup
remain separate and available.
Accounting lifetime settlement and physical reclamation do not release still-pending work. Closed leases are pruned at successful
admission; poisoned leases conservatively retain capacity. Reconstruction does not recover this
process-local pending policy, and unadmitted evaluator work is outside its scope.

`ExecutionCoordinator::new_with_resource_limits` enables both ceilings in one shared registry;
cloned handles retain the same admission refusal and machine-settlement release boundaries.
The existing `new_with_resource_limit` constructor leaves the pending ceiling disabled, while
still tracking successfully admitted work until machine settlement.

`InterpreterConfiguration::with_resource_accounting_limits(live, pending)` opts fresh launch
owners into finite accounting ceilings; the default `resource_accounting_limits()` is `None`.
Zero denies resource admission, not ordinary source execution. Concurrent root construction uses
`new_with_budget_and_resource_limits` to retain the same execution budget. This policy enables
accounting ownership only, not live-handle transport or host authority; current durable resume
does not reconstruct it. For example, an embedder can use
`configuration.with_resource_accounting_limits(64, 16)` for new execution owners while retaining
the existing raw-byte-hook refusal for live-resource results.

`ExecutionCoordinator::new_with_recovered_resources` constructs one shared accounting owner
atomically from declared reconstruction records. Each binding must name the execution and a known
task; settled tasks may retain accounting for cleanup. Registry carrier, kind, duplicate, owner
generation and live-ceiling checks all run before exposing a coordinator. No physical slots,
adapter bindings, pending policy or pending work are reconstructed. Journal provenance remains
the caller's recovery responsibility; this entry point does not add resource records to graph cuts.

The current durable graph wire carries no resource reconstruction records or registry policy.
`capture_checkpoint` and `stage_graph` refuse `ResourceStateUnsupported` before cloning machines
or reserving publication if retained accounts, physical slots or pending admitted work would be
omitted. An empty configured registry remains eligible. This fail-closed boundary prevents silent
accounting loss; it is not durable resource reconstruction integration.
`publish_committed_root` likewise refuses before installing task, session, budget, event or root
projections when retained resource state would be omitted. It does not undo an existing journal cut.

`attach_host_value` optionally attaches one typed process-local value to an existing active/open
account without moving or duplicating accounting and without changing quotas. The embedding caller
authenticates its association and authority. Duplicate, unknown, stale-owner and inactive refusals
return the value untouched. `invoke_host_value` checks the exact Rust type and accounting fences;
physical attachment, invocation, presence inspection and disposal also require the binding's
issuing execution/task to match the admitted account. `execution_id` and `task_id` retain machine
provenance across checkpoint recovery without changing portable operation/generation identities.
Another runtime owner with matching static identities refuses with `ForeignSubject`.
Invocation and unused callback destruction reuse host containment. `dispose_host_value` removes the
value before contained destruction, only after accounting leaves active. Finalization cannot
complete while a value remains held. Semantic poison or emergency release can release live quota
before disposal. A contained destruction failure remains recorded after the slot becomes empty:
repeated disposal reports the same failure without destroying again, and normal finalization
refuses with `PhysicalDisposalFailed`. Sealed emergency release remains available from finishing.
`has_host_value` reports presence only, not successful destruction.
Deleted accounts are not reaped while a value remains attached. Captures and reconstruction omit
physical slots; no callback route is exposed through the coordinator's shared lock. Registry drop
contains physical destruction only and does not synthesize semantic settlement.

`ExecutionCoordinator::attach_resource_host_value` retains physical ownership in the same registry
without changing accounting publication; refused inputs are returned untouched outside the lock.
Attachment requires the issuing execution to match and its task to be known and running;
task settlement closes physical admission without disabling accounting or physical cleanup.
Recorded task or execution cancellation closes both accounting admission and physical attachment
immediately with `TaskCancellationRequested`, before terminal settlement. Existing accepted work
and its pending lease are not settled by that refusal; cleanup remains available.
`close_resource_admission` separately closes acquisition during cooperative shutdown, returning
true only on the first closure. `ResourceAdmissionClosed` refuses new accounting and attachment
while preserving returned inputs, existing records, publication and accepted leases. Clones share
the monotonic fence and cleanup remains available. Shutdown closes current launch handoffs and
closes later owners before exposing them, without nesting registry/coordinator locks. This fence
is process-local, including during a publication reservation, not recovered graph policy.
`dispose_resource_host_value` checks owner and durable-publication availability, marks cleanup
pending and extracts exclusive physical ownership, then runs contained destruction without holding
the coordinator or cleanup-status mutex. Pending cleanup blocks finalization and reaping, and another
disposal refuses with `DisposalPending`. Completed cleanup retains success or failure in the slot.
Attachment and disposal neither release semantic quota nor advance accounting publication; their
process-local statuses are not journal cuts or physical recovery evidence.
`wait_for_shutdown_quiescence` requires settled task drivers and completed destruction of all
attached values, including extracted cleanup jobs. Completion wakes registered observers after
unlocking even when destruction failed; it does not imply normal finalization or initiate cleanup.

`emergency_release_resource_cohort` consumes sealed witnesses through the registry's canonical
settled-prefix sweep. `CoordinatorResourceCleanup::semantic` preserves that prefix and first
refusal; `physical` reports one independent disposal outcome per settled member. Cleanup jobs run
after unlocking and continue despite another member's destruction failure. Later members remain
unchanged after semantic refusal. A progressing sweep publishes once, while a zero-progress
refusal does not publish; physical failure never rolls back semantic release.

`submit_emergency_resource_cleanup` submits the same sealed cohort through bounded blocking-work
ownership and returns `ResourceCleanupObserver<CoordinatorResourceCleanup>`. It captures witnesses
and a coordinator handle, not physical slots. Refusal or queued cancellation consumes witnesses
without settling accounting or extracting physical ownership. Started cleanup survives observer
drop, preserves the canonical settled-prefix report, and never rolls back release after a destructor
failure. It grants no escalation authority and does not settle accepted machine work.

`emergency_release_task_resources` selects registry-owned live accounts for named tasks only after
checking that every task is known, cancelled and physically settled. These checks and selection
share the semantic settlement lock and publication fence. Duplicate task names select each account
once; terminal accounts remain excluded. The caller authenticates the sealed escalation's cohort
association. `submit_task_resource_cleanup` runs the same checks when its blocking job starts.
Neither route creates escalation authority, reopens admission or settles pending machine work;
the synchronous route still requires a blocking caller for physical destruction.

`dispose_settled_resource_host_values` drains already-settled physical obligations in canonical
runtime-subject order, reporting `ResourcePhysicalCleanupResults`. Active and finishing accounts
are excluded. Selection respects publication reservations; jobs execute after unlocking and continue
after failures. Retained failures remain reportable, while successful disposed slots are omitted
on repeat sweeps. Accounting publication, quotas and pending machine work remain unchanged; the
sweep neither initiates semantic settlement nor completes source-task cleanup integration.

`submit_settled_resource_cleanup` hands the sweep to the existing bounded blocking-work service,
capturing only a coordinator handle. Submission refusal or service cancellation before start
therefore leaves physical slots held. `ResourceCleanupObserver::completion` reports service and
coordinator failures separately from per-member destruction outcomes; repeated observation retains
the result. Dropping the observer or its future does not cancel accepted work. Submission, completion
polling and handle disposal use integration containment. Started destruction runs off async workers
and remains service-owned.

Nondurable execution cancellation now submits already-settled physical obligations after driver
drainage and before waiting for shutdown quiescence.
Failed semantic or physical driver-grace timing retains an executor error rather than implying
grace expiry. Abort-and-drain ownership and settled physical cleanup remain required; successful
drainage cannot erase the retained error or its first lifecycle `Executor` classification.
For positive grace, cancellation declares a supervisor stop before each driver-grace timer using
phase-relative logical microseconds (zero request instant, configured drain duration as grace and
drain). Only successful timer expiry issues sealed escalation at the declared deadline. Zero
duration and timer errors grant no emergency cleanup authority. After successful abort-and-drain,
only supervision records confirming both `Stopped` abort and `Stopped` completion select tasks for
`submit_task_resource_cleanup`; its cancelled/physically-settled fences are rechecked in the job.
Failed or already-settled aborts cannot authorize release. Emergency cleanup runs off async workers
and does not settle independently pending external machine work.
The configured cancellation drain deadline bounds observation, not started destruction.
Service/coordinator failures report `ResourceCleanup`;
member destruction failures report `ResourceDisposal`. `ExecutionSnapshot::resource_cleanup_failure`
retains the first operational classification (service, disposal, deadline, executor, unsettled accounting or pending resource work), including
after terminal publication. Fixed language outcomes and cancellation remain unchanged; failures
to record this classification propagate rather than being silently discarded.
Physical-quiescence observation also records deadline or executor failure, including when an active
resource remains held after driver terminal publication. It does not dispose or release that account.
An already-terminal cancellation request still drains retained settled physical obligations and
observes quiescence; success retains `AlreadyTerminal` without changing fixed language outcomes.
With no held/in-flight values, retained disposal failures, unsettled accounting or admitted pending
work, it returns immediately rather than waiting for unrelated driver completion. Interpreter
shutdown retains ownership of those drivers.
Active and finishing accounts are not implicitly released. This phase does not enable source
live-handle transport or complete durable cancellation integration.
After physical quiescence, cancellation independently checks accounting and pending work. Remaining
obligations return `ResourceObligations` with `UnsettledAccounting` or `PendingResourceWork`, retaining
the first lifecycle classification without changing accounting or leases. Explicit later settlement
remains available, including for already-terminal language outcomes.

Interpreter shutdown also inspects retained nondurable execution owners, including terminal owners
outside the semantic cancellation cohort. It submits settled physical cleanup before closing the
blocking-work service and observes remaining physical ownership under the shutdown drain deadline.
Cleanup failure, an earlier retained failure, or incomplete physical quiescence makes the report
unorderly and preserves independent lifecycle classification. Active and finishing accounts remain
held until explicitly settled; fixed language outcomes are never rewritten.
Active or finishing accounting also prevents orderly shutdown when no physical slot exists.
`UnsettledAccounting` records this missing semantic disposition without changing accounting or
overwriting an earlier cleanup classification.
Admitted pending operations independently prevent orderly shutdown even after accounting release.
`PendingResourceWork` records the outstanding machine settlement without closing its lease or
releasing pending capacity. Explicit later machine settlement remains available.
`ShutdownReport::resource_cleanup_failures` retains each execution's first cleanup failure in
execution order, including terminal owners outside the semantic cancellation cohort. It does not
expand that cohort. Recorded failures prevent orderly reporting and are retained in unclean reports.

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

`OwnedHostResource::transfer` consumes the owner and advances only its current accounting
generation. It requires active/open accounting, no loan root, a closed pending-machine lease,
settled historical containment, no bound adapter, and unpoisoned transport. Refusal returns the
complete owner untouched. Success preserves the physical value, subject, quota/root facts and
historical containment; it neither rebinds an adapter nor implements source-task transfer.

`OwnedHostResource::borrow_receiver` consumes an exact borrowed `LiveResource` into an exclusive
`HostReceiverLoan`, returning the handle on refusal. Admission checks the account's operation,
site, resource generation, current owner and declared loan root. `observe` retains Section 20
allowances and progress rules; accepted `settle` projects operation state and closes only the
loan root. Refusal retains the guard and progress for another candidate. Whole-resource lifetime,
quotas and pending machine work remain separate. Owner invocation, finish and transfer stay
fenced even if the guard is forgotten; dropping an unsettled guard poisons transport without
claiming settlement. Sealed emergency cleanup can still dispose the held value. These are
process-local synchronous loans, not source-evaluator borrowing or durable loan recovery.

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
subject-addressed mutations, containment and adapter changes, and sealed single/cohort cleanup
also require the binding's issuing execution/task to match the account before mutation. Foreign
provenance refuses with `ResourceRegistryRefusal::ForeignSubject`, preserving records and bindings.
This prevents accounting release from bypassing physical-access provenance checks. The ordinary
mutation routes - `charge`, `renew`, `begin_finish`, `complete_finalization`, `close_liveness_root`,
`retire`, `delete`, `bind_adapter_instance`, and `poison_adapter_instance` - are additionally
owner-qualified: the presented owner generation must be the account's current one, as
`GNT-20.10-retirement-and-stale-owner-fencing` requires, and a superseded generation is refused
before any declared fact changes. `settle_from_post_failure` is fenced by its own operation and
resource generation plus accepting-owner provenance from `LiveResource`, while declaration-only
`OperationAbi` failure classification cannot authorize runtime poisoning. Missing provenance or
a stale evidence owner refuses before mutation. `settle_from_emergency_cleanup` is authorized by the sealed cleanup
witness; neither uses an owner-generation argument. `poison_adapter_from_post_failure` is a distinct
adapter-failure route: the settlement selects its operation and resource generation and must declare
adapter poisoning under `GNT-20.7`. The evidence's accepting owner must match the account;
the presented current owner generation fences the bound adapter poison under `GNT-23.5`.
Its poison reason is supplied by the fault-classification caller,
and this route changes neither the resource lifetime nor sibling adapters. Physical reclamation is
the one registry-wide mutating route and changes no declared fact.

`ResourceRegistry::project_operation_state` accepts a `LiveResource` and derives its opaque
projection internally, alongside a machine-issued `ResourceSubjectBinding`;
`ResourceLedger::project_operation_state` consumes that projection. Registry failure settlement
and adapter-failure poisoning likewise require the accompanying binding. Evidence still selects
its own exact account; the binding must name that operation/generation and match its issuing
execution/task. `EvidenceSubjectMismatch` and `ForeignSubject` refuse before mutation, while
unsettled projection and absent evidence-selected account refusals retain precedence. A
projection exists only after the supplied `LiveResource` accepted its own Section 20 settlement.
That exact operation and resource generation select the account, and the accepted owner generation
must still be current. A fenced generation projects `Poisoned` even when its retained completion
would otherwise derive another state; projection preserves the fence without rewriting settlement
or progress evidence.
Once the ledger retains `Poisoned`, older non-poisoned projections refuse with
`PoisonedOperationStateRevival` without changing any accounting fact.
Consumed and closed generations likewise refuse projections restoring an open half with
`TerminalOperationStateRevival`. Current-owner validation still precedes this refusal;
repeated terminal projection and subsequent poison fencing remain available.
The route updates only the distinct operation-state field; it does not settle whole-resource
lifetime, change quotas or roots, or reconstruct or claim a host resource. Unsettled,
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
