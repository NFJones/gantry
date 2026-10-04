# Runtime resource integration

This note is a reader index of the runtime surfaces that consume the declared resource, operation,
and containment contracts. It states what the runtime publishes, where each decision is decided, and
what the runtime does not claim.

Declared semantics belong to the model: the runtime selects an account, applies a fence, and reports
the model's own reason. Two things are runtime policy over declared facts rather than model
decisions - the registry's live-account ceiling and physical reclamation - and both are named as such
below. Where a clause owns a fence rather than the runtime policy that consumes it, this note says so.

The subject-free v1 reconstruction codec rejects input above 4096 bytes before copying it.
Parsing is bounded to depth 5, 128 nodes, 64 scalars per string value, and 9 members per list;
object keys remain bounded by the input-byte ceiling.
these budgets cover all nine quota owner/family pairs, four roots, and full-range u64 facts.
Malformed excess input returns `ResourceRecordCodecError::Encoding` before model interpretation,
without allocating a parse tree proportional to arbitrary recovery input. This is not a journal
format or host-resource reconstruction claim.

## Registry surfaces

Registry storage keys qualify portable operation/resource-generation identity with the issuing
execution and task. Independent sibling counters can produce equal portable identities without
collapsing their accounts or physical slots; each account consumes the shared registry ceiling.
Inspection, capture and accounting reconstruction preserve that distinction. Cohort ordering and
deduplication use operation, generation, execution and task. Mutations select exact runtime ownership
first; a portable alias without matching ownership can only produce a foreign-provenance refusal.
Portable identity derivation and host authority remain unchanged.

`Machine::pending_resource_abi(ownership)` derives the live-resource declaration, recovery
class, site and generation from the pending machine rather than caller-selected identity facts.
The explicit receiver arrangement still requires independent authority and ownership validation.
Foreign loans use the model's refusal; missing action or live-kind authentication yields no ABI.
Inspection changes no accounting, budget or settlement lease and supplies no source-handle path.

`ResourceRegistry::with_limits` optionally declares independent live-account and pending
resource-operation ceilings under `GNT-28.11-runtime-admission-mapping`. `pending_limit` inspects
the ceiling; `pending_operations` tracks accepted work even when that ceiling is absent.
Already-settled accounting records require no live-account place, including at a zero ceiling;
their machine lease still undergoes independent pending-work admission. Physical acquisition
continues to require active lifetime and open operation state.
`with_accounting_limits(live, pending, retained)` independently caps all registry-held accounts.
`retained_limit` inspects the ceiling and `retained_resources` counts occupied places. Settlement,
retirement and deletion do not free a retained place; eligible `reap_deleted` reclamation does.
Excess admission returns `RetainedResourceLimitReached` after existing accounting quota checks,
without consuming physical inputs or publishing pending capacity. Existing constructors leave
this policy disabled. `new_with_budget_and_accounting_limits` exposes it through coordinator
ownership. Empty retained-account policy uses `GNTCDP07` to preserve its exact ceiling;
ordinary v6 empty-policy carriage is unchanged. Eligible accounting records use version-eight carriage below.
`with_adapter_identity_limit(limit)` separately caps distinct accepted adapter identities over
the registry lifetime. Bindings and substitutions validate existing fences before reserving a
place; aliases share a place and refusals preserve bindings and accounting. Reservations survive
account reclamation so poisoning can always retain failed-identity fences. `adapter_identity_limit`
and `retained_adapter_identities` inspect this policy and its occupancy.
Runtime replacements also require a strictly advanced binding sequence after model validation
and before capacity admission; `BindingSequenceNotAdvanced` preserves the held binding and
reservations. This enforces deployment ordering without changing the pure substitution model.
Legacy constructors leave
it absent. Configured policy currently refuses graph/envelope capture even when empty, because
those wires cannot retain it; it enables no host authority or durable adapter reconstruction.
`with_adapter_bounded_resource_accounting_limits(live, pending, retained, adapters)` applies all
four finite ceilings to fresh sequential and concurrent execution owners, retaining their shared
budget. Older accounting builders replace and clear adapter policy. The coordinator exposes
`adapter_identity_limit()` for inspection. Durable start/resume refuses configured policy with
`unsupported-durable-adapter-identity-policy` before mappings or admission, without evidence writes;
this is a fail-closed limitation rather than adapter-policy recovery.
Every successful live admission retains its settlement lease. Pending places follow admitted machine
settlement leases: accepted completion, failure, and settled cancellation release them; refused
completion and a cancellation request alone retain them.
Successful result completion and explicit operation failure claim this shared pending lease once
after result validation. Shared aliases refuse closed/unreadable leases with `NotWaiting` and shared
cancellation with `Cancelled`, without publishing another result or failure. The guard releases
before value disposal and failure cleanup. Isolated durable stages claim only their private lease
until committed promotion; this supplies no cross-recovery uniqueness or journal authentication.
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
admission and during `reap_deleted`, including when no account is reaped; pending and unreadable
leases remain retained. Lease pruning changes storage references, not accepted-work settlement or
the returned reaped-account count. Poisoned leases conservatively retain capacity. Reconstruction does not recover this
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
reconstructs enabled empty-registry policy through the version-six combined graph. Eligible records
use the separately bounded version-eight path below. For example, an embedder can use
`configuration.with_resource_accounting_limits(64, 16)` for new execution owners while retaining
the existing raw-byte-hook refusal for live-resource results.
`with_bounded_resource_accounting_limits(64, 16, 128)` additionally limits retained account records
in both sequential and concurrent fresh owners, preserving their shared execution budget.
`retained_resource_limit()` inspects this independent ceiling. The default leaves it absent;
calling the two-ceiling builder replaces and clears retained policy. Zero denies record admission,
not ordinary source execution. Empty bounded policy uses version-seven graph carriage.
Enabled accounting policy is also included in the immutable durable execution-start configuration
identity. Changed live, pending or retained ceilings, retained-policy removal and disabled accounting
refuse resume with `immutable-configuration-mismatch` without journal mutation. Disabled-policy
configuration bytes remain unchanged; absent retention differs from zero. Binding this policy is
not itself resource reconstruction or host authority admission.
Serial root-driver recovery restores enabled empty accounting from identity-validated configuration,
retaining the recovered machine's shared execution budget and all configured ceilings. It creates
no resource records, physical slots or accepted-work leases; sequential record refusal remains intact.
Concurrent resume additionally compares recovered graph accounting policy with that validated
configuration before lifecycle admission, journal repair or replacement-driver submission.
Disagreement refuses with `graph-accounting-policy-mismatch` without journal mutation, even when
the substituted policy is otherwise structurally valid and consistent across all graph cuts.

`ExecutionCoordinator::new_with_recovered_resources` constructs one shared accounting owner
atomically from declared reconstruction records. Each binding must name the execution and a known
task; settled tasks may retain accounting for cleanup. Registry carrier, kind, duplicate, owner
generation and live-ceiling checks all run before exposing a coordinator. No physical slots,
adapter bindings, pending policy or pending work are reconstructed. Journal provenance remains
the caller's recovery responsibility; this entry point does not add resource records to graph cuts.
`new_with_budget_and_recovered_resources` additionally retains the matching shared execution-budget
owner. Budget execution mismatch refuses with `InvalidTaskMachine` before record validation;
the same complete-set accounting checks follow. Budget retention neither authenticates journal
provenance nor reconstructs physical slots, adapters or pending work.

`new_with_budget_and_bounded_recovered_resources` composes the same budget-qualified complete-set
validation with explicitly supplied live, pending and retained ceilings. Reconstructed records
consume live/retained capacity as applicable; pending policy governs future work only, with no
invented leases. Legacy entry points keep pending and retained policy absent. These inputs remain
caller-authenticated reconstruction evidence, not a journal provenance guarantee.

`RecoveredResourceRecord::from_issuing_checkpoint` derives an accounting subject from a validated
issuing machine checkpoint and budget, rather than caller-selected identity strings. It validates
the declared kind, carrier and owner, and closes only its private recovered admission lease.
The source machine lease remains unchanged; no accepted work or physical slot is reconstructed.
The caller must authenticate the issuing checkpoint's journal provenance and current cleanup
ownership. This is not resource-record carriage in the combined graph wire.
Validated origins retain immutable canonical checkpoint bytes and their issuing budget through
accounting reconstruction and declared capture. `issuing_evidence()` inspects these historical
facts without opening a lease; legacy record construction leaves them absent. Current accounting
advancement does not rewrite issuing evidence or qualify it as journal-authenticated state.

`stage_owner_advance` builds a private same-cleanup-task candidate by reconstructing the account
and reusing existing ownership transfer fences. Active/open accounting, strict successor, no loan,
closed machine work and settled historical containment precede atomic Move charging; missing
containment stays unsettled. Success preserves issuing/history facts, roots and cleanup task.
Refusal leaves the source unchanged. This is not physical transfer or journal publication authority;
durable publication requires the exact ownership cut below, not ordinary graph-image replacement.

`stage_task_handoff` additionally qualifies a private cleanup-task candidate against a supplied
task-state snapshot: matching execution, distinct known running tasks and no cancellation precede
current cleanup-owner and transfer checks. Move charges, generation and cleanup task change together
only in the candidate; issuing provenance and containment history remain unchanged. The caller
authenticates the snapshot and authority. This enables no physical transfer or journal publication by itself,
and the same-task ownership carrier still rejects cleanup-task changes.

`new_task_handoff` derives eligibility from tasks recovered from the exact predecessor graph.
`GNTRWA02` retains source/destination tasks and authored Move charges under the same vector and
4 MiB journal limits, selecting `gantry.resource-owner-evidence/v2`. Kind/carrier correspondence
prevents relabeling same-task evidence. `stage_resource_task_handoff` privately stages the candidate
and rechecks live cancellation and admission closure before submission; cleanup task, generation
and quota use install together only after a validated receipt. Existing rollback and indeterminate
publication fencing remain intact. No physical, source-handle or accepted-work recovery is supplied.

`ResourceOwnerEvidenceV1` reproduces one same-cleanup-task advancement between executable-validated
complete graphs. Its `GNTRWA01` carrier retains the authored Move vector under a 128-member limit
and a caller-supplied complete byte ceiling; closed tags, canonical framing and exact successor
comparison reject unrelated changes. Output admission precedes checkpoint copying, not temporary
checkpoint allocation. Constructing evidence alone grants no journal authority.

`stage_resource_owner_advance` privately stages exactly one same-cleanup-task advancement for the
`ResourceOwnerAdvance` cut and `gantry.resource-owner-evidence/v1` journal kind. Its 4 MiB carrier
requires the actual authoritative predecessor and an empty protected-payload list. Writer baselines
and logical accounting install only after a validated receipt; pre-submission drop rolls back while
indeterminate submission remains fenced. Full-prefix and selector-eight histories replay the exact
transition; legacy compaction refuses rather than dropping it. This supplies no physical or cleanup-task
transfer, accepted-work recovery, or change to fixed terminal outcomes.

`stage_finish(owner, ResourceFinishTransition::Begin)` builds a finishing candidate; `Complete`
records a declared logical settlement instant using the same ledger rules. Both leave the source
record unchanged and preserve its subject, cleanup ownership, quotas, roots and historical evidence.
Stale ownership refuses before lifetime classification. This candidate performs no physical
finalization or journal publication; publication requires the exact finish cut described below.

`stage_finish_with_charges` privately admits a whole explicit release vector while active before
entering finishing. Refusal leaves the source unchanged; success retains historical evidence and
changes only declared quota use and lifetime. Complete candidates refuse additional charges.
The existing `GNTRFT01` journal validator still rejects these extra quota changes: a charged
candidate is not publication authority and requires the `GNTRFT02` carrier.

`new_with_charges` retains at most 128 authored release members before deduplication, including
order and duplicate keys, and reproduces exactly one charged Begin successor. Nonempty vectors
select `GNTRFT02` / `gantry.resource-finish-evidence/v2`; empty vectors preserve legacy bytes and
kind. Closed quota tags, canonical framing and journal-kind correspondence refuse substitution.
`stage_resource_finish_with_charges` installs declared quota use with finishing only after a
validated receipt under the same 4 MiB journal bound and authoritative predecessor fence.
Full-prefix and selector-eight snapshot replay retain these explicit charges without physical cleanup.

`ResourceFinishEvidenceV1` compares two executable-validated graph checkpoints. One owner-qualified
finish at a canonical record index must reproduce the complete successor, rejecting unrelated
graph, policy or historical changes. Its separate `GNTRFT01` carrier uses an independent total
byte ceiling and canonical framing. Temporary checkpoint encoding is not a peak-heap bound.
This validator alone grants no journal publication authority.

`stage_resource_finish` privately stages one exact begin/complete transition for journal-first
`ResourceFinish` publication. Its `gantry.resource-finish-evidence/v1` carrier is bounded to
4 MiB and names complete predecessor/successor graphs. Both finish versions reject nonempty
protected-payload lists before decoding, because neither represents such obligations.
The writer requires the actual committed
predecessor; a validated receipt precedes logical registry installation. Rollback before submission
discards the candidate, while indeterminate submission retains the existing publication fence.
Only authoritative prefix recovery or a validated graph receipt seeds the complete predecessor.
Capturing mutable transaction machines cannot seed it: matching records and journal coordinates
do not establish that uncommitted machine progress belongs to the preceding cut.
Full-prefix replay checks exact predecessor correspondence. Legacy version-seven snapshot compaction
containing these cuts refuses rather than discarding them. No physical cleanup or accepted-work recovery
is supplied, and a finish after terminal publication does not reopen the language execution.

`ConcurrentFinishSnapshotV1` retains complete envelope history in bounded `GNTCSF01` bytes under
snapshot selector eight. It checks the caller's byte ceiling and a separate 16 MiB ceiling before
body copying or input parsing. Recovery compares journal/frontier/evidence bindings, then replays
the retained history and suffix through the same authoritative full-prefix validator. Legacy
snapshot bytes remain unchanged. This preserves causal evidence without reducing history or
embedding protected payload content; it supplies neither storage authenticity nor physical recovery.

`encode_resource_recovery_envelope` and `decode_resource_recovery_envelope` carry those facts in
the exact `GNTRRE01` envelope. Both accept an independent total byte ceiling; encoding checks
the complete framed size before copying the checkpoint, and decoding refuses excess bytes before
parsing. The decoder validates issuing machine/budget facts, rederives the subject, and compares
cleanup-task and current-owner facts supplied by the recovery pass. Canonical round trips reject
trailing or alternate encodings. Legacy records without issuing evidence cannot be encoded.
This is declared reconstruction carriage, not ordinary value serialization, journal authentication,
or combined-graph integration; physical slots and accepted work are not restored.

`declared_records_with_containment()` explicitly adds historical containment ownership and its
optional effect/outcome winner. Such records use `GNTRRE02`; records without this projection keep
their `GNTRRE01` bytes. Reconstruction validates the winner through the Section 23 model and
preserves its historical owner even after accounting ownership advances. A retained winner still
refuses second settlement. Direct registry reconstruction also rejects future historical owners
with `Containment(StaleGeneration)` before restoring containment or publishing any registry.
Future historical owners, unknown tags, impossible winners and trailing
containment bytes refuse. Ordinary declared capture remains accounting-only and opens fresh
containment during reconstruction. Neither path restores adapters or accepted machine work.

`capture_recovery_envelopes(maximum_bytes)` captures all registry records in canonical
runtime-subject order, preserving issuing and containment evidence under one shared ceiling.
The ceiling includes an eight-byte count and eight-byte lengths for every envelope. Pending
work, live loan roots, physical slots, adapter bindings and poison history refuse before
projection. Missing evidence or byte exhaustion returns no partial set and changes no
accounting. Members are projected incrementally after framing admission, avoiding an eager
clone of the complete accounting set. This is not a total transient-allocation guarantee;
combined graph eligibility remains unchanged.

`reconstruct_recovery_envelopes` restores a complete ordered set with independently supplied
owner generations, cleanup tasks and optional live/pending/retained policy. Aggregate framed
byte admission runs before decoding; malformed, duplicate, reordered, containment-absent or
loan-bearing records refuse without exposing a partial registry. Live and retained ceilings
apply to reconstructed accounting; pending policy applies only to future admission. No physical
slots or accepted-work leases are created, and journal authentication remains the caller's duty.

`ExecutionCoordinator::new_with_budget_and_recovered_resource_envelopes` additionally checks
current budget execution before decoding, issuing execution and known issuing/cleanup tasks,
and each issuing budget against the unchanged current frontier. Issuing checkpoint coordinates
and source-body creation workflow/site/result/capture contracts must match retained task facts;
membership alone cannot authorize a foreign issuing body. It retains the shared current
budget and optional accounting policy only after complete validation. This is not authenticated
journal recovery or physical-resource reconstruction.

`admit_pending_operation_with_issuing_evidence` opts live accounting admission into retaining
validated issuing facts under an explicit envelope byte ceiling. Evidence and byte admission run
before insertion; ordinary machine-lease and quota checks still decide acquisition. The admitted
account keeps the authoritative machine lease, so settlement releases pending capacity without
discarding historical evidence. Refusal publishes no account or pending place. The route does not
grant host authority, authenticate journal state or relax graph capture refusal.
`ExecutionCoordinator::admit_resource_with_issuing_evidence` applies the same publication,
execution, running-task, cancellation, shutdown and enabled-registry fences as ordinary admission.
Success publishes once; evidence, byte or registry refusal preserves the snapshot and publication.
Captured issuing evidence remains inspection rather than journal-committed resource state.

`ResourceRegistry::reconstruct_with_retained_limit` additionally bounds every reconstructed
account, including terminal records. Existing evidence and live-capacity refusals retain
precedence; the retained ceiling is checked before insertion. Recovery publishes the complete
set or refuses it, never a partial registry, and still creates no pending work or physical slots.

Record-free graph versions carry no resource reconstruction records. `GNTCDP06` separately
retains an enabled empty registry's exact optional live and pending ceilings. Absence differs from
enabled unlimited policy; legacy v4/v5 graph bytes retain absent policy. Capture, staging, replay
and coordinator-backed driver recovery preserve the policy without reconstructing accepted work.
`into_machine_graph` now returns a Result and refuses policy-bearing recovery with the complete
owner unchanged; use `into_driver_admission` to retain policy in its coordinator. Every replayed
graph transition rejects changed or removed policy, including operation cuts.
`capture_checkpoint` and `stage_graph` refuse `ResourceStateUnsupported` before cloning machines
or reserving publication if retained accounts, physical slots, adapter poison history or pending
admitted work would be omitted. Poison history remains a refusal even after accounts are reaped,
so policy-only recovery cannot re-enable a failed adapter identity. An empty configured registry
without that history remains eligible. This fail-closed boundary prevents silent
accounting loss. Version-eight accounting recovery is separately scoped below.
`publish_committed_root` likewise refuses before installing task, session, budget, event or root
projections when retained resource state would be omitted. It does not undo an existing journal cut.

`GNTCDP08` carries a complete nonempty accounting set with issuing and containment evidence and
exact optional admission policy. Its independently bounded resource section is at most 1 MiB,
including count, owner, cleanup-task and envelope framing. Decoding admits the complete raw section
before recovering members. Capture/staging preflight refuses pending admitted work, live loans,
physical slots, adapter bindings, poison history, missing issuing evidence and excess bytes before
cloning machines or reserving publication. Coordinator-backed recovery checks the complete set's
execution/task provenance, budget predecessors, current owners, canonical order, containment and
capacity before exposing accounting. Where an issuing machine remains in the graph, its task path
and executable task-body identity must match validated issuing evidence, including an absent body
for workflow-root machines. Matching task coordinates and counters cannot substitute another body.
Its retained operation-site generation frontier must agree with validated issuing evidence; a
shared budget cannot substitute for missing machine history. Settled children without retained
machines still validate issuing evidence against immutable creation coordinates and source-body
result/capture contracts. Known task membership cannot authorize another issuing body. This is
correspondence, not journal authentication. Consuming driver admission revalidates the actual machine graph after
mutable recovery access, so replacing a recovered machine cannot bypass this history check.
Records are frozen across ordinary replay transitions; the exact typed `ResourceFinish` cut is
the only mutation exception. Coordinator capture/staging compares the committed resource image before
cloning or reservation, and graph committers reject image drift before storage invocation. Recovery
seeds the same image; local accounting cleanup cannot silently become a new durable mutation cut.
The writer also retains exact optional live, pending and retained policy with that predecessor
image. Changed ceilings, removed policy and disabled/enabled-unlimited substitution refuse before
storage invocation, matching replay's policy invariants. Baselines advance only after validated receipts.
An unseeded recovered graph committer refuses even a record-free successor rather than inferring
that its unknown predecessor had no resources. Staged owners supply the validated predecessor image.
Public `DurableCommitCoordinatorV1::from_concurrent_prefix` validates a full or snapshot prefix
for the sink's journal before deriving the execution, root task, authoritative tip and resource
baseline. Construction writes no evidence, does not authenticate storage by itself and never
permits arbitrary resource-image mutation. Wrong-journal prefixes refuse before recovery.
Machine-only extraction refuses; scheduler/driver recovery and replay
capture retain the records. Record-free legacy bytes remain unchanged. This reconstructs logical
accounting, not physical handles, adapters or accepted work, and does not qualify publication.
Durable lifecycle owners also retain the committed accounting image after graph drivers finish.
Shutdown records `UnsettledAccounting` for active or finishing committed accounts, including
terminal executions, without settling resources or rewriting fixed outcomes. Journal-owner release
does not establish resource cleanup. First cleanup failures remain retained; local uncommitted
accounting drift cannot replace the committed image used by this inspection.

`attach_host_value` optionally attaches one typed process-local value to an existing active/open
account without moving or duplicating accounting and without changing quotas. The embedding caller
authenticates its association and authority. Duplicate, unknown, stale-owner and inactive refusals
return the value untouched. `invoke_host_value` checks the exact Rust type and accounting fences;
after provenance, owner and active/open checks, a poisoned bound adapter refuses with
`HostResourceError::Operation(AdapterInstancePoisoned)` before executing the callback. Accounting,
physical ownership and sibling usability remain unchanged; unused callback disposal stays contained.
Bound adapters also require retirement and dispatch-right admission from the account's issuing
recovery metadata. Registry, affine-owner and admitted-loan callbacks share that check; callers
cannot substitute a weaker recovery class. Missing metadata refuses `UnauthenticatedRecoveryClass`,
and insufficient rights refuses `AdapterRightsInsufficient` without releasing ownership or work.
Unbound callbacks still require embedding-authenticated authority; this supplies no capability grant.
Eligible direct invocation also checks the admitted account's machine lease: recorded cancellation
refuses with `CancellationRequested`, and an unreadable lease with `PendingOperation`. Recovered
caller bindings cannot bypass this check. Admission linearizes under the lease, then releases it
before integration or callback destruction; accepted callbacks and cleanup are not rolled back.
`invoke_host_value_with_charges` additionally admits a complete explicit update-charge vector
under that lease after account, adapter, cancellation and physical type/transport validation.
Refusals spend nothing; admitted callback errors and panics retain charges. Legacy uncharged
invocation remains unchanged. This grants no source transport or implicit physical-size charging.
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
Deleted accounts are not reaped while a value remains attached or its disposal failure remains
recorded. Retaining the failed slot preserves repeated failure reporting and refuses same-subject
readmission; it restores neither physical presence nor a semantically released live place.
Captures and reconstruction omit
physical slots; no callback route is exposed through the coordinator's shared lock. Registry drop
contains physical destruction only and does not synthesize semantic settlement.

`ResourceRegistry::admit_host_value` atomically admits accounting and one caller-authenticated
physical value under the same machine lease. Accounting refusals retain their precedence, then
physical acquisition requires active/open accounting. Refusal returns the host input untouched
without publishing an account, slot or pending-capacity change. `admit_resource_host_value` exposes
this through the coordinator's execution/running-task, cancellation, closure and publication fences;
success publishes once and refused inputs remain owned outside the lock. Neither route completes
the machine operation, grants authority or enables source live-handle transport.

`admit_host_value_with_charges` admits a caller-declared action and whole explicit vector after
cancellation, capacity and active/open physical eligibility checks. The private account is charged
under the same machine lease before either insertion. Refusal returns the input untouched without
publishing accounting, a slot or pending capacity. Legacy acquisition remains uncharged; physical
size implies no charge and this boundary grants no authority.
`admit_resource_host_value_with_charges` exposes the same atomic admission through coordinator
task, cancellation, closure and publication guards. Success publishes the charged account once;
refused inputs remain owned outside the coordinator lock without a partial acquisition.

`ExecutionCoordinator::attach_resource_host_value` retains physical ownership in the same registry
without changing accounting publication; refused inputs are returned untouched outside the lock.
Attachment requires the issuing execution to match and its task to be known and running;
after handoff, this task check uses the current cleanup owner. Task settlement closes physical
admission without disabling accounting or physical cleanup.
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

`ResourceRegistry::advance_owner` and `ExecutionCoordinator::advance_resource_owner` advance
only same-task accounting ownership. They retain the account's runtime subject and physical slot,
check exact provenance and current owner before physical eligibility, and reuse the standalone
transfer obligations (active/open, strict successor, no loan, settled machine work and containment,
no bound adapter). Poisoned, disposed and disposal-pending slots refuse. Refusal changes no facts
or publication; coordinator success publishes once. `settle_resource_containment` exposes the
existing containment settlement through the same publication fence, without settling resource
lifetime or pending machine work. Neither route implements source-task transfer or grants authority.

`transfer_resource_task_owner` separately hands off runtime cleanup responsibility between distinct
known, running, uncancelled tasks of the same execution. It retains the issuing subject and registry
key, physical slot, quotas, roots and historical containment while advancing owner generation and
changing the current cleanup task. Admission closure and publication reservations fence handoff;
refusal changes nothing. `task_owner()` inspects current cleanup ownership on admitted accounts and
captured records; reconstruction preserves it and validates both issuing and cleanup tasks. Emergency
task selection and physical attachment follow current cleanup ownership, not the original issuing
task. The caller authenticates authority; this route enables neither source syntax nor durable graph
resource transport and does not settle pending machine work.

`transfer_resource_task_owner_with_charges` applies an explicit whole move vector after the same
task, provenance, physical and ownership checks. Declared quota use, successor generation and
cleanup task commit together before one coordinator publication. Refusals preserve the complete
accounting image and physical slot; legacy handoff uses an empty vector. No implicit physical
charge, authority grant or durable ownership transition is introduced.

`bind_resource_adapter` and `poison_resource_adapter_from_post_failure` expose the registry's
adapter binding and evidence-qualified one-way poisoning through coordinator publication fencing.
Binding retains current-owner and substitution checks; failure poisoning retains the evidence's
exact operation, resource generation and accepting owner. Neither settles whole-resource lifetime
or pending work. Bindings and poison reasons remain process-local, not accounting recovery facts.
Successful poisoning fences all aliases of the exact adapter identity in that registry; later
rebinding of its recorded poisoned identity refuses. Distinct identities and accounting stay
unchanged. This is an identity-wide process-local fence, not a cross-registry or recovery claim.

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
`GNT-28.11-runtime-admission-mapping`. `bind` consumes one active/open `AdmittedResource` and one
host value, returning both on refusal. The embedding caller authenticates their association and
supplies authority. After active lifetime, binding checks open operation state and refuses other
states with `IllegalLifetimeTransition` before acquisition. Binding holds the consumed account's machine lease through physical acquisition;
recorded cancellation refuses with `CancellationRequested`, and an unreadable lease refuses with
`PendingOperation`. Both inputs and accounting facts remain untouched on refusal; binding never
settles pending work. `bind_with_charges(account, value, (action, charges))` additionally admits an
explicit whole vector after eligibility and cancellation, under the same lease as physical binding.
Refusal returns both owned inputs unchanged; success publishes charged quota use and physical
ownership together, without inferred physical-size charges or authority. Legacy binding is uncharged.
`invoke` fences the current owner and active lifetime before a bounded
synchronous callback, using existing `gantry-host` unwind containment. A panic poisons this
transport boundary, not the accounting lifetime. `invoke_with_charges` additionally admits an
explicit whole update-charge vector under the cancellation lease after eligibility and adapter
checks. Poisoned transport and quota refusal spend nothing; accepted callback error or panic
retains charges. Callback execution and unused destruction run after releasing the lease.
Unused callbacks are disposed under containment
on refusal, including an already-poisoned boundary, without executing their bodies; a destruction
panic takes precedence over the original refusal. `finish` enters finishing before the callback and
records finished only after callback and contained physical disposal succeed. Bound finalizers
first pass account-qualified adapter dispatch checks after loan, owner and lifetime validation;
admission refusal changes no accounting or physical ownership. Failure after admitted finish remains
finishing without implicit retry; sealed `emergency_release` settles accounting before disposal,
so destruction failure cannot undo semantic release. Disposal removes the value before destruction.
`finish_with_charges` additionally commits an explicit whole release vector together with entering
finishing, after eligibility, adapter, physical-presence and transport checks. Quota refusal leaves
active accounting and the held value unchanged. Accepted finalizer errors or panics retain charges
and finishing state; cleanup remains independent of cancellation admission. No implicit charge or
retry is introduced, and the legacy uncharged finish path is unchanged.
Wrapper drop contains physical destruction but never fabricates semantic finish. This owner is
also able to perform normal evidence-qualified cleanup through `poison_from_failure`: an outstanding
transport loan refuses first, then the accounting owner validates exact operation/generation,
accepting owner and resource-poisoning evidence before lifetime settlement and contained disposal.
Refusal retains accounting and physical ownership; disposal failure cannot undo poisoning or
cause a second destruction. Roots and pending machine work remain unchanged. This owner is
not automatically attached to the registry or evaluator and publishes no async cancellation,
source transfer, authority admission, or host reconstruction. Its host value is never placed in
`LogicalValue`, hook bytes, or accounting reconstruction records.

`OwnedHostResource::transfer` consumes the owner and advances only its current accounting
generation. It requires active/open accounting, no loan root, a closed pending-machine lease,
settled historical containment, no bound adapter, and unpoisoned transport. Refusal returns the
complete owner untouched. Success preserves the physical value, subject, quota/root facts and
historical containment; it neither rebinds an adapter nor implements source-task transfer.

`transfer_with_charges` commits an explicit whole move vector and successor ownership together,
after the same eligibility fences. Quota refusal returns the complete owner unchanged; success
preserves physical ownership and historical containment while retaining the declared quota use.
Legacy transfer remains uncharged; physical size never supplies an implicit charge.

`OwnedHostResource::borrow_receiver` consumes an exact borrowed `LiveResource` into an exclusive
`HostReceiverLoan`, returning the handle on refusal. Admission checks the account's operation,
site, resource generation, current owner and declared loan root.
The Section 20 ABI constructor validates the complete declaration-qualified loan seal;
matching site and generation alone cannot admit a loan sealed for a foreign declaration.
The loan's recovery class must match issuing executable metadata retained by the account;
absent or mismatched metadata refuses
`ForeignLoan` without changing either input. Subject identity alone cannot substitute a recovery
contract. Eligible acquisition then checks
the admitted account's machine lease: cancellation refuses with `CancellationRequested`, and an
unreadable lease refuses with `PendingOperation`. The check and acquisition share the lease lock;
refusal returns the complete handle without changing accounting or poisoning transport.
`borrow_receiver_with_charges` applies an explicit whole Section 28 loan-charge vector under that
same lease, after eligibility and cancellation and before the infallible acquisition. Quota refusal
preserves the handle and every quota and acquires no loan. Ordinary borrowing uses an empty vector;
neither physical size nor observation allowance supplies implicit charges. Already
admitted loan settlement and sealed cleanup remain available after cancellation.
`borrow_receiver_from_pending(machine, owner, allowance, charges)` derives the loan and ABI
from the supplied pending machine after current-owner and exact runtime-subject checks.
Foreign execution/task subjects refuse `ForeignSubject`; absent pending work refuses
`PendingOperation`. It reuses the existing account-lease cancellation, eligibility and atomic
quota path without accepting caller-selected operation identities or recovery classes.
After cancellation validation, this pending-specific route additionally checks the account's
authoritative pending state under the same lock as charging and acquisition. A recovered pending
alias cannot reopen settled issuing work; refusal spends no quota and creates no loan fence.
Historical unqualified borrowing remains unchanged.
Cancellation retained by the supplied machine also refuses at cancellation admission, even
if its recovered lease differs from the account's uncancelled authoritative lease. This local
refusal does not cancel or settle the original issuing machine or prevent its eligible acquisition.
The caller still authenticates receiver authority and declares observation allowance/charges;
this is process-local access, not source-handle transport or pending-machine settlement.
The underlying `LiveResource`
refuses observation after accepted settlement with `SecondSettlement`, preserving progress,
state and observation allowance even for a partial winner with an open half. Generation fencing
retains observation-refusal precedence and the first fencing category on repeated requests,
including after accepted settlement. Later failure settlement also refuses with
`SecondSettlement` without changing state or issuing new poisoning evidence after a winner.
Failure-first settlement retains its exact evidence through `failure_settlement()`, separately
from successful operation settlement. It refuses later completion, observation and failure
settlement without mutation, before repeated poison or half-close classification. It supplies
no fabricated successful outcome, progress or ordinary operation-state projection.
Half-close also refuses after either kind of winner with `SecondSettlement` before state
classification or mutation, including partial winners retaining an open half. Generation fencing
remains available and does not rewrite accepted settlement or progress evidence.
`observe` retains Section 20 allowances and progress rules. Later observations must equal or
upgrade retained progress; mismatches refuse before allowance charging without changing state.
Admissible EOF closes the operation even after partial advance. Existing generation, winner
and unusable-state refusals retain precedence. Accepted `settle` projects operation state and closes only the
loan root. Refusal retains the guard and progress for another candidate. Whole-resource lifetime,
quotas and pending machine work remain separate.
`HostReceiverLoan::invoke_with_charges` admits an explicit whole update vector after existing
loan, adapter, disposal and transport checks. Quota refusal preserves the acquired guard and
progress; admitted callback errors or panics retain charges. It does not reacquire cancellation
admission for already-owned loan work or settle it. Explicit settlement and cleanup remain available.
Legacy uncharged invocation remains unchanged, with no inferred physical or observation charge.
Owner invocation, finish and transfer stay fenced even if the guard is forgotten;
dropping an unsettled guard poisons transport without
claiming settlement. Sealed emergency cleanup can still dispose the held value. These are
process-local synchronous loans, not source-evaluator borrowing or durable loan recovery.
`HostReceiverLoan::settle_failure` explicitly accepts one classified failure winner, projects
its operation state through `LiveResource::failure_state_projection`, and closes only the loan
root. Adapter failure additionally poisons transport; resource failure projects Poisoned operation
state. Neither releases accounting lifetime or pending machine work, nor disposes the held value.
Refused classification retains progress and the guard; either terminal loan route refuses later
settlement with `LoanSettled`. Failure projection remains distinct from ordinary successful
operation-state projection and cannot fabricate an accepted successful outcome.
Explicit transport finish refuses a Poisoned operation state with `IllegalLifetimeTransition`
before entering Finishing or invoking its finalizer, after current-owner validation. Accounting
remains unchanged and sealed emergency release can still dispose the held value.

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
`ResourceLedger::project_operation_state` consumes that projection.
Canonical `OperationSettlement` text retains the observed outcome separately from derived state,
so accepted and rejected unstarted work cannot collapse into identical evidence text.
`DedupRecord::restore` preserves a retired record's advanced owner fence separately from its
historical settlement owner. Equal or regressed retirement fences refuse; authoritative and
compacted records still require the exact settlement owner. The caller authenticates retained
retirement facts; restoration supplies no journal authentication or dispatch authority.
`DedupRecord::compact` preserves retired and rejected-stale-owner refusal states and owner
fences. Updating retention bounds cannot revive dispatch proof or fabricate missing settlement.
Restoration also checks that the resource generation belongs to the presented operation,
including rejected records with no settlement. Mixed identities refuse before record publication;
this consistency check does not authenticate caller-supplied evidence.
`DedupRecord::rejected_stale_owner` now returns `Result` and reuses restoration validation.
Callers must handle `ForeignOperation` when the generation belongs to another operation;
valid rejection records still carry no settlement or dispatch proof.
Registry failure settlement and adapter-failure poisoning likewise require the accompanying binding. Evidence still selects
its own exact account; the binding must name that operation/generation and match its issuing
execution/task. `EvidenceSubjectMismatch` and `ForeignSubject` refuse before mutation, while
unsettled projection and absent evidence-selected account refusals retain precedence. A
projection exists only after the supplied `LiveResource` accepted its own Section 20 settlement.
That exact operation and resource generation select the account, and the accepted owner generation
must still be current. Ordinary and failure projections additionally compare the live handle's
recovery class with the selected account's issuing metadata after current-owner validation.
Missing or substituted recovery metadata returns `RecoveryContractMismatch` without accounting
mutation or coordinator publication; a caller binding cannot replace the account's contract.
A fenced generation projects `Poisoned` even when its retained completion
would otherwise derive another state; projection preserves the fence without rewriting settlement
or progress evidence.
Once the ledger retains `Poisoned`, older non-poisoned projections refuse with
`PoisonedOperationStateRevival` without changing any accounting fact.
Half-closed, consumed and closed generations likewise refuse projections restoring an open half with
`TerminalOperationStateRevival`. Current-owner validation still precedes this refusal;
repeated terminal projection and subsequent poison fencing remain available.
The route updates only the distinct operation-state field; it does not settle whole-resource
lifetime, change quotas or roots, or reconstruct or claim a host resource. Unsettled,
unknown-subject, or stale-owner projections leave the account unchanged, as required by
`GNT-28.12-operation-state-projection`.
`ResourceRegistry::project_failure_state` and
`ExecutionCoordinator::project_resource_failure_state` separately consume the retained failure
projection through the same subject/provenance, current-owner, terminal-state and publication fences.
They change only operation state, preserving lifetime, quotas, roots, physical ownership and pending
work. Ordinary successful projection still refuses failure winners; refusal publishes nothing.

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
accounting writes. `renew_resource_quota`, `close_resource_liveness_root`, `retire_resource_record`
and `delete_resource_record` retain the existing registry renewal and retention checks under that
same publication fence. They do not dispose physical ownership, settle pending machine work or
refund a released live-account place; logical instants and successor generations are explicit
model inputs. `settle_resource_from_post_failure` selects the model-issued evidence's exact
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
  the lifetime of that value. A subject rebuilt from ordinary accounting-only declared capture,
  or reclaimed and readmitted, holds a fresh unsettled settlement; that accounting-only path
  publishes no cross-recovery single-settlement claim. Explicit containment capture
  instead preserves historical ownership and the accepted winner, including its second-settlement
  refusal; it is not by itself authenticated journal recovery.
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

## Bounded deterministic string construction

String length reads the exact scalar count retained in immutable logical-value metrics after
checking the operand type. It avoids rescanning the input; shared copies retain the same count.
Length conversion and transition charging remain unchanged. This optimization does not establish
complete semantic-work metering or cancellation-safe execution of other String primitives.

Primitive result evaluation and final logical-value construction run outside the shared
execution-budget mutex. Their existing deterministic and result-limit failures still precede
transition-budget refusal. A validated private result acquires the mutex only for its existing
single transition charge and atomic operand/program-position publication; recomputable scratch
and consumed operand storage are discarded afterward outside that lock. Temporary ownership
storage is preallocated for the closed primitive arity before locking; moving consumed operands
does not release their values inside the critical section. Semantic release and quota charges
are unchanged. This removes shared-counter contention during pure
construction, not synchronous construction latency or allocation cost, and adds no source stop point.

Ordinary aggregate construction uses the same private-candidate and single-charge publication
boundary. Live-resource classification still refuses before operand copying; result limits retain
precedence over counter exhaustion. Consumed values and origins are reclaimed after unlocking.
This does not make aggregate construction cooperative or grant live-handle transport.

Projection lookup and extended place-origin validation also run outside shared counters.
Invalid indexes and moved-out places retain their refusal precedence. Atomic publication preserves
the projected origin and the existing single charge; consumed source storage and temporary origins
are disposed after unlocking. Lookup remains synchronous and grants no new authority or stop point.

Discard likewise retains its consumed value and place origin until the existing charged stack/PC
update releases the shared budget mutex. Empty-stack refusal still precedes budget admission;
failed charging leaves the stack unchanged. Reclamation remains synchronous, with no changed
semantic release point, quota charge or latency guarantee.

Lexical scope exit retains removed value and task-handle scopes until its charged scope/PC
update unlocks shared counters, then reclaims them. Root-scope and alignment checks still
precede counter admission; failed charging removes no scope. This does not move a lexical
release point, settle task work, or promise bounded destruction latency.

Callable return validates its result outside shared counters. Nonroot return retains retired
callee frames and operand storage until charged caller restoration unlocks, preserving moved-out
facts and consumption obligations. Invalid-result refusal precedes budget admission; rejected
charging changes no frame or caller context. Root return remains uncharged. This relocates
reclamation, not semantic release or synchronous destruction latency.

Callable admission prepares and validates arguments, receiver arrangement and the callee frame
before locking shared counters. Its existing single charge publishes caller position, occurrence
and callee ownership; consumed arguments and origins remain retained until after unlock. Refusal
preserves caller state. Receiver authority, semantic release and quota charges remain unchanged;
frame construction and destruction remain synchronous without a latency guarantee.

Spawn capture validation and detached copying run outside shared execution counters, including
cleanup of a partially prepared capture vector on refusal. Preparation retains its existing
uncharged suspension and task-local occurrence semantics and publishes no partial spawn.
Copying, allocation and destruction remain synchronous without a cooperative latency guarantee.

Spawned-body completion validates before counter locking and retains consumed operand ownership
until its existing completion charge unlocks. Invalid-result refusal precedes budget admission;
failed charging consumes no operand. Outcome and obligation settlement run after unlocking,
without changing terminal semantics or claiming bounded destruction latency.

Assignment stages replacement paths and propagated exclusive-receiver candidates outside shared
counters, preserving mutability/type/path/limit refusal precedence. A single charged update installs
all validated values and clears the same moved-out/consumption facts as before. Consumed operands
and superseded values are retained until after unlocking. Refusal changes no assignment target;
this does not establish cooperative construction or bounded publication bookkeeping.

Lexical binding validates name availability, operand type and target scope before counter
admission. Its existing single charge publishes the binding and PC, retaining consumed values
and place origins until after unlocking. Refusal changes no operand, scope or PC, and the
`binding` transition label is unchanged. Reclamation remains synchronous; semantic release
points and quota charges do not move.

Boolean/Decision branching validates the condition before counter admission and publishes the
existing occurrence and target with one charge. Consumed values and origins remain owned until
after unlocking; refusal changes no operands, occurrence or PC. The `branch` label is preserved.
This relocates reclamation, not semantic release or synchronous destruction latency.

Option branches likewise prepare payload and extended place-origin facts before locking.
Their existing single charge publishes payload, occurrence and target atomically; consumed
and temporary values/origins are reclaimed after unlocking. Invalid Option refusal precedes
counter exhaustion and rejected publication preserves operands, occurrences and PC. This adds
no scheduling stop or latency bound and leaves semantic release and quota charges unchanged.

Result branches use the same preparation/publication boundary: payload extraction and exact
extended origin precede counter admission, while consumed and temporary ownership survives until
unlock. Invalid Result refusal precedes budget exhaustion; the existing single charge publishes
payload, occurrence and target. Refusal preserves staged state and the `branch` label is unchanged.
This relocates reclamation without changing semantic release or bounding destruction latency.

Enum branches prepare variant selection, optional payload and exact extended origin before
counter admission. Invalid values and unmatched variants retain refusal precedence over exhausted
budgets. One existing charge publishes payload, occurrence and target, and consumed/temporary
ownership is reclaimed after unlock. Labels, release points and quota charges remain unchanged;
this is not a cooperative or bounded-latency destruction guarantee.

Direct String equality, inequality, prefix and suffix matching compare at most 4096 UTF-8 octets per machine call
before requesting a scheduling-only executor yield. Operands and program position remain
unchanged until the Boolean result commits with the existing single transition charge.
Cancellation is checked by the existing yield/driver boundary; this adds no source cooperative-stop
observation point. Comparison scratch is private and recomputable, so checkpoint recovery restarts
from retained operands. Replay grants a finite separate yield allowance from admitted String limits.
This covers direct String operands only, not nested aggregate equality, other primitives or complete
semantic-work metering. The comparison does not hold the execution-budget lock across its chunks.

Flat String-list equality and inequality additionally share 4096 work units across member
admission and byte comparison per machine call. Even empty members spend admission work.
Private offsets preserve exact ordered results without early publication or extra semantic
charges, and recovery restarts from the retained operands. Replay budgets include the admitted
maximum String length per List member. Non-String members retain general equality semantics;
this does not bound nested aggregate equality, allocation, cloning or destruction latency.

Substring containment builds its prefix table and searches incrementally, performing at most
4096 comparison/fallback work units per call. Fallback counts even when input does not advance,
so repeated-prefix patterns do not cause quadratic rescanning or monopolize comparison work.
Scratch retains at most one prefix entry per pattern octet and is discarded on terminal settlement;
recovery restarts pure work from unchanged operands. Boolean publication still charges exactly
one transition, with cancellation observed at existing driver yields. Replay accounts for the
finite linear search work separately. Prefix-table allocation and cloning are not bounded-latency
or total-allocation guarantees, and this supplies no complete semantic-work metering contract.

Trimming scans leading/trailing boundaries in chunks of at most 4096 scalars using pinned
Unicode whitespace rules. Private scalar-boundary offsets survive scheduling yields, not
checkpoint recovery; restart recomputes them from unchanged operands. Cancellation and the
single transition charge retain their existing boundaries. This bounds whitespace scanning
only: final substring copying, logical-value construction and allocation remain synchronous
and do not establish total primitive latency or complete cancellation-safe construction.

Uppercase mapping accumulates private output in chunks of at most 4096 input scalars,
using pinned full mappings and checking each complete expansion before accumulation.
Cancellation discards scratch; checkpoint recovery recomputes it from unchanged operands.
Only the completed logical result publishes with the existing single transition charge.
Final logical construction/copying and allocation remain synchronous, so this bounds mapping
work rather than total primitive latency. Contextual lowercase mapping remains a separate path.

Contextual lowercase uses finite collection, backward context and forward mapping phases,
sharing at most 4096 scalar steps per call. The pinned Cased/Case_Ignorable properties preserve
Final_Sigma even across long ignorable runs and scheduling yields. Private scratch retains one
scalar/context flag per input scalar and bounded output, and restarts from operands on recovery.
Every full expansion is admitted before accumulation; only a completed logical value publishes
with one transition charge. Allocation, cloning, disposal and final construction remain outside
the mapping-work guarantee; complete semantic-work metering is still outstanding.

Concatenation admits its complete output scalar count from immutable String metrics before
copying private chunks of at most 4096 scalars. Numeric addition remains unchanged. Cancellation
discards private output, and recovery recomputes it from retained operands; the result publishes
atomically with the existing single transition charge. Final logical construction, allocation,
cloning and disposal remain outside this copy-work guarantee.

List joining shares a finite 4096-unit piece-admission/scalar-copy quantum. Empty pieces consume
admission work, and cached scalar metrics admit each whole separator/item before copying in
the existing order. Refusal publishes no private prefix; recovery restarts from retained operands.
Only the complete logical result publishes with one transition charge. Replay includes List-item
limits as well as String limits; final construction and allocation remain outside the work bound.

Replacement shares a finite 4096-unit quantum across incremental nonoverlapping search,
whole-piece scalar admission, copying and phase boundaries. Search retains its prefix table
between matches and never examines inserted text. Every unmatched/replacement piece is fully
counted before any of it is copied; refusal publishes no accumulated prefix. Recovery recomputes
scratch from unchanged operands and completed publication charges one transition. Allocation,
cloning, disposal and final logical construction remain outside this work guarantee.

Splitting shares a finite 4096-unit quantum across nonoverlapping search, segment admission,
scalar copying and phase boundaries. The next List place is admitted before segment construction,
preserving item-limit precedence and exact empty segments. Private items remain invisible until
one atomic List publication with the existing transition charge. Recovery recomputes scratch from
retained operands. Segment/String and final List construction, allocation, cloning and disposal
remain synchronous and outside the search/copy-work guarantee.

Concatenation, replacement and list joining check each next output piece's Unicode-scalar contribution before
appending it to private construction state. Over-limit pieces are not allocated or appended;
only the complete logical value is published. Replacement stays nonoverlapping and never rescans
replacement text. This enforces captured String limits during composition, not complete semantic
work metering or cancellation safe points; those resource-runtime obligations remain outstanding.
Splitting checks each next segment against the List-item limit before constructing its String;
an excess item refuses without publishing the private prefix. Leading, trailing and adjacent
empty segments and exact Unicode separator matching remain unchanged.
Case mapping uses bounded variants in the pinned Unicode owner, preserving contextual Final_Sigma
and full expansions. Each scalar mapping is checked before accumulation; small mapping scratch
and input-context scanning remain outside the output bound and do not establish work metering.
