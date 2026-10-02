//! Linearizable execution-scoped ownership of root and child task state.
//!
//! The coordinator has one shared mutex. Task state, logical sessions,
//! completion coordinates, and waiter registration are changed only while
//! that mutex is held. Wakers are removed with the published successor, then
//! invoked after the guard is dropped. The coordinator mutex is never held
//! while polling a host future and must not be nested with lifecycle,
//! supervision, adapter, event-delivery, or journal locks; callers snapshot
//! the required state before invoking those owners.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::task::{Context, Poll, Waker};

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::TaskStatusKind;
use gantry_core::value::ValueLimits;
use gantry_host::contracts::HostError;
use gantry_host::event::SinkId;
use gantry_ir::{CanonicalPath, StructuralPosition, TaskControlSite};
use gantry_observe::SinkPlan;

use crate::{
    ConcurrentShutdownCohortV1, ConcurrentTaskStateV1, ConcurrentTaskStatusV1,
    ConcurrentTerminalOutcomeV1, DynamicTaskHandleIdentity, ExecutionBudget,
    ExecutionBudgetSnapshot, JoinResolutionV1, JoinStartV1, LogicalSessionRegistryV1,
    LogicalSessionV1, MachineOutcome, SessionCreationModeV1, SessionError, SessionEstablishmentV1,
    TaskCreationRequestV1, TaskCreationV1, TaskOwnershipChangedV1, TaskStateError,
};

static NEXT_COORDINATOR_WAITER_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(all(test, feature = "durable"))]
mod root_tests;

#[cfg(all(feature = "concurrent", feature = "durable"))]
mod transaction;
#[cfg(all(feature = "concurrent", feature = "durable"))]
pub use transaction::DurableGraphTransaction;

/// Cloneable execution-scoped semantic coordination owner.
#[derive(Clone, Debug)]
pub struct ExecutionCoordinator {
    inner: Arc<CoordinatorInner>,
}

/// Refusal at the optional execution-scoped resource-accounting admission boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorResourceRefusal {
    /// A durable transaction currently reserves semantic publication.
    Task(TaskStateError),
    /// The presented machine belongs to another execution.
    ForeignExecution,
    /// The presented machine's task is absent from this coordinator.
    UnknownTask,
    /// Only a running task may admit a resource account.
    TaskNotRunning,
    /// Requested task or execution cancellation has closed new resource admission.
    TaskCancellationRequested,
    /// Cooperative shutdown has monotonically closed new resource acquisition.
    ResourceAdmissionClosed,
    /// Task-qualified emergency cleanup requires a fixed cancellation outcome.
    TaskNotCancelled,
    /// Task-qualified emergency cleanup requires confirmed physical driver cessation.
    TaskDriverNotSettled,
    /// This coordinator was constructed without a resource registry.
    RegistryDisabled,
    /// The registry refused the exact pending subject or its accounting facts.
    Registry(crate::ResourceRegistryRefusal),
    /// Process-local physical attachment or contained disposal refused or failed.
    Host(crate::HostResourceError),
}

/// Canonical per-subject physical outcomes, separate from semantic accounting settlement.
pub type ResourcePhysicalCleanupResults = Vec<(
    crate::ResourceSubjectBinding,
    Result<(), crate::HostResourceError>,
)>;

/// Semantic settled-prefix evidence and independent physical cleanup results for one sweep.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorResourceCleanup {
    semantic: crate::CohortEmergencyCleanup,
    physical: Vec<(
        crate::ResourceSubjectBinding,
        Result<(), crate::HostResourceError>,
    )>,
}

impl CoordinatorResourceCleanup {
    /// Returns the canonical settled prefix and first semantic refusal, if any.
    #[must_use]
    pub const fn semantic(&self) -> &crate::CohortEmergencyCleanup {
        &self.semantic
    }

    /// Returns one physical result per settled member, in the same canonical order.
    ///
    /// A member without an attached slot needs no physical disposal and reports success.
    #[must_use = "physical cleanup failures must be inspected separately from semantic release"]
    pub fn physical(
        &self,
    ) -> &[(
        crate::ResourceSubjectBinding,
        Result<(), crate::HostResourceError>,
    )] {
        &self.physical
    }
}

/// Failure while allocating one coordinator-owned per-task event sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskEventSequenceError {
    /// The requested task is not part of this execution.
    UnknownTask,
    /// The task has exhausted the portable sequence counter.
    Exhausted,
}

/// Waiter for exclusive completion of one task-backed event occurrence.
pub(crate) struct TaskEventCompletionWait {
    inner: Arc<CoordinatorInner>,
    task_id: ProtocolIdentity,
    waiter_id: u64,
    completed: bool,
}

/// Exclusive per-task turn retained through asynchronous event completion.
pub(crate) struct TaskEventCompletionPermit {
    inner: Arc<CoordinatorInner>,
    task_id: ProtocolIdentity,
    sequence: u64,
    committed: bool,
}

#[derive(Debug)]
struct CoordinatorInner {
    state: Mutex<CoordinatorState>,
}

#[derive(Debug)]
struct CoordinatorState {
    tasks: ConcurrentTaskStateV1,
    sessions: LogicalSessionRegistryV1,
    execution_budget: Option<ExecutionBudget>,
    resources: Option<crate::ResourceRegistry>,
    resource_admission_closed: bool,
    publication: u64,
    next_event_sequence: BTreeMap<ProtocolIdentity, u64>,
    task_event_completion_active: BTreeSet<ProtocolIdentity>,
    task_event_completion_waiters: BTreeMap<ProtocolIdentity, Vec<RegisteredWaiter>>,
    active_event_plan: Option<SinkPlan>,
    next_required_delivery: u64,
    pending_required_deliveries: BTreeSet<u64>,
    next_best_effort_delivery: u64,
    pending_best_effort_deliveries: BTreeSet<u64>,
    required_event_delivery_failed: bool,
    event_delivery_executor_failed: bool,
    required_delivery_waiters: Vec<RegisteredWaiter>,
    best_effort_delivery_waiters: Vec<RegisteredWaiter>,
    task_waiters: BTreeMap<ProtocolIdentity, Vec<RegisteredWaiter>>,
    foreground_waiters: Vec<RegisteredWaiter>,
    terminal_waiters: Vec<RegisteredWaiter>,
    shutdown_waiters: Vec<RegisteredWaiter>,
    /// Reserved by a durable transaction; retained if its commit is indeterminate.
    durable_publication_reserved: bool,
    /// Last committed graph task/session semantics, excluding process-local driver drift.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    durable_graph_baseline: Option<(ConcurrentTaskStateV1, LogicalSessionRegistryV1)>,
    /// Complete committed root cut retained independently of its running driver.
    #[cfg(feature = "durable")]
    durable_root: Option<crate::RecoveredDurableStateV1>,
    /// Journal-first graph event obligations, using the existing delivery model.
    #[cfg(feature = "durable")]
    durable_events: crate::RecoveredDurableEventsV1,
}

#[derive(Clone, Debug)]
struct RegisteredWaiter {
    id: u64,
    waker: Waker,
}

/// Immutable point-in-time coordinator projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionCoordinatorSnapshot {
    state: ConcurrentTaskStateV1,
    sessions: Vec<LogicalSessionV1>,
    execution_budget: Option<ExecutionBudgetSnapshot>,
    resources: Option<Vec<crate::RecoveredResourceRecord>>,
    publication: u64,
}

impl ExecutionCoordinatorSnapshot {
    /// Returns the complete root-and-child semantic task state.
    #[must_use]
    pub const fn state(&self) -> &ConcurrentTaskStateV1 {
        &self.state
    }

    /// Returns the execution-wide logical sessions in canonical identity order.
    #[must_use]
    pub fn sessions(&self) -> &[LogicalSessionV1] {
        &self.sessions
    }

    /// Returns the execution-budget projection when runtime ownership is attached.
    #[must_use]
    pub const fn execution_budget(&self) -> Option<ExecutionBudgetSnapshot> {
        self.execution_budget
    }

    /// Returns immutable accounting records when this coordinator owns a resource registry.
    ///
    /// These records are a process-local inspection projection, not a committed journal cut or
    /// physical host-resource reconstruction. A disabled registry is distinct from an empty one.
    #[must_use]
    pub fn resource_records(&self) -> Option<&[crate::RecoveredResourceRecord]> {
        self.resources.as_deref()
    }

    /// Returns the monotonic publication generation captured with the state.
    #[must_use]
    pub const fn publication(&self) -> u64 {
        self.publication
    }
}

impl ExecutionCoordinator {
    /// Creates one coordinator around the existing task and session models.
    pub fn new(
        tasks: ConcurrentTaskStateV1,
        sessions: LogicalSessionRegistryV1,
    ) -> Result<Self, TaskStateError> {
        Self::new_inner(tasks, sessions, None, None)
    }

    /// Creates one coordinator whose snapshots include a shared runtime budget.
    pub fn new_with_budget(
        tasks: ConcurrentTaskStateV1,
        sessions: LogicalSessionRegistryV1,
        execution_budget: ExecutionBudget,
    ) -> Result<Self, TaskStateError> {
        if execution_budget.snapshot().execution != tasks.execution_id() {
            return Err(TaskStateError::InvalidTaskMachine);
        }
        Self::new_inner(tasks, sessions, Some(execution_budget), None)
    }

    /// Creates a budget-sharing coordinator with explicit finite resource accounting ceilings.
    ///
    /// Both ceilings admit zero. Cloned handles share accounting without enabling host transport
    /// or persisting registry policy in the existing durable graph wire.
    pub fn new_with_budget_and_resource_limits(
        tasks: ConcurrentTaskStateV1,
        sessions: LogicalSessionRegistryV1,
        execution_budget: ExecutionBudget,
        maximum_live_resources: u64,
        maximum_pending_operations: u64,
    ) -> Result<Self, TaskStateError> {
        if execution_budget.snapshot().execution != tasks.execution_id() {
            return Err(TaskStateError::InvalidTaskMachine);
        }
        Self::new_inner(
            tasks,
            sessions,
            Some(execution_budget),
            Some(crate::ResourceRegistry::with_limits(
                maximum_live_resources,
                maximum_pending_operations,
            )),
        )
    }

    /// Creates one shared accounting registry with an explicit live-account ceiling.
    ///
    /// Cloned coordinator handles share this registry under the existing coordinator mutex.
    /// It is not attached automatically to evaluator dispatch or persisted in durable task cuts.
    /// The ceiling limits live accounts only, not retained records or snapshot size.
    pub fn new_with_resource_limit(
        tasks: ConcurrentTaskStateV1,
        sessions: LogicalSessionRegistryV1,
        maximum_live_resources: u64,
    ) -> Result<Self, TaskStateError> {
        Self::new_inner(
            tasks,
            sessions,
            None,
            Some(crate::ResourceRegistry::with_live_limit(
                maximum_live_resources,
            )),
        )
    }

    /// Creates shared accounting with separate finite live and pending-operation ceilings.
    ///
    /// Pending capacity follows admitted machine settlement leases, not resource lifetime.
    /// Neither policy reconstructs pending work or attaches automatically to evaluator dispatch.
    pub fn new_with_resource_limits(
        tasks: ConcurrentTaskStateV1,
        sessions: LogicalSessionRegistryV1,
        maximum_live_resources: u64,
        maximum_pending_operations: u64,
    ) -> Result<Self, TaskStateError> {
        Self::new_inner(
            tasks,
            sessions,
            None,
            Some(crate::ResourceRegistry::with_limits(
                maximum_live_resources,
                maximum_pending_operations,
            )),
        )
    }

    /// Reconstructs execution-owned accounting only from declared resource records.
    ///
    /// Every binding must name this execution and a known task; terminal tasks may retain
    /// accounting for cleanup. Carrier, kind, duplicate, owner-generation and live-limit checks
    /// are delegated to the registry before any coordinator is published. Physical values,
    /// pending-operation policy and pending work are not reconstructed.
    pub fn new_with_recovered_resources(
        tasks: ConcurrentTaskStateV1,
        sessions: LogicalSessionRegistryV1,
        maximum_live_resources: u64,
        recovered: Vec<crate::RecoveredResourceRecord>,
    ) -> Result<Self, CoordinatorResourceRefusal> {
        for record in &recovered {
            if record.subject().execution_id() != tasks.execution_id() {
                return Err(CoordinatorResourceRefusal::ForeignExecution);
            }
            if tasks.task_record(record.subject().task_id()).is_none() {
                return Err(CoordinatorResourceRefusal::UnknownTask);
            }
        }
        let resources =
            crate::ResourceRegistry::reconstruct(Some(maximum_live_resources), recovered)
                .map_err(CoordinatorResourceRefusal::Registry)?;
        Self::new_inner(tasks, sessions, None, Some(resources))
            .map_err(CoordinatorResourceRefusal::Task)
    }

    fn new_inner(
        tasks: ConcurrentTaskStateV1,
        sessions: LogicalSessionRegistryV1,
        execution_budget: Option<ExecutionBudget>,
        resources: Option<crate::ResourceRegistry>,
    ) -> Result<Self, TaskStateError> {
        if sessions
            .sessions()
            .any(|session| session.execution_id != tasks.execution_id())
        {
            return Err(TaskStateError::SessionExecutionMismatch);
        }
        Ok(Self {
            inner: Arc::new(CoordinatorInner {
                state: Mutex::new(CoordinatorState {
                    tasks,
                    sessions,
                    execution_budget,
                    resources,
                    resource_admission_closed: false,
                    publication: 0,
                    next_event_sequence: BTreeMap::new(),
                    task_event_completion_active: BTreeSet::new(),
                    task_event_completion_waiters: BTreeMap::new(),
                    active_event_plan: None,
                    next_required_delivery: 0,
                    pending_required_deliveries: BTreeSet::new(),
                    next_best_effort_delivery: 0,
                    pending_best_effort_deliveries: BTreeSet::new(),
                    required_event_delivery_failed: false,
                    event_delivery_executor_failed: false,
                    required_delivery_waiters: Vec::new(),
                    best_effort_delivery_waiters: Vec::new(),
                    task_waiters: BTreeMap::new(),
                    foreground_waiters: Vec::new(),
                    terminal_waiters: Vec::new(),
                    shutdown_waiters: Vec::new(),
                    durable_publication_reserved: false,
                    #[cfg(all(feature = "concurrent", feature = "durable"))]
                    durable_graph_baseline: None,
                    #[cfg(feature = "durable")]
                    durable_root: None,
                    #[cfg(feature = "durable")]
                    durable_events: crate::RecoveredDurableEventsV1::default(),
                }),
            }),
        })
    }

    /// Returns one linearizable point-in-time state projection.
    #[must_use]
    pub fn snapshot(&self) -> ExecutionCoordinatorSnapshot {
        snapshot_from(&lock(&self.inner.state))
    }

    /// Admits accounting facts for one running task's exact pending live-resource operation.
    ///
    /// Publication reservations, foreign executions, absent or non-running tasks, disabled
    /// registries, and registry refusals change neither records nor publication. Successful
    /// admission publishes once. The coordinator retains the account; callers receive no mutable
    /// registry or account and snapshots contain only declared reconstruction-record facts.
    pub fn admit_resource(
        &self,
        machine: &crate::Machine,
        carrier: gantry_ir::ResourceCarrier,
        record: gantry_ir::DurableResourceRecord,
    ) -> Result<(), CoordinatorResourceRefusal> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state).map_err(CoordinatorResourceRefusal::Task)?;
        if machine.execution_id() != state.tasks.execution_id() {
            return Err(CoordinatorResourceRefusal::ForeignExecution);
        }
        let task = state
            .tasks
            .task_record(machine.task_id())
            .ok_or(CoordinatorResourceRefusal::UnknownTask)?;
        if !matches!(task.status(), ConcurrentTaskStatusV1::Running) {
            return Err(CoordinatorResourceRefusal::TaskNotRunning);
        }
        if state
            .tasks
            .task_cancellation_reason(machine.task_id())
            .is_some()
            || state.tasks.execution_cancellation_reason().is_some()
        {
            return Err(CoordinatorResourceRefusal::TaskCancellationRequested);
        }
        if state.resource_admission_closed {
            return Err(CoordinatorResourceRefusal::ResourceAdmissionClosed);
        }
        state
            .resources
            .as_mut()
            .ok_or(CoordinatorResourceRefusal::RegistryDisabled)?
            .admit_pending_operation(machine, carrier, record)
            .map_err(CoordinatorResourceRefusal::Registry)?;
        state.publication = state.publication.wrapping_add(1);
        Ok(())
    }

    /// Atomically admits accounting and physical ownership for one running task's pending operation.
    ///
    /// Acquisition retains the machine cancellation lease through both registry insertions and
    /// publishes once. Refusal returns the physical input outside the coordinator lock, without
    /// an account, physical slot or pending-capacity mutation. Association and authority are the
    /// embedding caller's responsibility; this does not complete source-resource transport.
    pub fn admit_resource_host_value<T: std::any::Any + Send>(
        &self,
        machine: &crate::Machine,
        carrier: gantry_ir::ResourceCarrier,
        record: gantry_ir::DurableResourceRecord,
        value: T,
    ) -> Result<(), Box<(CoordinatorResourceRefusal, T)>> {
        let mut value = Some(value);
        let result = (|| {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state).map_err(CoordinatorResourceRefusal::Task)?;
            if machine.execution_id() != state.tasks.execution_id() {
                return Err(CoordinatorResourceRefusal::ForeignExecution);
            }
            let task = state
                .tasks
                .task_record(machine.task_id())
                .ok_or(CoordinatorResourceRefusal::UnknownTask)?;
            if !matches!(task.status(), ConcurrentTaskStatusV1::Running) {
                return Err(CoordinatorResourceRefusal::TaskNotRunning);
            }
            if state
                .tasks
                .task_cancellation_reason(machine.task_id())
                .is_some()
                || state.tasks.execution_cancellation_reason().is_some()
            {
                return Err(CoordinatorResourceRefusal::TaskCancellationRequested);
            }
            if state.resource_admission_closed {
                return Err(CoordinatorResourceRefusal::ResourceAdmissionClosed);
            }
            let resources = state
                .resources
                .as_mut()
                .ok_or(CoordinatorResourceRefusal::RegistryDisabled)?;
            let subject =
                machine
                    .pending_resource_subject()
                    .ok_or(CoordinatorResourceRefusal::Registry(
                        crate::ResourceRegistryRefusal::NoPendingResourceSubject,
                    ))?;
            let input = value
                .take()
                .unwrap_or_else(|| unreachable!("input transferred once"));
            if let Err(refusal) = resources.admit_host_value(subject, carrier, record, input) {
                let (error, returned) = *refusal;
                value = Some(returned);
                return Err(CoordinatorResourceRefusal::Registry(error));
            }
            state.publication = state.publication.wrapping_add(1);
            Ok(())
        })();
        result.map_err(|error| {
            Box::new((
                error,
                value
                    .take()
                    .unwrap_or_else(|| unreachable!("refused input remains owned")),
            ))
        })
    }

    /// Charges a complete vector against one coordinator-owned account under its current owner.
    ///
    /// The registry's subject, owner, lifetime and quota rules remain authoritative. Refusal
    /// commits no charge and advances no coordinator publication.
    pub fn charge_resource(
        &self,
        subject: &crate::ResourceSubjectBinding,
        owner: gantry_ir::OwnerGeneration,
        action: gantry_ir::ResourceAction,
        charges: &[gantry_ir::Charge],
    ) -> Result<(), CoordinatorResourceRefusal> {
        self.mutate_resources(|resources| resources.charge(subject, owner, action, charges))
    }

    /// Advances same-task accounting ownership without moving its account or physical slot.
    ///
    /// The registry enforces exact provenance and all existing transfer obligations. A successful
    /// advancement publishes once; refusal leaves publication unchanged. This grants no authority
    /// and does not transfer ownership to another task or reconstruct a physical resource.
    pub fn advance_resource_owner(
        &self,
        subject: &crate::ResourceSubjectBinding,
        owner: gantry_ir::OwnerGeneration,
        successor: gantry_ir::OwnerGeneration,
    ) -> Result<(), CoordinatorResourceRefusal> {
        self.mutate_resources(|resources| resources.advance_owner(subject, owner, successor))
    }

    /// Records one coordinator-held account's accepted containment completion.
    ///
    /// Historical containment remains independent of resource lifetime and machine settlement;
    /// refusal publishes nothing and success never releases resource or pending-operation quota.
    pub fn settle_resource_containment(
        &self,
        subject: &crate::ResourceSubjectBinding,
        owner: gantry_ir::OwnerGeneration,
        completion: gantry_ir::Completion,
    ) -> Result<gantry_ir::ExternalOutcome, CoordinatorResourceRefusal> {
        self.mutate_resources(|resources| resources.settle_containment(subject, owner, completion))
    }

    /// Projects only a live resource's retained accepted settlement into its matching account.
    ///
    /// This changes operation-state accounting only, not whole-resource lifetime or quota
    /// release. Unsettled, unknown-subject and stale-owner refusals advance no publication.
    pub fn project_resource_operation_state(
        &self,
        live: &gantry_ir::LiveResource,
        subject: &crate::ResourceSubjectBinding,
    ) -> Result<gantry_ir::ResourceState, CoordinatorResourceRefusal> {
        self.mutate_resources(|resources| resources.project_operation_state(live, subject))
    }

    /// Advances one coordinator-owned account to finishing under its current owner.
    pub fn begin_resource_finish(
        &self,
        subject: &crate::ResourceSubjectBinding,
        owner: gantry_ir::OwnerGeneration,
    ) -> Result<gantry_ir::ResourceLifetimeState, CoordinatorResourceRefusal> {
        self.mutate_resources(|resources| resources.begin_finish(subject, owner))
    }

    /// Settles accounting lifetime from model-issued resource-poisoning evidence.
    ///
    /// The evidence selects its own exact operation and resource generation. Adapter-only
    /// failure evidence cannot settle this lifetime; successful resource poisoning releases
    /// its live place while retaining the accounting record. Refusal advances no publication.
    pub fn settle_resource_from_post_failure(
        &self,
        settlement: &gantry_ir::PostFailureSettlement,
        settled_at: u64,
        subject: &crate::ResourceSubjectBinding,
    ) -> Result<gantry_ir::ResourceLifetimeState, CoordinatorResourceRefusal> {
        self.mutate_resources(|resources| {
            resources.settle_from_post_failure(settlement, settled_at, subject)
        })
    }

    /// Completes accounting finalization and releases the live place, not retained records.
    pub fn complete_resource_finalization(
        &self,
        subject: &crate::ResourceSubjectBinding,
        owner: gantry_ir::OwnerGeneration,
        settled_at: u64,
    ) -> Result<gantry_ir::ResourceLifetimeState, CoordinatorResourceRefusal> {
        self.mutate_resources(|resources| {
            resources.complete_finalization(subject, owner, settled_at)
        })
    }

    /// Consumes one sealed cleanup witness to settle one coordinator-owned account.
    ///
    /// The witness is consumed even on refusal, just as at the registry boundary. Cleanup
    /// remains available after task settlement; it does not revive task admission.
    pub fn emergency_release_resource(
        &self,
        subject: &crate::ResourceSubjectBinding,
        cleanup: gantry_ir::EmergencyCleanupWitness,
    ) -> Result<gantry_ir::ResourceLifetimeState, CoordinatorResourceRefusal> {
        self.mutate_resources(|resources| resources.settle_from_emergency_cleanup(subject, cleanup))
    }

    /// Settles a sealed cohort's canonical prefix and disposes that prefix outside shared locks.
    ///
    /// Semantic refusal preserves earlier releases and leaves later members unchanged. Physical
    /// failure is reported separately and never skips another settled member's cleanup. Witnesses
    /// are consumed on all paths. A nonempty settled prefix advances accounting publication once.
    pub fn emergency_release_resource_cohort(
        &self,
        cleanups: Vec<(
            crate::ResourceSubjectBinding,
            gantry_ir::EmergencyCleanupWitness,
        )>,
    ) -> Result<CoordinatorResourceCleanup, CoordinatorResourceRefusal> {
        self.emergency_release_selected_resources(|_| Ok(cleanups))
    }

    /// Selects live accounting owned by cancelled, physically settled tasks under one lock.
    ///
    /// The caller authenticates the sealed escalation's association with this task cohort.
    /// Unknown, non-cancelled or still-owned drivers refuse before any resource mutation.
    /// Already-terminal resource accounts are excluded; pending machine work is never settled
    /// by this route. Physical destruction remains synchronous and runs outside the lock.
    pub fn emergency_release_task_resources(
        &self,
        task_ids: &[ProtocolIdentity],
        escalation: gantry_ir::Escalation,
    ) -> Result<CoordinatorResourceCleanup, CoordinatorResourceRefusal> {
        self.emergency_release_selected_resources(|state| {
            for task_id in task_ids {
                let task = state
                    .tasks
                    .task_record(*task_id)
                    .ok_or(CoordinatorResourceRefusal::UnknownTask)?;
                if !matches!(task.status(), ConcurrentTaskStatusV1::Cancelled(_)) {
                    return Err(CoordinatorResourceRefusal::TaskNotCancelled);
                }
                if task.driver_ownership() != crate::TaskDriverOwnershipV1::PhysicallySettled {
                    return Err(CoordinatorResourceRefusal::TaskDriverNotSettled);
                }
            }
            let resources = state
                .resources
                .as_ref()
                .ok_or(CoordinatorResourceRefusal::RegistryDisabled)?;
            Ok(resources
                .live_subjects_for_tasks(task_ids)
                .into_iter()
                .map(|subject| (subject, escalation.admit_emergency_release()))
                .collect())
        })
    }

    /// Validates and selects one witnessed cohort before settlement under the publication fence.
    fn emergency_release_selected_resources(
        &self,
        select: impl FnOnce(
            &CoordinatorState,
        ) -> Result<
            Vec<(
                crate::ResourceSubjectBinding,
                gantry_ir::EmergencyCleanupWitness,
            )>,
            CoordinatorResourceRefusal,
        >,
    ) -> Result<CoordinatorResourceCleanup, CoordinatorResourceRefusal> {
        let (semantic, jobs) = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state).map_err(CoordinatorResourceRefusal::Task)?;
            let cleanups = select(&state)?;
            let resources = state
                .resources
                .as_mut()
                .ok_or(CoordinatorResourceRefusal::RegistryDisabled)?;
            let semantic = resources.settle_cohort_from_emergency_cleanup(cleanups);
            let mut jobs = Vec::with_capacity(semantic.settled().len());
            for settled in semantic.settled() {
                let subject = settled.subject();
                let owner = resources
                    .account(subject)
                    .unwrap_or_else(|| unreachable!("settled prefix retains its account"))
                    .ledger()
                    .owner();
                let job = match resources.extract_host_disposal(subject, owner) {
                    Err(crate::HostResourceError::NotAttached) => Ok(None),
                    result => result,
                };
                jobs.push((subject.clone(), job));
            }
            if !semantic.settled().is_empty() {
                state.publication = state.publication.wrapping_add(1);
            }
            (semantic, jobs)
        };
        let physical = jobs
            .into_iter()
            .map(|(subject, job)| {
                let result = job.and_then(|job| {
                    job.map_or(Ok(()), crate::resource_transport::HostDisposalJob::run)
                });
                (subject, result)
            })
            .collect();
        let waiters = take_shutdown_waiters_if_quiescent(&mut lock(&self.inner.state));
        wake_all(waiters);
        Ok(CoordinatorResourceCleanup { semantic, physical })
    }

    /// Attaches physical ownership to an existing account without changing accounting publication.
    ///
    /// Refused inputs remain owned outside the coordinator lock and are returned untouched.
    /// The embedding caller authenticates association and authority; this grants neither.
    pub fn attach_resource_host_value<T: std::any::Any + Send>(
        &self,
        subject: &crate::ResourceSubjectBinding,
        owner: gantry_ir::OwnerGeneration,
        value: T,
    ) -> Result<(), Box<(CoordinatorResourceRefusal, T)>> {
        let mut value = Some(value);
        let result = (|| {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state).map_err(CoordinatorResourceRefusal::Task)?;
            if subject.execution_id() != state.tasks.execution_id() {
                return Err(CoordinatorResourceRefusal::ForeignExecution);
            }
            let task = state
                .tasks
                .task_record(subject.task_id())
                .ok_or(CoordinatorResourceRefusal::UnknownTask)?;
            if !matches!(task.status(), ConcurrentTaskStatusV1::Running) {
                return Err(CoordinatorResourceRefusal::TaskNotRunning);
            }
            if state
                .tasks
                .task_cancellation_reason(subject.task_id())
                .is_some()
                || state.tasks.execution_cancellation_reason().is_some()
            {
                return Err(CoordinatorResourceRefusal::TaskCancellationRequested);
            }
            if state.resource_admission_closed {
                return Err(CoordinatorResourceRefusal::ResourceAdmissionClosed);
            }
            let resources = state
                .resources
                .as_mut()
                .ok_or(CoordinatorResourceRefusal::RegistryDisabled)?;
            let input = value
                .take()
                .unwrap_or_else(|| unreachable!("input transferred once"));
            match resources.attach_host_value(subject, owner, input) {
                Ok(()) => Ok(()),
                Err(refusal) => {
                    let (error, returned) = *refusal;
                    value = Some(returned);
                    Err(CoordinatorResourceRefusal::Host(error))
                }
            }
        })();
        result.map_err(|error| {
            Box::new((
                error,
                value
                    .take()
                    .unwrap_or_else(|| unreachable!("refused input remains owned")),
            ))
        })
    }

    /// Executes contained physical destruction after releasing the coordinator mutex.
    ///
    /// Extraction is owner- and publication-fenced. Its process-local pending status blocks
    /// normal finalization until cleanup completes; failure remains recorded. Neither extraction
    /// nor completion changes accounting publication or semantic quota.
    pub fn dispose_resource_host_value(
        &self,
        subject: &crate::ResourceSubjectBinding,
        owner: gantry_ir::OwnerGeneration,
    ) -> Result<(), CoordinatorResourceRefusal> {
        let job = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state).map_err(CoordinatorResourceRefusal::Task)?;
            state
                .resources
                .as_mut()
                .ok_or(CoordinatorResourceRefusal::RegistryDisabled)?
                .extract_host_disposal(subject, owner)
                .map_err(CoordinatorResourceRefusal::Host)?
        };
        let result = job
            .map_or(Ok(()), crate::resource_transport::HostDisposalJob::run)
            .map_err(CoordinatorResourceRefusal::Host);
        let waiters = take_shutdown_waiters_if_quiescent(&mut lock(&self.inner.state));
        wake_all(waiters);
        result
    }

    /// Closes new accounting and physical acquisition without cancelling accepted work.
    ///
    /// Returns true only for the first closure. This process-local fence may close during a
    /// durable publication reservation; it changes no accounting publication, lease or quota.
    pub fn close_resource_admission(&self) -> bool {
        let mut state = lock(&self.inner.state);
        let changed = !state.resource_admission_closed;
        state.resource_admission_closed = true;
        changed
    }

    /// Reports whether resource acquisition has been closed by this execution owner.
    #[must_use]
    pub fn resource_admission_is_closed(&self) -> bool {
        lock(&self.inner.state).resource_admission_closed
    }

    /// Reports whether active or finishing accounting still requires semantic settlement.
    ///
    /// This obligation is independent of physical slot presence and does not release quota.
    #[must_use]
    pub fn has_unsettled_resource_accounts(&self) -> bool {
        lock(&self.inner.state)
            .resources
            .as_ref()
            .is_some_and(|resources| resources.live_resources() != 0)
    }

    /// Reports admitted machine work still awaiting settlement, independently of accounting.
    ///
    /// An unreadable lease conservatively remains pending; this inspection releases no capacity.
    #[must_use]
    pub fn has_pending_resource_operations(&self) -> bool {
        lock(&self.inner.state)
            .resources
            .as_ref()
            .is_some_and(|resources| resources.pending_operations() != 0)
    }

    /// Reports whether any physical resource value remains held or in-flight.
    ///
    /// Completed disposal failures are quiescent but remain independently reportable.
    #[must_use]
    pub fn has_resource_host_values(&self) -> bool {
        lock(&self.inner.state)
            .resources
            .as_ref()
            .is_some_and(|resources| !resources.host_values_are_quiescent())
    }

    /// Reports whether already-settled physical obligations require a cleanup sweep.
    ///
    /// This is a point-in-time hint; extraction rechecks under the coordinator mutex.
    #[must_use]
    pub fn has_settled_resource_host_values(&self) -> bool {
        lock(&self.inner.state)
            .resources
            .as_ref()
            .is_some_and(|resources| !resources.settled_host_subjects().is_empty())
    }

    /// Drains physical obligations of semantically settled accounts without changing accounting.
    ///
    /// Selection and extraction respect publication reservations. Active and finishing accounts
    /// remain untouched. Every selected result is reported in canonical runtime-subject order;
    /// destruction runs unlocked and one failure never skips another selected member.
    pub fn dispose_settled_resource_host_values(
        &self,
    ) -> Result<ResourcePhysicalCleanupResults, CoordinatorResourceRefusal> {
        let jobs = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state).map_err(CoordinatorResourceRefusal::Task)?;
            let resources = state
                .resources
                .as_mut()
                .ok_or(CoordinatorResourceRefusal::RegistryDisabled)?;
            resources
                .settled_host_subjects()
                .into_iter()
                .map(|(subject, owner)| {
                    let job = resources.extract_host_disposal(&subject, owner);
                    (subject, job)
                })
                .collect::<Vec<_>>()
        };
        let results = jobs
            .into_iter()
            .map(|(subject, job)| {
                (
                    subject,
                    job.and_then(|job| {
                        job.map_or(Ok(()), crate::resource_transport::HostDisposalJob::run)
                    }),
                )
            })
            .collect();
        let waiters = take_shutdown_waiters_if_quiescent(&mut lock(&self.inner.state));
        wake_all(waiters);
        Ok(results)
    }

    /// Serializes one internal registry mutation and publishes only its successful result.
    fn mutate_resources<T>(
        &self,
        mutation: impl FnOnce(&mut crate::ResourceRegistry) -> Result<T, crate::ResourceRegistryRefusal>,
    ) -> Result<T, CoordinatorResourceRefusal> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state).map_err(CoordinatorResourceRefusal::Task)?;
        let result = mutation(
            state
                .resources
                .as_mut()
                .ok_or(CoordinatorResourceRefusal::RegistryDisabled)?,
        )
        .map_err(CoordinatorResourceRefusal::Registry)?;
        state.publication = state.publication.wrapping_add(1);
        Ok(result)
    }

    /// Installs a journal-committed sequential root cut after causal event evidence.
    ///
    /// The durable execution owner invokes this only after committing the cut
    /// and its event obligations. Validation and task transitions are private
    /// until installation; notifications run after unlocking. Child graphs use
    /// the graph transaction instead of this sequential projection.
    #[cfg(feature = "durable")]
    pub fn publish_committed_root(
        &self,
        recovered: &crate::RecoveredDurableStateV1,
    ) -> Result<(), TaskStateError> {
        use crate::DurableCommitCutV1;
        let projection = recovered.clone();
        let sessions = recovered
            .sessions()
            .cloned()
            .ok_or(TaskStateError::SessionExecutionMismatch)?;
        let budget =
            ExecutionBudget::recover_from_checkpoint(recovered.machine().budget_checkpoint())
                .map_err(|_| TaskStateError::InvalidTaskMachine)?;
        let waiters = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state)?;
            if state
                .resources
                .as_ref()
                .is_some_and(crate::ResourceRegistry::has_uncheckpointed_state)
            {
                return Err(TaskStateError::ResourceStateUnsupported);
            }
            let root = state.tasks.root_task_id();
            if state.tasks.task_record_count() != 1
                || recovered.machine().execution_id() != state.tasks.execution_id()
                || recovered.machine().task_id() != root
                || state
                    .durable_root
                    .as_ref()
                    .is_some_and(|prior| prior.latest_sequence() >= recovered.latest_sequence())
            {
                return Err(TaskStateError::InvalidTaskMachine);
            }
            let mut tasks = state.tasks.clone();
            let outcome = || {
                recovered
                    .machine()
                    .outcome()
                    .cloned()
                    .ok_or(TaskStateError::InvalidTransition)
            };
            match recovered.latest_cut() {
                DurableCommitCutV1::TaskSettlement => {
                    if tasks.task_record(root).is_some_and(|record| {
                        matches!(record.status(), ConcurrentTaskStatusV1::Submitting)
                    }) {
                        tasks.fail_root_submission(outcome()?, true)?;
                    } else {
                        tasks.settle(root, outcome()?)?;
                    }
                }
                DurableCommitCutV1::ForegroundCompletion => tasks.complete_foreground(outcome()?)?,
                DurableCommitCutV1::TerminalCompletion => {
                    tasks.complete_terminal()?;
                }
                _ => return Err(TaskStateError::InvalidTransition),
            }
            state.tasks = tasks;
            state.sessions = sessions;
            state.execution_budget = Some(budget);
            state.durable_events = projection.events().clone();
            state.durable_root = Some(projection);
            state.publication = state.publication.wrapping_add(1);
            let mut waiters = Vec::new();
            if task_is_settled(&state.tasks, root) {
                waiters.extend(state.task_waiters.remove(&root).unwrap_or_default());
            }
            if state.tasks.foreground_outcome().is_some() {
                waiters.append(&mut state.foreground_waiters);
            }
            if state.tasks.terminal_outcome().is_some() {
                waiters.append(&mut state.terminal_waiters);
            }
            waiters.extend(take_shutdown_waiters_if_quiescent(&mut state));
            waiters
        };
        wake_all(waiters);
        Ok(())
    }

    /// Returns an isolated copy of the last published durable root cut.
    #[cfg(feature = "durable")]
    #[must_use]
    pub fn committed_root(&self) -> Option<crate::RecoveredDurableStateV1> {
        lock(&self.inner.state).durable_root.clone()
    }

    /// Returns committed causal event obligations without driving delivery.
    #[cfg(feature = "durable")]
    #[must_use]
    pub fn committed_events(&self) -> crate::RecoveredDurableEventsV1 {
        lock(&self.inner.state).durable_events.clone()
    }

    /// Publishes event-only journal progress without changing semantic graph state.
    #[cfg(feature = "durable")]
    pub fn publish_committed_events(
        &self,
        events: crate::RecoveredDurableEventsV1,
    ) -> Result<(), TaskStateError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)?;
        state.durable_events = events;
        state.publication = state.publication.wrapping_add(1);
        Ok(())
    }

    /// Captures a quiescent graph while task and session state cannot change.
    ///
    /// The caller must borrow every live machine, preventing its driver from
    /// advancing during capture. The budget revision check rejects charges by
    /// other holders. No guard escapes this synchronous operation.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub fn capture_checkpoint(
        &self,
        foreground: &crate::Machine,
        children: &BTreeMap<ProtocolIdentity, crate::Machine>,
    ) -> Result<crate::ConcurrentDurableCheckpointV4, crate::ConcurrentDurableCheckpointError> {
        let state = lock(&self.inner.state);
        if state
            .resources
            .as_ref()
            .is_some_and(crate::ResourceRegistry::has_uncheckpointed_state)
        {
            return Err(crate::ConcurrentDurableCheckpointError::ResourceStateUnsupported);
        }
        let budget = state
            .execution_budget
            .as_ref()
            .ok_or(crate::ConcurrentDurableCheckpointError::InvalidCheckpoint)?;
        let (foreground, _foreground_resource_admission_guard) = foreground
            .clone_with_staged_budget(budget.clone())
            .map_err(crate::ConcurrentDurableCheckpointError::Machine)?;
        let mut projected_children = BTreeMap::new();
        let mut child_resource_admission_guards = Vec::new();
        for (task_id, machine) in children {
            let (machine, guard) = machine
                .clone_with_staged_budget(budget.clone())
                .map_err(crate::ConcurrentDurableCheckpointError::Machine)?;
            projected_children.insert(*task_id, machine);
            child_resource_admission_guards.push(guard);
        }
        crate::ConcurrentDurableCheckpointV4::capture_coordinated(
            &foreground,
            &projected_children,
            &state.tasks,
            &state.sessions,
            budget,
        )
    }

    /// Publishes successful root submission and supervision registration.
    pub fn resolve_root_submission(&self) -> Result<(), TaskStateError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)?;
        state.tasks.resolve_root_submission()?;
        state.publication = state.publication.wrapping_add(1);
        Ok(())
    }

    /// Preserves the committed cut before resetting process-local driver ownership.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) fn prepare_recovered_driver_admission(&self) -> Vec<ProtocolIdentity> {
        let mut state = lock(&self.inner.state);
        state.durable_graph_baseline = Some((state.tasks.clone(), state.sessions.clone()));
        state.tasks.prepare_recovered_driver_admission()
    }

    /// Registers one complete recovered replacement-driver set at one linearization point.
    pub(crate) fn register_recovered_drivers(
        &self,
        task_ids: &[ProtocolIdentity],
    ) -> Result<(), TaskStateError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)?;
        state.tasks.register_recovered_drivers(task_ids)?;
        state.publication = state.publication.wrapping_add(1);
        Ok(())
    }

    /// Reconstructs already committed task-control staging without mutating ownership.
    #[cfg(feature = "concurrent")]
    pub fn recovered_staged_task_control(
        &self,
        task_id: ProtocolIdentity,
        pending: &crate::machine::MachineTaskControlSuspension,
    ) -> Result<(Option<JoinStartV1>, Option<TaskOwnershipChangedV1>), TaskStateError> {
        lock(&self.inner.state)
            .tasks
            .recovered_staged_task_control(task_id, pending)
    }

    /// Settles an accepted root after exceptional executor submission failure.
    pub fn fail_root_submission(&self, outcome: MachineOutcome) -> Result<(), TaskStateError> {
        let (task_waiters, shutdown_waiters) = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state)?;
            let task_id = state.tasks.root_task_id();
            state.tasks.fail_root_submission(outcome, true)?;
            state.publication = state.publication.wrapping_add(1);
            let task_waiters = state.task_waiters.remove(&task_id).unwrap_or_default();
            let shutdown_waiters = take_shutdown_waiters_if_quiescent(&mut state);
            (task_waiters, shutdown_waiters)
        };
        wake_all(task_waiters);
        wake_all(shutdown_waiters);
        Ok(())
    }

    /// Settles a submitting root whose registered driver could not become runnable.
    pub fn fail_root_registration(&self, outcome: MachineOutcome) -> Result<(), TaskStateError> {
        let (task_waiters, shutdown_waiters) = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state)?;
            let task_id = state.tasks.root_task_id();
            state.tasks.fail_root_submission(outcome, false)?;
            state.publication = state.publication.wrapping_add(1);
            let task_waiters = state.task_waiters.remove(&task_id).unwrap_or_default();
            let shutdown_waiters = take_shutdown_waiters_if_quiescent(&mut state);
            (task_waiters, shutdown_waiters)
        };
        wake_all(task_waiters);
        wake_all(shutdown_waiters);
        Ok(())
    }

    /// Attempts a snapshot without blocking, for lock-order instrumentation.
    #[must_use]
    pub fn try_snapshot(&self) -> Option<ExecutionCoordinatorSnapshot> {
        match self.inner.state.try_lock() {
            Ok(state) => Some(snapshot_from(&state)),
            Err(TryLockError::Poisoned(error)) => Some(snapshot_from(&error.into_inner())),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// Returns one execution-wide logical-session record without retaining the guard.
    #[must_use]
    pub fn session(&self, session_id: ProtocolIdentity) -> Option<LogicalSessionV1> {
        lock(&self.inner.state).sessions.get(session_id).cloned()
    }

    /// Creates one execution-wide non-root logical session at a linearization point.
    pub fn create_session(
        &self,
        parent_id: ProtocolIdentity,
        creator_task: ProtocolIdentity,
        site: StructuralPosition,
        occurrence: u64,
        mode: SessionCreationModeV1,
        establishment: SessionEstablishmentV1,
    ) -> Result<LogicalSessionV1, SessionError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)
            .map_err(|_| SessionError::DurablePublicationReserved)?;
        let session = state
            .sessions
            .create(
                parent_id,
                creator_task,
                site,
                occurrence,
                mode,
                establishment,
            )?
            .clone();
        state.publication = state.publication.wrapping_add(1);
        Ok(session)
    }

    /// Applies one synchronous session update while holding the coordinator linearization lock.
    ///
    /// The callback must not await, invoke an integration, or reenter this coordinator.
    pub fn with_session_mut<T>(
        &self,
        session_id: ProtocolIdentity,
        update: impl FnOnce(&mut LogicalSessionV1) -> T,
    ) -> Result<T, SessionError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)
            .map_err(|_| SessionError::DurablePublicationReserved)?;
        let result = update(
            state
                .sessions
                .get_mut(session_id)
                .ok_or(SessionError::UnknownParent)?,
        );
        state.publication = state.publication.wrapping_add(1);
        Ok(result)
    }

    /// Records one child and its forked logical session at one linearization point.
    pub fn create_child(
        &self,
        request: TaskCreationRequestV1,
        limits: ValueLimits,
    ) -> Result<TaskCreationV1, TaskStateError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)?;
        let CoordinatorState {
            tasks,
            sessions,
            publication,
            ..
        } = &mut *state;
        let created = tasks.create_child(sessions, request, limits)?;
        *publication = publication.wrapping_add(1);
        Ok(created)
    }

    /// Resolves child submission and publishes any resulting settlement notification.
    pub fn resolve_submission(
        &self,
        task_id: ProtocolIdentity,
        result: Result<(), HostError>,
    ) -> Result<TaskStatusKind, TaskStateError> {
        let (disposition, task_waiters, shutdown_waiters) = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state)?;
            let disposition = state.tasks.resolve_submission(task_id, result)?;
            state.publication = state.publication.wrapping_add(1);
            let task_waiters = if task_is_settled(&state.tasks, task_id) {
                state.task_waiters.remove(&task_id).unwrap_or_default()
            } else {
                Vec::new()
            };
            let shutdown_waiters = take_shutdown_waiters_if_quiescent(&mut state);
            (disposition, task_waiters, shutdown_waiters)
        };
        wake_all(task_waiters);
        wake_all(shutdown_waiters);
        Ok(disposition)
    }

    /// Settles cancellation for a child that never acquired executor ownership.
    pub fn resolve_unsubmitted_cancellation(
        &self,
        task_id: ProtocolIdentity,
    ) -> Result<(), TaskStateError> {
        let (task_waiters, shutdown_waiters) = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state)?;
            state.tasks.resolve_unsubmitted_cancellation(task_id)?;
            state.publication = state.publication.wrapping_add(1);
            let task_waiters = state.task_waiters.remove(&task_id).unwrap_or_default();
            let shutdown_waiters = take_shutdown_waiters_if_quiescent(&mut state);
            (task_waiters, shutdown_waiters)
        };
        wake_all(task_waiters);
        wake_all(shutdown_waiters);
        Ok(())
    }

    /// Stages one outcome without notifying semantic-settlement waiters.
    pub fn stage_task_outcome(
        &self,
        task_id: ProtocolIdentity,
        outcome: MachineOutcome,
    ) -> Result<(), TaskStateError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)?;
        state.tasks.stage_task_outcome(task_id, outcome)?;
        state.publication = state.publication.wrapping_add(1);
        Ok(())
    }

    /// Publishes one staged settlement and wakes observers after unlocking.
    pub fn settle_staged_task(&self, task_id: ProtocolIdentity) -> Result<(), TaskStateError> {
        let (task_waiters, shutdown_waiters) = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state)?;
            state.tasks.settle_staged_task(task_id)?;
            state.publication = state.publication.wrapping_add(1);
            let task_waiters = state.task_waiters.remove(&task_id).unwrap_or_default();
            let shutdown_waiters = take_shutdown_waiters_if_quiescent(&mut state);
            (task_waiters, shutdown_waiters)
        };
        wake_all(task_waiters);
        wake_all(shutdown_waiters);
        Ok(())
    }

    /// Stages and publishes one root or child settlement atomically.
    pub fn settle_task(
        &self,
        task_id: ProtocolIdentity,
        outcome: MachineOutcome,
    ) -> Result<(), TaskStateError> {
        let (task_waiters, shutdown_waiters) = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state)?;
            state.tasks.settle(task_id, outcome)?;
            state.publication = state.publication.wrapping_add(1);
            let task_waiters = state.task_waiters.remove(&task_id).unwrap_or_default();
            let shutdown_waiters = take_shutdown_waiters_if_quiescent(&mut state);
            (task_waiters, shutdown_waiters)
        };
        wake_all(task_waiters);
        wake_all(shutdown_waiters);
        Ok(())
    }

    /// Atomically publishes semantic settlement after a driver failure.
    ///
    /// A staged outcome takes precedence over `fallback`, and an effective
    /// cancellation takes precedence over both. Already-settled tasks return
    /// their fixed status without publishing or waking observers again. This
    /// operation does not change physical driver ownership.
    pub fn settle_after_driver_failure(
        &self,
        task_id: ProtocolIdentity,
        fallback: MachineOutcome,
    ) -> Result<ConcurrentTaskStatusV1, TaskStateError> {
        let (status, task_waiters, shutdown_waiters) = {
            let mut state = lock(&self.inner.state);
            let record = state
                .tasks
                .task_record(task_id)
                .ok_or(TaskStateError::UnknownTask)?;
            if status_is_settled(record.status()) {
                return Ok(record.status().clone());
            }
            require_publication_available(&state)?;
            let status = state.tasks.settle_after_driver_failure(task_id, fallback)?;
            state.publication = state.publication.wrapping_add(1);
            let task_waiters = state.task_waiters.remove(&task_id).unwrap_or_default();
            let shutdown_waiters = take_shutdown_waiters_if_quiescent(&mut state);
            (status, task_waiters, shutdown_waiters)
        };
        wake_all(task_waiters);
        wake_all(shutdown_waiters);
        Ok(status)
    }

    /// Atomically publishes executor-abort failure without changing physical ownership.
    pub fn settle_after_abort_failure(
        &self,
        task_id: ProtocolIdentity,
        outcome: MachineOutcome,
    ) -> Result<ConcurrentTaskStatusV1, TaskStateError> {
        let (status, task_waiters, shutdown_waiters) = {
            let mut state = lock(&self.inner.state);
            let record = state
                .tasks
                .task_record(task_id)
                .ok_or(TaskStateError::UnknownTask)?;
            if status_is_settled(record.status()) {
                return Ok(record.status().clone());
            }
            require_publication_available(&state)?;
            let status = state.tasks.settle_after_abort_failure(task_id, outcome)?;
            state.publication = state.publication.wrapping_add(1);
            let task_waiters = state.task_waiters.remove(&task_id).unwrap_or_default();
            let shutdown_waiters = take_shutdown_waiters_if_quiescent(&mut state);
            (status, task_waiters, shutdown_waiters)
        };
        wake_all(task_waiters);
        wake_all(shutdown_waiters);
        Ok(status)
    }

    /// Consumes one source join selection at the coordinator linearization point.
    pub fn begin_join(
        &self,
        owner_task_id: ProtocolIdentity,
        control: &TaskControlSite,
        handles: &[DynamicTaskHandleIdentity],
    ) -> Result<JoinStartV1, TaskStateError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)?;
        let started = state.tasks.begin_join(owner_task_id, control, handles)?;
        state.publication = state.publication.wrapping_add(1);
        Ok(started)
    }

    /// Consumes one source join or joinall from canonical executable metadata.
    pub fn begin_source_join(
        &self,
        owner_task_id: ProtocolIdentity,
        workflow: CanonicalPath,
        site: StructuralPosition,
        kind: gantry_ir::generated::TaskControlSiteKind,
        handle_names: &[Arc<str>],
        handles: &[DynamicTaskHandleIdentity],
    ) -> Result<JoinStartV1, TaskStateError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)?;
        let started = state.tasks.begin_source_join(
            owner_task_id,
            workflow,
            site,
            kind,
            handle_names,
            handles,
        )?;
        state.publication = state.publication.wrapping_add(1);
        Ok(started)
    }

    /// Transfers one attached handle to execution-owned detached work.
    pub fn detach(
        &self,
        owner_task_id: ProtocolIdentity,
        control: &TaskControlSite,
        handle: DynamicTaskHandleIdentity,
    ) -> Result<TaskOwnershipChangedV1, TaskStateError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)?;
        let detached = state.tasks.detach(owner_task_id, control, handle)?;
        state.publication = state.publication.wrapping_add(1);
        Ok(detached)
    }

    /// Transfers one source handle from canonical executable metadata to detached work.
    pub fn detach_source_handle(
        &self,
        owner_task_id: ProtocolIdentity,
        workflow: CanonicalPath,
        site: StructuralPosition,
        handle_name: Arc<str>,
        handle: DynamicTaskHandleIdentity,
    ) -> Result<TaskOwnershipChangedV1, TaskStateError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)?;
        let detached =
            state
                .tasks
                .detach_source_handle(owner_task_id, workflow, site, handle_name, handle)?;
        state.publication = state.publication.wrapping_add(1);
        Ok(detached)
    }

    /// Records the first execution cancellation at one linearization point.
    pub fn cancel_execution(
        &self,
        reason: impl Into<Arc<str>>,
    ) -> Result<Vec<ProtocolIdentity>, TaskStateError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)?;
        let affected = state.tasks.cancel_execution(reason)?;
        if !affected.is_empty() {
            state.publication = state.publication.wrapping_add(1);
        }
        Ok(affected)
    }

    /// Records task-tree cancellation through attached descendants only.
    pub fn cancel_task_tree(
        &self,
        task_id: ProtocolIdentity,
        reason: impl Into<Arc<str>>,
    ) -> Result<Vec<ProtocolIdentity>, TaskStateError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)?;
        let affected = state.tasks.cancel_task_tree(task_id, reason)?;
        if !affected.is_empty() {
            state.publication = state.publication.wrapping_add(1);
        }
        Ok(affected)
    }

    /// Derives foreground completion from the settled root and wakes observers.
    pub fn complete_foreground(&self) -> Result<MachineOutcome, TaskStateError> {
        let outcome = lock(&self.inner.state)
            .tasks
            .root_settled_outcome()
            .cloned()
            .ok_or(TaskStateError::RootTaskPending)?;
        self.complete_foreground_with_outcome(outcome.clone())?;
        Ok(outcome)
    }

    /// Fixes foreground completion with an execution-level outcome selected at
    /// an explicit required-delivery barrier after root settlement.
    pub fn complete_foreground_with_outcome(
        &self,
        outcome: MachineOutcome,
    ) -> Result<(), TaskStateError> {
        let waiters = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state)?;
            if state.tasks.root_settled_outcome().is_none() {
                return Err(TaskStateError::RootTaskPending);
            }
            state.tasks.complete_foreground(outcome)?;
            state.publication = state.publication.wrapping_add(1);
            std::mem::take(&mut state.foreground_waiters)
        };
        wake_all(waiters);
        Ok(())
    }

    /// Fixes terminal completion and wakes observers after publication.
    pub fn complete_terminal(&self) -> Result<ConcurrentTerminalOutcomeV1, TaskStateError> {
        let (outcome, waiters) = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state)?;
            let outcome = state.tasks.complete_terminal()?.clone();
            state.publication = state.publication.wrapping_add(1);
            (outcome, std::mem::take(&mut state.terminal_waiters))
        };
        wake_all(waiters);
        Ok(outcome)
    }

    /// Returns the fixed terminal semantic outcome, when terminal computation completed.
    #[must_use]
    pub fn terminal_outcome(&self) -> Option<ConcurrentTerminalOutcomeV1> {
        lock(&self.inner.state).tasks.terminal_outcome().cloned()
    }

    /// Returns a stable snapshot of work participating in execution shutdown.
    #[must_use]
    pub fn shutdown_cohort(&self) -> ConcurrentShutdownCohortV1 {
        lock(&self.inner.state).tasks.shutdown_cohort()
    }

    /// Returns the semantic cohort covered by execution cancellation.
    #[must_use]
    pub fn execution_cancellation_cohort(&self) -> Vec<ProtocolIdentity> {
        lock(&self.inner.state)
            .tasks
            .execution_cancellation_cohort()
    }

    /// Records physical driver settlement and publishes shutdown progress.
    pub fn mark_driver_physically_settled(
        &self,
        task_id: ProtocolIdentity,
    ) -> Result<bool, TaskStateError> {
        let (changed, waiters) = {
            let mut state = lock(&self.inner.state);
            let changed = state.tasks.mark_driver_physically_settled(task_id)?;
            if !changed {
                return Ok(false);
            }
            state.publication = state.publication.wrapping_add(1);
            let waiters = take_shutdown_waiters_if_quiescent(&mut state);
            (changed, waiters)
        };
        wake_all(waiters);
        Ok(changed)
    }

    /// Acquires one task-local turn spanning sequence assignment and completion.
    pub(crate) fn acquire_task_event_completion(
        &self,
        task_id: ProtocolIdentity,
    ) -> TaskEventCompletionWait {
        TaskEventCompletionWait {
            inner: Arc::clone(&self.inner),
            task_id,
            waiter_id: next_waiter_id(),
            completed: false,
        }
    }

    /// Installs the execution's immutable initial sink plan and returns the
    /// currently active plan after any required-sink exclusions.
    pub fn event_plan(&self, initial: &SinkPlan) -> SinkPlan {
        let mut state = lock(&self.inner.state);
        state
            .active_event_plan
            .get_or_insert_with(|| initial.clone())
            .clone()
    }

    /// Excludes one exhausted sink from later consequence-event plans.
    pub fn exclude_event_sink(&self, sink_id: &SinkId) {
        let mut state = lock(&self.inner.state);
        if let Some(plan) = state.active_event_plan.take() {
            state.active_event_plan = Some(plan.without_sink(sink_id));
        }
    }

    /// Registers one asynchronously owned required-delivery acknowledgement.
    pub fn begin_required_event_delivery(&self) -> Result<u64, TaskEventSequenceError> {
        let mut state = lock(&self.inner.state);
        let delivery = state.next_required_delivery;
        state.next_required_delivery = delivery
            .checked_add(1)
            .ok_or(TaskEventSequenceError::Exhausted)?;
        state.pending_required_deliveries.insert(delivery);
        Ok(delivery)
    }

    /// Atomically registers the required and best-effort sides of one frozen plan.
    pub fn begin_event_delivery_plan(
        &self,
        has_required: bool,
        has_best_effort: bool,
    ) -> Result<(Option<u64>, Option<u64>), TaskEventSequenceError> {
        let mut state = lock(&self.inner.state);
        let required = has_required.then_some(state.next_required_delivery);
        let best_effort = has_best_effort.then_some(state.next_best_effort_delivery);
        let next_required = required
            .map(|delivery| {
                delivery
                    .checked_add(1)
                    .ok_or(TaskEventSequenceError::Exhausted)
            })
            .transpose()?;
        let next_best_effort = best_effort
            .map(|delivery| {
                delivery
                    .checked_add(1)
                    .ok_or(TaskEventSequenceError::Exhausted)
            })
            .transpose()?;
        if let (Some(delivery), Some(next)) = (required, next_required) {
            state.next_required_delivery = next;
            state.pending_required_deliveries.insert(delivery);
        }
        if let (Some(delivery), Some(next)) = (best_effort, next_best_effort) {
            state.next_best_effort_delivery = next;
            state.pending_best_effort_deliveries.insert(delivery);
        }
        Ok((required, best_effort))
    }

    /// Settles one required-delivery acknowledgement and wakes named barriers.
    pub fn settle_required_event_delivery(&self, delivery: u64) {
        let waiters = {
            let mut state = lock(&self.inner.state);
            if !state.pending_required_deliveries.remove(&delivery) {
                return;
            }
            std::mem::take(&mut state.required_delivery_waiters)
        };
        wake_all(waiters);
    }

    /// Records that an asynchronously acknowledged required obligation failed.
    pub fn note_required_event_delivery_failure(&self) {
        lock(&self.inner.state).required_event_delivery_failed = true;
    }

    /// Records that delivery infrastructure failed after semantic acceptance.
    pub fn note_event_delivery_executor_failure(&self) {
        lock(&self.inner.state).event_delivery_executor_failed = true;
    }

    /// Returns whether a required obligation has failed for this execution.
    #[must_use]
    pub fn required_event_delivery_failed(&self) -> bool {
        lock(&self.inner.state).required_event_delivery_failed
    }

    /// Returns whether accepted delivery work failed in executor infrastructure.
    #[must_use]
    pub fn event_delivery_executor_failed(&self) -> bool {
        lock(&self.inner.state).event_delivery_executor_failed
    }

    /// Registers an ordering barrier through required predecessors of one delivery.
    #[must_use]
    pub fn wait_for_required_event_delivery_predecessors(
        &self,
        delivery: u64,
    ) -> RequiredEventDeliveryWait {
        RequiredEventDeliveryWait {
            inner: Arc::clone(&self.inner),
            through: delivery.checked_sub(1),
            waiter_id: next_waiter_id(),
            completed: false,
        }
    }

    /// Registers one asynchronously owned best-effort delivery obligation.
    pub fn begin_best_effort_event_delivery(&self) -> Result<u64, TaskEventSequenceError> {
        let mut state = lock(&self.inner.state);
        let delivery = state.next_best_effort_delivery;
        state.next_best_effort_delivery = delivery
            .checked_add(1)
            .ok_or(TaskEventSequenceError::Exhausted)?;
        state.pending_best_effort_deliveries.insert(delivery);
        Ok(delivery)
    }

    /// Settles one best-effort obligation and wakes ordering barriers.
    pub fn settle_best_effort_event_delivery(&self, delivery: u64) {
        let waiters = {
            let mut state = lock(&self.inner.state);
            if !state.pending_best_effort_deliveries.remove(&delivery) {
                return;
            }
            std::mem::take(&mut state.best_effort_delivery_waiters)
        };
        wake_all(waiters);
    }

    /// Registers an ordering barrier through best-effort predecessors.
    #[must_use]
    pub fn wait_for_best_effort_event_delivery_predecessors(
        &self,
        delivery: u64,
    ) -> BestEffortEventDeliveryWait {
        BestEffortEventDeliveryWait {
            inner: Arc::clone(&self.inner),
            through: delivery.checked_sub(1),
            waiter_id: next_waiter_id(),
            completed: false,
        }
    }

    /// Registers an explicit barrier through all required acknowledgements
    /// that were admitted before the barrier is polled.
    #[must_use]
    pub fn wait_for_required_event_delivery(&self) -> RequiredEventDeliveryWait {
        let through = lock(&self.inner.state)
            .next_required_delivery
            .checked_sub(1);
        RequiredEventDeliveryWait {
            inner: Arc::clone(&self.inner),
            through,
            waiter_id: next_waiter_id(),
            completed: false,
        }
    }

    /// Registers a race-safe, non-polling task-settlement observer.
    pub fn wait_for_task_settlement(
        &self,
        task_id: ProtocolIdentity,
    ) -> Result<TaskSettlementWait, TaskStateError> {
        if lock(&self.inner.state).tasks.task_record(task_id).is_none() {
            return Err(TaskStateError::UnknownTask);
        }
        Ok(TaskSettlementWait {
            inner: Arc::clone(&self.inner),
            task_id,
            waiter_id: next_waiter_id(),
            completed: false,
        })
    }

    /// Registers a race-safe all-settled join observer.
    pub fn wait_for_join(
        &self,
        ownership: TaskOwnershipChangedV1,
        limits: ValueLimits,
    ) -> Result<JoinSettlementWait, TaskStateError> {
        lock(&self.inner.state)
            .tasks
            .resolve_join(&ownership, limits)?;
        Ok(JoinSettlementWait {
            inner: Arc::clone(&self.inner),
            ownership,
            limits,
            waiter_id: next_waiter_id(),
            registered_tasks: Vec::new(),
            completed: false,
        })
    }

    /// Registers a race-safe foreground-completion observer.
    #[must_use]
    pub fn wait_for_foreground(&self) -> ForegroundCompletionWait {
        ForegroundCompletionWait {
            inner: Arc::clone(&self.inner),
            waiter_id: next_waiter_id(),
            completed: false,
        }
    }

    /// Registers a race-safe terminal-completion observer.
    #[must_use]
    pub fn wait_for_terminal(&self) -> TerminalCompletionWait {
        TerminalCompletionWait {
            inner: Arc::clone(&self.inner),
            waiter_id: next_waiter_id(),
            completed: false,
        }
    }

    /// Registers a race-safe observer for task-driver and attached physical-value quiescence.
    #[must_use]
    pub fn wait_for_shutdown_quiescence(&self) -> ShutdownQuiescenceWait {
        ShutdownQuiescenceWait {
            inner: Arc::clone(&self.inner),
            waiter_id: next_waiter_id(),
            completed: false,
        }
    }
}

impl Future for TaskEventCompletionWait {
    type Output = Result<TaskEventCompletionPermit, TaskEventSequenceError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let result = {
            let mut state = lock(&self.inner.state);
            if state.tasks.task_record(self.task_id).is_none() {
                remove_task_waiter(
                    &mut state.task_event_completion_waiters,
                    self.task_id,
                    self.waiter_id,
                );
                Some(Err(TaskEventSequenceError::UnknownTask))
            } else if state.task_event_completion_active.contains(&self.task_id) {
                register_task_waiter(
                    &mut state.task_event_completion_waiters,
                    self.task_id,
                    self.waiter_id,
                    context.waker(),
                );
                None
            } else {
                let sequence = *state.next_event_sequence.entry(self.task_id).or_insert(0);
                if sequence.checked_add(1).is_none() {
                    remove_task_waiter(
                        &mut state.task_event_completion_waiters,
                        self.task_id,
                        self.waiter_id,
                    );
                    Some(Err(TaskEventSequenceError::Exhausted))
                } else {
                    remove_task_waiter(
                        &mut state.task_event_completion_waiters,
                        self.task_id,
                        self.waiter_id,
                    );
                    state.task_event_completion_active.insert(self.task_id);
                    Some(Ok(TaskEventCompletionPermit {
                        inner: Arc::clone(&self.inner),
                        task_id: self.task_id,
                        sequence,
                        committed: false,
                    }))
                }
            }
        };
        match result {
            Some(result) => {
                self.completed = true;
                Poll::Ready(result)
            }
            None => Poll::Pending,
        }
    }
}

impl Drop for TaskEventCompletionWait {
    fn drop(&mut self) {
        if !self.completed {
            remove_task_waiter(
                &mut lock(&self.inner.state).task_event_completion_waiters,
                self.task_id,
                self.waiter_id,
            );
        }
    }
}

impl TaskEventCompletionPermit {
    /// Returns the sequence reserved for this task-local completion turn.
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Publishes successful event completion and releases the task-local turn.
    pub(crate) fn commit(mut self) -> Result<(), TaskEventSequenceError> {
        let waiters = {
            let mut state = lock(&self.inner.state);
            let next = self
                .sequence
                .checked_add(1)
                .ok_or(TaskEventSequenceError::Exhausted)?;
            state.next_event_sequence.insert(self.task_id, next);
            state.task_event_completion_active.remove(&self.task_id);
            state
                .task_event_completion_waiters
                .remove(&self.task_id)
                .unwrap_or_default()
        };
        self.committed = true;
        wake_all(waiters);
        Ok(())
    }
}

impl Drop for TaskEventCompletionPermit {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let waiters = {
            let mut state = lock(&self.inner.state);
            state.task_event_completion_active.remove(&self.task_id);
            state
                .task_event_completion_waiters
                .remove(&self.task_id)
                .unwrap_or_default()
        };
        wake_all(waiters);
    }
}

/// Independent required-event-delivery barrier observer.
pub struct RequiredEventDeliveryWait {
    inner: Arc<CoordinatorInner>,
    through: Option<u64>,
    waiter_id: u64,
    completed: bool,
}

impl Future for RequiredEventDeliveryWait {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let ready = {
            let mut state = lock(&self.inner.state);
            if self.through.is_none_or(|through| {
                state
                    .pending_required_deliveries
                    .range(..=through)
                    .next()
                    .is_none()
            }) {
                remove_waiter(&mut state.required_delivery_waiters, self.waiter_id);
                true
            } else {
                register_waiter(
                    &mut state.required_delivery_waiters,
                    self.waiter_id,
                    context.waker(),
                );
                false
            }
        };
        if ready {
            self.completed = true;
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for RequiredEventDeliveryWait {
    fn drop(&mut self) {
        if !self.completed {
            remove_waiter(
                &mut lock(&self.inner.state).required_delivery_waiters,
                self.waiter_id,
            );
        }
    }
}

/// Independent best-effort predecessor barrier observer.
pub struct BestEffortEventDeliveryWait {
    inner: Arc<CoordinatorInner>,
    through: Option<u64>,
    waiter_id: u64,
    completed: bool,
}

impl Future for BestEffortEventDeliveryWait {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let ready = {
            let mut state = lock(&self.inner.state);
            if self.through.is_none_or(|through| {
                state
                    .pending_best_effort_deliveries
                    .range(..=through)
                    .next()
                    .is_none()
            }) {
                remove_waiter(&mut state.best_effort_delivery_waiters, self.waiter_id);
                true
            } else {
                register_waiter(
                    &mut state.best_effort_delivery_waiters,
                    self.waiter_id,
                    context.waker(),
                );
                false
            }
        };
        if ready {
            self.completed = true;
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for BestEffortEventDeliveryWait {
    fn drop(&mut self) {
        if !self.completed {
            remove_waiter(
                &mut lock(&self.inner.state).best_effort_delivery_waiters,
                self.waiter_id,
            );
        }
    }
}

/// Independent task-settlement observer; dropping it removes only this waiter.
pub struct TaskSettlementWait {
    inner: Arc<CoordinatorInner>,
    task_id: ProtocolIdentity,
    waiter_id: u64,
    completed: bool,
}

impl Future for TaskSettlementWait {
    type Output = ConcurrentTaskStatusV1;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let status = {
            let mut state = lock(&self.inner.state);
            let status = state
                .tasks
                .task_record(self.task_id)
                .map(|task| task.status().clone());
            match status {
                Some(status) if status_is_settled(&status) => {
                    remove_waiter_for_task(&mut state, self.task_id, self.waiter_id);
                    Some(status)
                }
                Some(_) => {
                    register_waiter(
                        state.task_waiters.entry(self.task_id).or_default(),
                        self.waiter_id,
                        context.waker(),
                    );
                    None
                }
                None => panic!("coordinator task disappeared while a waiter existed"),
            }
        };
        if let Some(status) = status {
            self.completed = true;
            Poll::Ready(status)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for TaskSettlementWait {
    fn drop(&mut self) {
        if !self.completed {
            remove_waiter_for_task(&mut lock(&self.inner.state), self.task_id, self.waiter_id);
        }
    }
}

/// Independent all-settled join observer.
pub struct JoinSettlementWait {
    inner: Arc<CoordinatorInner>,
    ownership: TaskOwnershipChangedV1,
    limits: ValueLimits,
    waiter_id: u64,
    registered_tasks: Vec<ProtocolIdentity>,
    completed: bool,
}

impl Future for JoinSettlementWait {
    type Output = Result<JoinResolutionV1, TaskStateError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let (resolution, registered) = {
            let mut state = lock(&self.inner.state);
            for task_id in &self.registered_tasks {
                remove_waiter_for_task(&mut state, *task_id, self.waiter_id);
            }
            match state.tasks.resolve_join(&self.ownership, self.limits) {
                Ok(JoinResolutionV1::Pending(task_ids)) => {
                    for task_id in &task_ids {
                        register_waiter(
                            state.task_waiters.entry(*task_id).or_default(),
                            self.waiter_id,
                            context.waker(),
                        );
                    }
                    (None, task_ids)
                }
                result => (Some(result), Vec::new()),
            }
        };
        self.registered_tasks = registered;
        if let Some(result) = resolution {
            self.completed = true;
            Poll::Ready(result)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for JoinSettlementWait {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let mut state = lock(&self.inner.state);
        for task_id in &self.registered_tasks {
            remove_waiter_for_task(&mut state, *task_id, self.waiter_id);
        }
    }
}

/// Independent foreground-completion observer.
pub struct ForegroundCompletionWait {
    inner: Arc<CoordinatorInner>,
    waiter_id: u64,
    completed: bool,
}

impl Future for ForegroundCompletionWait {
    type Output = MachineOutcome;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let outcome = {
            let mut state = lock(&self.inner.state);
            match state.tasks.foreground_outcome().cloned() {
                Some(outcome) => {
                    remove_waiter(&mut state.foreground_waiters, self.waiter_id);
                    Some(outcome)
                }
                None => {
                    register_waiter(
                        &mut state.foreground_waiters,
                        self.waiter_id,
                        context.waker(),
                    );
                    None
                }
            }
        };
        if let Some(outcome) = outcome {
            self.completed = true;
            Poll::Ready(outcome)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for ForegroundCompletionWait {
    fn drop(&mut self) {
        if !self.completed {
            remove_waiter(
                &mut lock(&self.inner.state).foreground_waiters,
                self.waiter_id,
            );
        }
    }
}

/// Independent terminal-completion observer.
pub struct TerminalCompletionWait {
    inner: Arc<CoordinatorInner>,
    waiter_id: u64,
    completed: bool,
}

impl Future for TerminalCompletionWait {
    type Output = ConcurrentTerminalOutcomeV1;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let outcome = {
            let mut state = lock(&self.inner.state);
            match state.tasks.terminal_outcome().cloned() {
                Some(outcome) => {
                    remove_waiter(&mut state.terminal_waiters, self.waiter_id);
                    Some(outcome)
                }
                None => {
                    register_waiter(&mut state.terminal_waiters, self.waiter_id, context.waker());
                    None
                }
            }
        };
        if let Some(outcome) = outcome {
            self.completed = true;
            Poll::Ready(outcome)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for TerminalCompletionWait {
    fn drop(&mut self) {
        if !self.completed {
            remove_waiter(
                &mut lock(&self.inner.state).terminal_waiters,
                self.waiter_id,
            );
        }
    }
}

/// Independent observer for physical completion of every task driver and attached host value.
pub struct ShutdownQuiescenceWait {
    inner: Arc<CoordinatorInner>,
    waiter_id: u64,
    completed: bool,
}

impl Future for ShutdownQuiescenceWait {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let ready = {
            let mut state = lock(&self.inner.state);
            if shutdown_is_quiescent(&state) {
                remove_waiter(&mut state.shutdown_waiters, self.waiter_id);
                true
            } else {
                register_waiter(&mut state.shutdown_waiters, self.waiter_id, context.waker());
                false
            }
        };
        if ready {
            self.completed = true;
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for ShutdownQuiescenceWait {
    fn drop(&mut self) {
        if !self.completed {
            remove_waiter(
                &mut lock(&self.inner.state).shutdown_waiters,
                self.waiter_id,
            );
        }
    }
}

fn next_waiter_id() -> u64 {
    NEXT_COORDINATOR_WAITER_ID.fetch_add(1, Ordering::Relaxed)
}

/// Rejects semantic writes while a durable successor owns publication.
fn require_publication_available(state: &CoordinatorState) -> Result<(), TaskStateError> {
    if state.durable_publication_reserved {
        Err(TaskStateError::DurablePublicationReserved)
    } else {
        Ok(())
    }
}

fn snapshot_from(state: &CoordinatorState) -> ExecutionCoordinatorSnapshot {
    ExecutionCoordinatorSnapshot {
        state: state.tasks.clone(),
        sessions: state.sessions.sessions().cloned().collect(),
        execution_budget: state
            .execution_budget
            .as_ref()
            .map(ExecutionBudget::snapshot),
        resources: state
            .resources
            .as_ref()
            .map(crate::ResourceRegistry::declared_records),
        publication: state.publication,
    }
}

fn task_is_settled(tasks: &ConcurrentTaskStateV1, task_id: ProtocolIdentity) -> bool {
    tasks
        .task_record(task_id)
        .is_some_and(|task| status_is_settled(task.status()))
}

fn status_is_settled(status: &ConcurrentTaskStatusV1) -> bool {
    matches!(
        status,
        ConcurrentTaskStatusV1::Succeeded(_)
            | ConcurrentTaskStatusV1::Failed(_)
            | ConcurrentTaskStatusV1::Cancelled(_)
    )
}

fn register_waiter(waiters: &mut Vec<RegisteredWaiter>, id: u64, waker: &Waker) {
    if let Some(waiter) = waiters.iter_mut().find(|waiter| waiter.id == id) {
        waiter.waker = waker.clone();
    } else {
        waiters.push(RegisteredWaiter {
            id,
            waker: waker.clone(),
        });
    }
}

fn remove_waiter_for_task(state: &mut CoordinatorState, task_id: ProtocolIdentity, waiter_id: u64) {
    let remove_entry = state.task_waiters.get_mut(&task_id).is_some_and(|waiters| {
        remove_waiter(waiters, waiter_id);
        waiters.is_empty()
    });
    if remove_entry {
        state.task_waiters.remove(&task_id);
    }
}

fn remove_waiter(waiters: &mut Vec<RegisteredWaiter>, waiter_id: u64) {
    waiters.retain(|waiter| waiter.id != waiter_id);
}

fn register_task_waiter(
    waiters: &mut BTreeMap<ProtocolIdentity, Vec<RegisteredWaiter>>,
    task_id: ProtocolIdentity,
    waiter_id: u64,
    waker: &Waker,
) {
    register_waiter(waiters.entry(task_id).or_default(), waiter_id, waker);
}

fn remove_task_waiter(
    waiters: &mut BTreeMap<ProtocolIdentity, Vec<RegisteredWaiter>>,
    task_id: ProtocolIdentity,
    waiter_id: u64,
) {
    let remove_entry = if let Some(task_waiters) = waiters.get_mut(&task_id) {
        remove_waiter(task_waiters, waiter_id);
        task_waiters.is_empty()
    } else {
        false
    };
    if remove_entry {
        waiters.remove(&task_id);
    }
}

/// Requires both settled task drivers and completed physical resource destruction.
fn shutdown_is_quiescent(state: &CoordinatorState) -> bool {
    state.tasks.drivers_are_quiescent()
        && state
            .resources
            .as_ref()
            .is_none_or(crate::ResourceRegistry::host_values_are_quiescent)
}

fn take_shutdown_waiters_if_quiescent(state: &mut CoordinatorState) -> Vec<RegisteredWaiter> {
    if shutdown_is_quiescent(state) {
        std::mem::take(&mut state.shutdown_waiters)
    } else {
        Vec::new()
    }
}

fn wake_all(waiters: Vec<RegisteredWaiter>) {
    for waiter in waiters {
        waiter.waker.wake();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    use gantry_core::portable::IdentityKind;
    use gantry_core::value::LogicalValue;

    use super::*;
    use crate::CanonicalTranscriptV1;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn driver_failure_settlement_wakes_task_and_shutdown_waiters_once() {
        let execution = identity(IdentityKind::Execution, 1);
        let root_task = ProtocolIdentity::derive(IdentityKind::Task, b"{\"root\":true}")
            .unwrap_or_else(|error| panic!("root task identity failed: {error}"));
        let root_session = identity(IdentityKind::Session, 3);
        let tasks = ConcurrentTaskStateV1::new(execution, root_task, 1)
            .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
        let sessions = LogicalSessionRegistryV1::new(
            execution,
            root_session,
            SessionCreationModeV1::GantryRoot,
            CanonicalTranscriptV1::empty(),
        )
        .unwrap_or_else(|error| panic!("sessions failed: {error:?}"));
        let coordinator = ExecutionCoordinator::new(tasks, sessions)
            .unwrap_or_else(|error| panic!("coordinator failed: {error:?}"));
        coordinator
            .stage_task_outcome(root_task, MachineOutcome::Succeeded(LogicalValue::unit()))
            .unwrap_or_else(|error| panic!("outcome staging failed: {error:?}"));
        assert!(
            coordinator
                .mark_driver_physically_settled(root_task)
                .unwrap_or_else(|error| panic!("physical settlement failed: {error:?}"))
        );
        let mut task_wait = Box::pin(
            coordinator
                .wait_for_task_settlement(root_task)
                .unwrap_or_else(|error| panic!("task wait failed: {error:?}")),
        );
        let mut shutdown_wait = Box::pin(coordinator.wait_for_shutdown_quiescence());
        let task_wakes = Arc::new(WakeCount::default());
        let shutdown_wakes = Arc::new(WakeCount::default());
        assert!(
            task_wait
                .as_mut()
                .poll(&mut Context::from_waker(&Waker::from(task_wakes.clone())))
                .is_pending()
        );
        assert!(
            shutdown_wait
                .as_mut()
                .poll(&mut Context::from_waker(&Waker::from(
                    shutdown_wakes.clone()
                )))
                .is_pending()
        );

        let status = coordinator
            .settle_after_driver_failure(
                root_task,
                MachineOutcome::Cancelled(Arc::from("unused-fallback")),
            )
            .unwrap_or_else(|error| panic!("driver failure settlement failed: {error:?}"));
        assert!(matches!(status, ConcurrentTaskStatusV1::Succeeded(_)));
        assert_eq!(task_wakes.0.load(Ordering::Acquire), 1);
        assert_eq!(shutdown_wakes.0.load(Ordering::Acquire), 1);
        let publication = coordinator.snapshot().publication();

        assert_eq!(
            coordinator
                .settle_after_driver_failure(
                    root_task,
                    MachineOutcome::Cancelled(Arc::from("unused-fallback")),
                )
                .unwrap_or_else(|error| panic!("repeat settlement failed: {error:?}")),
            status
        );
        assert_eq!(coordinator.snapshot().publication(), publication);
        assert_eq!(task_wakes.0.load(Ordering::Acquire), 1);
        assert_eq!(shutdown_wakes.0.load(Ordering::Acquire), 1);
    }

    /// Acquisition closure remains monotonic even while semantic publication is reserved.
    #[test]
    fn reserved_publication_does_not_reopen_resource_admission() {
        let execution = identity(IdentityKind::Execution, 11);
        let root = crate::root_task_identity(execution);
        let tasks = ConcurrentTaskStateV1::new(execution, root, 1)
            .unwrap_or_else(|error| panic!("tasks: {error:?}"));
        let sessions = LogicalSessionRegistryV1::new(
            execution,
            identity(IdentityKind::Session, 12),
            SessionCreationModeV1::GantryRoot,
            CanonicalTranscriptV1::empty(),
        )
        .unwrap_or_else(|error| panic!("sessions: {error:?}"));
        let coordinator = ExecutionCoordinator::new_with_resource_limits(tasks, sessions, 2, 2)
            .unwrap_or_else(|error| panic!("coordinator: {error:?}"));
        lock(&coordinator.inner.state).durable_publication_reserved = true;
        let before = coordinator.snapshot();
        assert!(coordinator.close_resource_admission());
        assert!(coordinator.resource_admission_is_closed());
        assert!(!coordinator.clone().close_resource_admission());
        assert_eq!(coordinator.snapshot(), before);
        lock(&coordinator.inner.state).durable_publication_reserved = false;
        assert!(coordinator.resource_admission_is_closed());
        assert_eq!(coordinator.snapshot(), before);
    }

    /// Durable publication reservations fence accounting writes before their mutation executes.
    #[test]
    fn reserved_publication_refuses_resource_mutation_without_changing_snapshot() {
        let execution = identity(IdentityKind::Execution, 1);
        let root = ProtocolIdentity::derive(IdentityKind::Task, b"resource-reservation-root")
            .unwrap_or_else(|error| panic!("task identity: {error}"));
        let tasks = ConcurrentTaskStateV1::new(execution, root, 1)
            .unwrap_or_else(|error| panic!("task state: {error:?}"));
        let sessions = LogicalSessionRegistryV1::new(
            execution,
            identity(IdentityKind::Session, 2),
            SessionCreationModeV1::GantryRoot,
            CanonicalTranscriptV1::empty(),
        )
        .unwrap_or_else(|error| panic!("sessions: {error:?}"));
        let coordinator = ExecutionCoordinator::new_with_resource_limit(tasks, sessions, 1)
            .unwrap_or_else(|error| panic!("coordinator: {error:?}"));
        lock(&coordinator.inner.state).durable_publication_reserved = true;
        let before = coordinator.snapshot();
        let result: Result<(), CoordinatorResourceRefusal> = coordinator.mutate_resources(|_| {
            panic!("a reserved publication must not execute the registry mutation")
        });
        assert_eq!(
            result,
            Err(CoordinatorResourceRefusal::Task(
                TaskStateError::DurablePublicationReserved
            ))
        );
        assert_eq!(coordinator.snapshot(), before);
        lock(&coordinator.inner.state).durable_publication_reserved = false;
        assert_eq!(coordinator.mutate_resources(|_| Ok(())), Ok(()));
        assert_eq!(
            coordinator.snapshot().publication(),
            before.publication() + 1
        );
        let path = CanonicalPath::new("crate::reserved_resource")
            .unwrap_or_else(|error| panic!("resource path: {error}"));
        let subject = crate::ResourceSubjectBinding::derive(
            &path,
            path.clone(),
            StructuralPosition::new(vec![0])
                .unwrap_or_else(|error| panic!("resource site: {error}")),
            0,
            Some(gantry_ir::OperationKind::LiveResource),
            Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open())),
            (execution, root),
        );
        let owner = gantry_ir::OwnerGeneration::new(4);
        let record = gantry_ir::ResourceLedger::new(
            owner,
            gantry_ir::ResourceState::Usable,
            &[gantry_ir::LivenessRoot::Resource],
            &[],
        )
        .unwrap_or_else(|error| panic!("resource ledger: {error:?}"))
        .durable_record();
        lock(&coordinator.inner.state)
            .resources
            .as_mut()
            .unwrap_or_else(|| panic!("registry exists"))
            .admit(
                subject.clone(),
                gantry_ir::ResourceCarrier::ReconstructionRecord,
                record,
            )
            .unwrap_or_else(|error| panic!("resource admission: {error:?}"));
        let drops = Arc::new(AtomicUsize::new(0));
        let value = ReservationDropProbe(Arc::clone(&drops));
        lock(&coordinator.inner.state).durable_publication_reserved = true;
        let before_attachment = coordinator.snapshot();
        assert_eq!(
            coordinator.advance_resource_owner(&subject, owner, gantry_ir::OwnerGeneration::new(5)),
            Err(CoordinatorResourceRefusal::Task(
                TaskStateError::DurablePublicationReserved
            ))
        );
        assert_eq!(
            coordinator.settle_resource_containment(
                &subject,
                owner,
                gantry_ir::Completion::observed(
                    gantry_ir::ExternalOutcome::Accepted,
                    gantry_ir::EffectState::NotStarted,
                ),
            ),
            Err(CoordinatorResourceRefusal::Task(
                TaskStateError::DurablePublicationReserved
            ))
        );
        assert_eq!(coordinator.snapshot(), before_attachment);
        let (error, value) = *coordinator
            .attach_resource_host_value(&subject, owner, value)
            .err()
            .unwrap_or_else(|| panic!("reserved attachment refuses"));
        assert_eq!(
            error,
            CoordinatorResourceRefusal::Task(TaskStateError::DurablePublicationReserved)
        );
        assert_eq!(drops.load(Ordering::Acquire), 0);
        assert_eq!(coordinator.snapshot(), before_attachment);
        lock(&coordinator.inner.state).durable_publication_reserved = false;
        coordinator
            .attach_resource_host_value(&subject, owner, value)
            .unwrap_or_else(|_| panic!("unreserved attachment succeeds"));
        coordinator
            .begin_resource_finish(&subject, owner)
            .unwrap_or_else(|error| panic!("begin finish: {error:?}"));
        lock(&coordinator.inner.state).durable_publication_reserved = true;
        let before_disposal = coordinator.snapshot();
        assert_eq!(
            coordinator.dispose_resource_host_value(&subject, owner),
            Err(CoordinatorResourceRefusal::Task(
                TaskStateError::DurablePublicationReserved
            ))
        );
        assert_eq!(
            coordinator.emergency_release_resource_cohort(Vec::new()),
            Err(CoordinatorResourceRefusal::Task(
                TaskStateError::DurablePublicationReserved
            ))
        );
        assert_eq!(
            coordinator.dispose_settled_resource_host_values(),
            Err(CoordinatorResourceRefusal::Task(
                TaskStateError::DurablePublicationReserved
            ))
        );
        assert_eq!(drops.load(Ordering::Acquire), 0);
        assert_eq!(coordinator.snapshot(), before_disposal);
        lock(&coordinator.inner.state).durable_publication_reserved = false;
        assert_eq!(
            coordinator.dispose_resource_host_value(&subject, owner),
            Ok(())
        );
        assert_eq!(drops.load(Ordering::Acquire), 1);
        assert_eq!(coordinator.snapshot(), before_disposal);
    }

    /// Detects any destruction before a publication-reservation refusal returns ownership.
    struct ReservationDropProbe(Arc<AtomicUsize>);

    impl Drop for ReservationDropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn identity(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
        ProtocolIdentity::from_fresh_material(kind, [byte; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}"))
    }
}
