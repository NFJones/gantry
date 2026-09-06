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
        Self::new_inner(tasks, sessions, None)
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
        Self::new_inner(tasks, sessions, Some(execution_budget))
    }

    fn new_inner(
        tasks: ConcurrentTaskStateV1,
        sessions: LogicalSessionRegistryV1,
        execution_budget: Option<ExecutionBudget>,
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
        let budget = state
            .execution_budget
            .as_ref()
            .ok_or(crate::ConcurrentDurableCheckpointError::InvalidCheckpoint)?;
        let foreground = foreground
            .clone_with_staged_budget(budget.clone())
            .map_err(crate::ConcurrentDurableCheckpointError::Machine)?;
        let children = children
            .iter()
            .map(|(task_id, machine)| {
                machine
                    .clone_with_staged_budget(budget.clone())
                    .map(|machine| (*task_id, machine))
                    .map_err(crate::ConcurrentDurableCheckpointError::Machine)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        crate::ConcurrentDurableCheckpointV4::capture_coordinated(
            &foreground,
            &children,
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

    /// Registers a race-safe observer for physical task-driver quiescence.
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

/// Independent observer for physical completion of every task driver.
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
            if state.tasks.drivers_are_quiescent() {
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

fn take_shutdown_waiters_if_quiescent(state: &mut CoordinatorState) -> Vec<RegisteredWaiter> {
    if state.tasks.drivers_are_quiescent() {
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

    fn identity(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
        ProtocolIdentity::from_fresh_material(kind, [byte; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}"))
    }
}
