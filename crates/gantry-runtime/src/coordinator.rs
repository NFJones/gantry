//! Linearizable execution-scoped ownership of root and child task state.
//!
//! The coordinator has one shared mutex. Task state, logical sessions,
//! completion coordinates, and waiter registration are changed only while
//! that mutex is held. Wakers are removed with the published successor, then
//! invoked after the guard is dropped. The coordinator mutex is never held
//! while polling a host future and must not be nested with lifecycle,
//! supervision, adapter, event-delivery, or journal locks; callers snapshot
//! the required state before invoking those owners.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::task::{Context, Poll, Waker};

use gantry_core::identity::ProtocolIdentity;
use gantry_core::value::ValueLimits;
use gantry_host::contracts::HostError;
use gantry_ir::{StructuralPosition, TaskControlSite};

use crate::task::TaskSubmissionDispositionV1;
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
    task_waiters: BTreeMap<ProtocolIdentity, Vec<RegisteredWaiter>>,
    foreground_waiters: Vec<RegisteredWaiter>,
    terminal_waiters: Vec<RegisteredWaiter>,
    shutdown_waiters: Vec<RegisteredWaiter>,
    /// Reserved by a durable transaction; retained if its commit is indeterminate.
    durable_publication_reserved: bool,
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
                    task_waiters: BTreeMap::new(),
                    foreground_waiters: Vec::new(),
                    terminal_waiters: Vec::new(),
                    shutdown_waiters: Vec::new(),
                    durable_publication_reserved: false,
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
    ) -> Result<TaskSubmissionDispositionV1, TaskStateError> {
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
        let (outcome, waiters) = {
            let mut state = lock(&self.inner.state);
            require_publication_available(&state)?;
            let outcome = state
                .tasks
                .root_settled_outcome()
                .cloned()
                .ok_or(TaskStateError::RootTaskPending)?;
            state.tasks.complete_foreground(outcome.clone())?;
            state.publication = state.publication.wrapping_add(1);
            (outcome, std::mem::take(&mut state.foreground_waiters))
        };
        wake_all(waiters);
        Ok(outcome)
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

    /// Returns a stable snapshot of work participating in execution shutdown.
    #[must_use]
    pub fn shutdown_cohort(&self) -> ConcurrentShutdownCohortV1 {
        lock(&self.inner.state).tasks.shutdown_cohort()
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
