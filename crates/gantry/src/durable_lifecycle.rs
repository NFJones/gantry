//! Durable lifecycle ownership and observation over authoritative journal state.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{
    CancellationReasonCategory, ExecutionObservationState, JournalOwnerStatus,
};
use gantry_host::contracts::DurationMicros;
use gantry_host::event::ProtectedPayload;
use gantry_host::journal::{
    JournalError, JournalId, JournalOwnershipToken, JournalPrefixV1, JournalStorage,
    ReadJournalPrefixV1, ReleaseJournalOwnerV1,
};
use gantry_observe::SinkPlan;
use gantry_runtime::{
    CancellationReason, DurableCommitCoordinatorV1, DurableCommitCutV1, DurableCommitError,
    DurableEventCommitCoordinatorV1, DurableEventCommitError, DurableEventOccurrenceV1,
    DurableEventPlanV1, DurableEvidenceError, DurableOperationEvidenceV1, DurableTransitionSink,
    ExecutionHandle, ExecutionTransitionError, FinalShutdownEventSettlement, InterpreterLifecycle,
    LifecycleError, MachineOutcome, RecoveredDurableStateV1, RequiredEventDeliveryFailureV1,
    ShutdownCompletionError, ShutdownReport, recover_authoritative_prefix_with_retained_program,
};

static NEXT_DURABLE_WAITER_ID: AtomicU64 = AtomicU64::new(0);

/// Read-only durable execution query by stable journal identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableQueryExecutionRequest {
    /// Stable journal whose authoritative prefix is observed.
    pub journal_id: JournalId,
    /// Optional assertion preventing a journal from being confused with another execution.
    pub expected_execution_id: Option<ProtocolIdentity>,
}

/// One internally consistent projection of the latest authoritative durable prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableExecutionObservation {
    /// Stable journal used for this observation.
    pub journal_id: JournalId,
    /// Execution identity accepted by sequence one.
    pub execution_id: ProtocolIdentity,
    /// Exact observation-state vocabulary value.
    pub state: ExecutionObservationState,
    /// Durable foreground outcome when a foreground-completion cut exists.
    pub foreground: Option<MachineOutcome>,
    /// Durable terminal outcome only when a terminal-completion cut exists.
    pub terminal: Option<MachineOutcome>,
    /// First durably committed cancellation reason, when one exists.
    pub cancellation: Option<CancellationReason>,
    /// Required-delivery failures retained separately from the language outcome.
    pub required_delivery_failures: Arc<[RequiredEventDeliveryFailureV1]>,
    /// In-process owner state; read-only cross-process queries leave this absent.
    pub owner: Option<DurableJournalOwnerState>,
    /// Operational failure of the current run, never a durable language outcome.
    pub run_failure: Option<DurableRunFailure>,
    /// Latest authoritative logical sequence represented by the projection.
    pub latest_sequence: u64,
    /// Latest storage-assigned evidence identity represented by the projection.
    pub latest_evidence_id: ProtocolIdentity,
}

impl DurableExecutionObservation {
    /// Returns the latest authoritative semantic cut represented by this observation.
    #[must_use]
    pub const fn latest_cut(&self) -> DurableCommitCutV1 {
        if self.terminal.is_some() {
            DurableCommitCutV1::TerminalCompletion
        } else if self.foreground.is_some() {
            DurableCommitCutV1::ForegroundCompletion
        } else {
            DurableCommitCutV1::Checkpoint
        }
    }
}

/// Operational durable-query failure that does not fabricate execution state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableQueryExecutionFailure {
    /// Stable journal supplied by the caller.
    pub journal_id: JournalId,
    /// Exact storage or authoritative-format failure.
    pub error: DurableQueryExecutionError,
}

/// Closed implementation error union for durable prefix observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableQueryExecutionError {
    /// Journal storage could not return the authoritative prefix.
    Journal(JournalError),
    /// Returned history was malformed or lacked required durable state.
    Format(DurableEvidenceError),
}

/// Read-only durable query result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableQueryExecutionResult {
    /// No execution-start record exists, or the expected execution identity did not match.
    NotFound {
        /// Stable journal supplied by the caller.
        journal_id: JournalId,
    },
    /// One authoritative point-in-time snapshot was recovered without mutation.
    Snapshot(Box<DurableExecutionObservation>),
    /// Storage or authoritative-format observation failed.
    Failed(DurableQueryExecutionFailure),
}

/// In-process journal-owner state with release failure retained separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableJournalOwnerState {
    /// The current process still holds the fenced token.
    Held,
    /// The token was invalidated by the one orderly release attempt.
    Released,
    /// The one release attempt failed and its exact journal error is retained.
    ReleaseFailed(JournalError),
}

impl DurableJournalOwnerState {
    /// Returns the closed portable owner-status discriminant.
    #[must_use]
    pub const fn kind(&self) -> JournalOwnerStatus {
        match self {
            Self::Held => JournalOwnerStatus::Held,
            Self::Released => JournalOwnerStatus::Released,
            Self::ReleaseFailed(_) => JournalOwnerStatus::ReleaseFailed,
        }
    }
}

/// Operational failure of one in-process durable run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableRunFailure {
    /// A journal-first semantic commit failed or returned an invalid receipt.
    Commit(DurableCommitError),
    /// Committed state could not be published into the in-process lifecycle owner.
    Lifecycle(ExecutionTransitionError),
    /// A safely contained interpreter invariant prevented further durable progress.
    Internal,
}

/// Result of opening an accepted fenced execution for durable lifecycle control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableOwnedExecutionOpenError {
    /// Storage could not return the authoritative prefix.
    Journal(JournalError),
    /// The authoritative prefix was malformed or incomplete.
    Format(DurableEvidenceError),
    /// The journal did not contain the expected accepted execution.
    NotFound,
    /// Recovered state could not be reflected in the supplied lifecycle handle.
    Lifecycle(ExecutionTransitionError),
}

/// Closed durable cancellation result preserving terminal and operational coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableCancelExecutionResult {
    /// The first committed reason won and the resulting terminal state is durable.
    Accepted {
        /// Canonical first committed reason, including on repeated calls.
        effective_reason: CancellationReason,
        /// Durable terminal observation with separate owner and barrier state.
        terminal: Box<DurableExecutionObservation>,
    },
    /// Terminal state was already durable before this request linearized.
    AlreadyTerminal(Box<DurableExecutionObservation>),
    /// The supplied execution identity did not name this owned execution.
    NotFound {
        /// Identity supplied by the caller.
        execution_id: ProtocolIdentity,
    },
    /// The current run failed operationally without fabricating terminal state.
    Failed {
        /// First reason when cancellation itself had already committed.
        effective_reason: Option<CancellationReason>,
        /// Exact current-run failure.
        failure: DurableRunFailure,
        /// Last authoritative observation, including `run-failed-nondurably`.
        observation: Box<DurableExecutionObservation>,
    },
}

/// Immutable sequential-durable shutdown result with separated execution coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableShutdownReport {
    /// Shared interpreter lifecycle report fixed by the unique shutdown coordinator.
    pub lifecycle: Arc<ShutdownReport>,
    /// Final in-process durable observations in execution-identity order.
    pub executions: Arc<[DurableExecutionObservation]>,
}

/// Failure to coordinate one sequential-durable shutdown invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableShutdownError {
    /// Interpreter lifecycle admission rejected shutdown.
    Lifecycle(LifecycleError),
    /// The caller supplied one durable owner more than once.
    DuplicateOwnedExecution(ProtocolIdentity),
    /// A supplied durable owner belongs to another interpreter lifecycle.
    WrongLifecycle(ProtocolIdentity),
    /// A shutdown-cohort execution had no durable owner supplied by the facade.
    MissingOwnedExecution(ProtocolIdentity),
    /// Lifecycle invariants prevented final report publication.
    Completion(ShutdownCompletionError),
}

/// Independent durable foreground or terminal waiter.
pub struct DurableExecutionWait<'a> {
    execution: &'a DurableOwnedExecution,
    terminal: bool,
    waiter_id: u64,
}

/// One accepted, fenced durable execution and its serial authoritative state.
pub struct DurableOwnedExecution {
    storage: Arc<dyn JournalStorage>,
    event_plan: SinkPlan,
    journal_id: JournalId,
    ownership_token: JournalOwnershipToken,
    handle: ExecutionHandle,
    state: Mutex<DurableOwnedExecutionState>,
}

impl std::fmt::Debug for DurableOwnedExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableOwnedExecution")
            .field("journal_id", &self.journal_id)
            .field("execution_id", &self.handle.execution_id())
            .finish_non_exhaustive()
    }
}

struct DurableOwnedExecutionState {
    recovered: Option<RecoveredDurableStateV1>,
    owner: DurableJournalOwnerState,
    run_failure: Option<DurableRunFailure>,
    completed_cancellation: Option<DurableCancelExecutionResult>,
    operation_in_flight: bool,
    driver_active: bool,
    driver_cancellation: Option<CancellationReason>,
    driver_waker: Option<Waker>,
    generation: u64,
    operation_waiters: Vec<Waker>,
    observation_waiters: Vec<DurableRegisteredWaiter>,
    last_observation: DurableExecutionObservation,
}

struct DurableRegisteredWaiter {
    waiter_id: u64,
    waker: Waker,
}

pub(crate) enum DurableDriverPoll<T> {
    Completed(T),
    CancellationSettled,
}

#[derive(Default)]
struct DurableShutdownState {
    report: Option<Arc<DurableShutdownReport>>,
    operation_in_flight: bool,
    generation: u64,
    waiters: Vec<Waker>,
}

/// Durable read-only lifecycle coordinator over one journal adapter.
pub struct DurableLifecycleCoordinator {
    storage: Arc<dyn JournalStorage>,
    shutdown: Mutex<DurableShutdownState>,
}

impl DurableLifecycleCoordinator {
    /// Binds durable lifecycle observation to one backend-neutral journal adapter.
    #[must_use]
    pub fn new(storage: Arc<dyn JournalStorage>) -> Self {
        Self {
            storage,
            shutdown: Mutex::new(DurableShutdownState::default()),
        }
    }

    pub(crate) fn own_committed_start(
        &self,
        journal_id: JournalId,
        ownership_token: JournalOwnershipToken,
        handle: ExecutionHandle,
        recovered: RecoveredDurableStateV1,
        event_plan: SinkPlan,
    ) -> Result<Arc<DurableOwnedExecution>, DurableOwnedExecutionOpenError> {
        let execution_id = recovered
            .execution_start()
            .map(|start| start.execution_id())
            .ok_or(DurableOwnedExecutionOpenError::NotFound)?;
        if handle.execution_id() != execution_id {
            return Err(DurableOwnedExecutionOpenError::NotFound);
        }
        restore_lifecycle(&handle, &recovered)
            .map_err(DurableOwnedExecutionOpenError::Lifecycle)?;
        let owner = DurableJournalOwnerState::Held;
        let observation =
            observation_from_recovered(&journal_id, &handle, &recovered, Some(owner.clone()), None);
        Ok(Arc::new(DurableOwnedExecution {
            storage: Arc::clone(&self.storage),
            event_plan,
            journal_id,
            ownership_token,
            handle,
            state: Mutex::new(DurableOwnedExecutionState {
                recovered: Some(recovered),
                owner,
                run_failure: None,
                completed_cancellation: None,
                operation_in_flight: false,
                driver_active: false,
                driver_cancellation: None,
                driver_waker: None,
                generation: 0,
                operation_waiters: Vec::new(),
                observation_waiters: Vec::new(),
                last_observation: observation,
            }),
        }))
    }

    /// Runs or joins the unique sequential-durable shutdown coordinator.
    ///
    /// Every supplied owner must belong to `lifecycle`. The first call fixes the
    /// effective durations and final event settlement; later calls return the same
    /// immutable report. Concurrent profiles extend `owned_executions` with their
    /// additional execution-owned tasks rather than defining another shutdown path.
    pub async fn shutdown(
        &self,
        lifecycle: &InterpreterLifecycle,
        owned_executions: &[Arc<DurableOwnedExecution>],
        graceful_override: Option<DurationMicros>,
        drain_override: Option<DurationMicros>,
        final_event: FinalShutdownEventSettlement,
    ) -> Result<Arc<DurableShutdownReport>, DurableShutdownError> {
        let owned = index_owned_executions(lifecycle, owned_executions)?;
        loop {
            let generation = {
                let mut shutdown = lock_shutdown(&self.shutdown);
                if let Some(report) = &shutdown.report {
                    return Ok(Arc::clone(report));
                }
                if shutdown.operation_in_flight {
                    Some(shutdown.generation)
                } else {
                    shutdown.operation_in_flight = true;
                    None
                }
            };
            if let Some(generation) = generation {
                self.wait_for_shutdown_generation(generation).await;
                continue;
            }

            let result = self
                .drive_shutdown(
                    lifecycle,
                    &owned,
                    graceful_override,
                    drain_override,
                    final_event,
                )
                .await;
            let mut shutdown = lock_shutdown(&self.shutdown);
            shutdown.operation_in_flight = false;
            shutdown.generation = shutdown.generation.wrapping_add(1);
            if let Ok(report) = &result {
                shutdown.report = Some(Arc::clone(report));
            }
            let waiters = std::mem::take(&mut shutdown.waiters);
            drop(shutdown);
            for waiter in waiters {
                waiter.wake();
            }
            return result;
        }
    }

    async fn drive_shutdown(
        &self,
        lifecycle: &InterpreterLifecycle,
        owned: &BTreeMap<ProtocolIdentity, Arc<DurableOwnedExecution>>,
        graceful_override: Option<DurationMicros>,
        drain_override: Option<DurationMicros>,
        final_event: FinalShutdownEventSettlement,
    ) -> Result<Arc<DurableShutdownReport>, DurableShutdownError> {
        let mut admission = lifecycle
            .begin_shutdown(graceful_override, drain_override)
            .map_err(DurableShutdownError::Lifecycle)?;
        let Some(coordinator) = admission.coordinator.take() else {
            let lifecycle_report = admission.wait.await;
            let executions = owned
                .values()
                .map(|execution| execution.observation())
                .collect::<Vec<_>>();
            return Ok(Arc::new(DurableShutdownReport {
                lifecycle: lifecycle_report,
                executions: Arc::from(executions),
            }));
        };

        for execution_id in coordinator.pending_executions().iter().copied() {
            let execution = owned
                .get(&execution_id)
                .ok_or(DurableShutdownError::MissingOwnedExecution(execution_id))?;
            let reason =
                CancellationReason::new(CancellationReasonCategory::Shutdown, None, None, 0)
                    .unwrap_or_else(|_| unreachable!("empty shutdown reason is always bounded"));
            let _ = execution.cancel_execution(execution_id, reason).await;
        }

        let mut executions = Vec::with_capacity(owned.len());
        let mut orderly = final_event == FinalShutdownEventSettlement::Settled;
        for execution in owned.values() {
            let observation = execution.release_owner_once().await;
            orderly &= observation.run_failure.is_none()
                && observation.required_delivery_failures.is_empty()
                && observation.owner == Some(DurableJournalOwnerState::Released);
            executions.push(observation);
        }
        coordinator.wait_for_quiescence().await;
        let lifecycle_report = coordinator
            .complete(orderly, final_event)
            .map_err(DurableShutdownError::Completion)?;
        Ok(Arc::new(DurableShutdownReport {
            lifecycle: lifecycle_report,
            executions: Arc::from(executions),
        }))
    }

    async fn wait_for_shutdown_generation(&self, generation: u64) {
        poll_fn(|context| {
            let mut shutdown = lock_shutdown(&self.shutdown);
            if shutdown.generation != generation {
                return Poll::Ready(());
            }
            if !shutdown
                .waiters
                .iter()
                .any(|waiter| waiter.will_wake(context.waker()))
            {
                shutdown.waiters.push(context.waker().clone());
            }
            Poll::Pending
        })
        .await
    }

    /// Opens one already accepted fenced execution for cancellation, await, and release control.
    pub async fn open_owned_execution(
        &self,
        journal_id: JournalId,
        ownership_token: JournalOwnershipToken,
        handle: ExecutionHandle,
        expected_execution_id: ProtocolIdentity,
    ) -> Result<Arc<DurableOwnedExecution>, DurableOwnedExecutionOpenError> {
        let prefix = self
            .storage
            .read_prefix(ReadJournalPrefixV1 {
                journal_id: journal_id.clone(),
            })
            .await
            .map_err(DurableOwnedExecutionOpenError::Journal)?;
        if prefix_is_empty(&prefix) {
            return Err(DurableOwnedExecutionOpenError::NotFound);
        }
        let (_, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
            .map_err(DurableOwnedExecutionOpenError::Format)?;
        let execution_id = recovered
            .execution_start()
            .map(|start| start.execution_id())
            .ok_or(DurableOwnedExecutionOpenError::NotFound)?;
        if execution_id != expected_execution_id || handle.execution_id() != execution_id {
            return Err(DurableOwnedExecutionOpenError::NotFound);
        }
        restore_lifecycle(&handle, &recovered)
            .map_err(DurableOwnedExecutionOpenError::Lifecycle)?;
        let owner = DurableJournalOwnerState::Held;
        let observation =
            observation_from_recovered(&journal_id, &handle, &recovered, Some(owner.clone()), None);
        Ok(Arc::new(DurableOwnedExecution {
            storage: Arc::clone(&self.storage),
            event_plan: SinkPlan::default(),
            journal_id,
            ownership_token,
            handle,
            state: Mutex::new(DurableOwnedExecutionState {
                recovered: Some(recovered),
                owner,
                run_failure: None,
                completed_cancellation: None,
                operation_in_flight: false,
                driver_active: false,
                driver_cancellation: None,
                driver_waker: None,
                generation: 0,
                operation_waiters: Vec::new(),
                observation_waiters: Vec::new(),
                last_observation: observation,
            }),
        }))
    }

    /// Returns one point-in-time authoritative snapshot without acquiring ownership or writing.
    pub async fn query(
        &self,
        request: DurableQueryExecutionRequest,
    ) -> DurableQueryExecutionResult {
        let journal_id = request.journal_id;
        let prefix = match self
            .storage
            .read_prefix(ReadJournalPrefixV1 {
                journal_id: journal_id.clone(),
            })
            .await
        {
            Ok(prefix) => prefix,
            Err(error) => {
                return DurableQueryExecutionResult::Failed(DurableQueryExecutionFailure {
                    journal_id,
                    error: DurableQueryExecutionError::Journal(error),
                });
            }
        };
        if prefix_is_empty(&prefix) {
            return DurableQueryExecutionResult::NotFound { journal_id };
        }
        let (_, recovered) = match recover_authoritative_prefix_with_retained_program(&prefix) {
            Ok(recovered) => recovered,
            Err(error) => {
                return DurableQueryExecutionResult::Failed(DurableQueryExecutionFailure {
                    journal_id,
                    error: DurableQueryExecutionError::Format(error),
                });
            }
        };
        let Some(execution_start) = recovered.execution_start() else {
            return DurableQueryExecutionResult::Failed(DurableQueryExecutionFailure {
                journal_id,
                error: DurableQueryExecutionError::Format(
                    DurableEvidenceError::MissingRecoveryState,
                ),
            });
        };
        let execution_id = execution_start.execution_id();
        if request
            .expected_execution_id
            .is_some_and(|expected| expected != execution_id)
        {
            return DurableQueryExecutionResult::NotFound { journal_id };
        }

        DurableQueryExecutionResult::Snapshot(Box::new(observation_from_recovered(
            &journal_id,
            &None::<ExecutionHandle>,
            &recovered,
            None,
            None,
        )))
    }
}

impl DurableOwnedExecution {
    /// Returns the accepted execution identity controlled by this owner.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.handle.execution_id()
    }

    pub(crate) fn execution_handle(&self) -> ExecutionHandle {
        self.handle.clone()
    }

    /// Returns the stable journal target controlled by this owner.
    #[must_use]
    pub fn journal_id(&self) -> &JournalId {
        &self.journal_id
    }

    /// Returns the latest in-process observation without advancing execution.
    #[must_use]
    pub fn observation(&self) -> DurableExecutionObservation {
        lock_state(&self.state).last_observation.clone()
    }

    pub(crate) fn begin_driver(&self) -> Option<RecoveredDurableStateV1> {
        let mut state = lock_state(&self.state);
        if state.operation_in_flight || state.run_failure.is_some() {
            return None;
        }
        state.operation_in_flight = true;
        state.driver_active = true;
        state.recovered.take()
    }

    pub(crate) fn take_driver_cancellation(&self) -> Option<CancellationReason> {
        let mut state = lock_state(&self.state);
        state.driver_waker = None;
        state.driver_cancellation.take()
    }

    pub(crate) async fn poll_driver_future<F>(
        &self,
        recovered: &mut RecoveredDurableStateV1,
        last_committed: &mut RecoveredDurableStateV1,
        future: F,
    ) -> Result<DurableDriverPoll<F::Output>, DurableRunFailure>
    where
        F: Future,
    {
        let mut future = std::pin::pin!(future);
        let first = poll_fn(|context| {
            {
                let mut state = lock_state(&self.state);
                if let Some(reason) = state.driver_cancellation.take() {
                    state.driver_waker = None;
                    return Poll::Ready(Err(reason));
                }
                state.driver_waker = Some(context.waker().clone());
            }
            match future.as_mut().poll(context) {
                Poll::Ready(output) => {
                    lock_state(&self.state).driver_waker = None;
                    Poll::Ready(Ok(output))
                }
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        match first {
            Ok(output) => Ok(DurableDriverPoll::Completed(output)),
            Err(reason) => {
                if let Err(failure) = self.commit_driver_cancellation(recovered, reason).await {
                    let _ = self.handle.publish_run_failed_nondurably();
                    let _ = future.await;
                    return Err(failure);
                }
                *last_committed = recovered.clone();
                let _ = future.await;
                Ok(DurableDriverPoll::CancellationSettled)
            }
        }
    }

    pub(crate) async fn commit_driver_cancellation(
        &self,
        recovered: &mut RecoveredDurableStateV1,
        requested_reason: CancellationReason,
    ) -> Result<CancellationReason, DurableRunFailure> {
        let effective_reason = if let Some(reason) = recovered.cancellation_reason().cloned() {
            reason
        } else {
            let execution_start = recovered
                .execution_start()
                .unwrap_or_else(|| unreachable!("owned durable state retains sequence one"));
            let reason_text = requested_reason
                .message
                .clone()
                .unwrap_or_else(|| Arc::from(requested_reason.category.wire_name()));
            let mut staged_machine = recovered.machine().clone();
            let _ = staged_machine.cancel(reason_text);
            let sink = DurableTransitionSink::new(
                Arc::clone(&self.storage),
                self.journal_id.clone(),
                self.ownership_token.clone(),
            );
            let mut commits = DurableCommitCoordinatorV1::new(
                &sink,
                execution_start.execution_id(),
                execution_start.task_id(),
                Some((recovered.latest_evidence_id(), recovered.latest_sequence())),
            )
            .map_err(DurableRunFailure::Commit)?;
            let commit = commits
                .commit_cancellation(
                    requested_reason.clone(),
                    &staged_machine,
                    recovered.sessions(),
                )
                .await
                .map_err(DurableRunFailure::Commit)?;
            recovered
                .record_cancellation_commit(requested_reason.clone(), &commit)
                .map_err(|error| DurableRunFailure::Commit(DurableCommitError::Evidence(error)))?;
            *recovered.machine_mut() = staged_machine;
            requested_reason
        };
        self.handle
            .publish_committed_cancellation(effective_reason.clone())
            .map_err(DurableRunFailure::Lifecycle)?;
        self.update_driver_observation(recovered, None);
        Ok(effective_reason)
    }

    pub(crate) async fn commit_driver_cut(
        &self,
        recovered: &mut RecoveredDurableStateV1,
        cut: DurableCommitCutV1,
        operation: Option<DurableOperationEvidenceV1>,
    ) -> Result<(), DurableRunFailure> {
        let execution_start = recovered
            .execution_start()
            .unwrap_or_else(|| unreachable!("owned durable state retains sequence one"));
        let sink = DurableTransitionSink::new(
            Arc::clone(&self.storage),
            self.journal_id.clone(),
            self.ownership_token.clone(),
        );
        let mut commits = DurableCommitCoordinatorV1::new(
            &sink,
            execution_start.execution_id(),
            execution_start.task_id(),
            Some((recovered.latest_evidence_id(), recovered.latest_sequence())),
        )
        .map_err(DurableRunFailure::Commit)?;
        let commit = commits
            .commit_cut(cut, operation, recovered.machine(), recovered.sessions())
            .await
            .map_err(DurableRunFailure::Commit)?;
        recovered
            .record_semantic_commit(&commit)
            .map_err(|error| DurableRunFailure::Commit(DurableCommitError::Evidence(error)))
    }

    pub(crate) async fn commit_driver_event(
        &self,
        recovered: &mut RecoveredDurableStateV1,
        event: gantry_core::event::EventEnvelope,
        protected_payloads: &[ProtectedPayload],
    ) -> Result<(), DurableRunFailure> {
        let cause = recovered.latest_evidence_id();
        let plan = DurableEventPlanV1::from_sink_plan(&self.event_plan)
            .map_err(|_| DurableRunFailure::Internal)?;
        let occurrence = DurableEventOccurrenceV1::new(cause, event, plan)
            .map_err(|_| DurableRunFailure::Internal)?;
        let sink = DurableTransitionSink::new(
            Arc::clone(&self.storage),
            self.journal_id.clone(),
            self.ownership_token.clone(),
        );
        let mut commits = DurableEventCommitCoordinatorV1::from_recovered(
            &sink,
            (cause, recovered.latest_sequence()),
            recovered.events(),
        )
        .map_err(map_event_commit_failure)?;
        commits
            .commit_occurrence(&occurrence, protected_payloads)
            .await
            .map_err(map_event_commit_failure)?;
        let prefix = self
            .storage
            .read_prefix(ReadJournalPrefixV1 {
                journal_id: self.journal_id.clone(),
            })
            .await
            .map_err(|error| DurableRunFailure::Commit(DurableCommitError::Journal(error)))?;
        let (_, refreshed) = recover_authoritative_prefix_with_retained_program(&prefix)
            .map_err(|error| DurableRunFailure::Commit(DurableCommitError::Evidence(error)))?;
        *recovered = refreshed;
        Ok(())
    }

    pub(crate) fn publish_driver_progress(
        &self,
        recovered: &RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        let outcome = recovered.machine().outcome().cloned();
        if recovered.latest_cut() == DurableCommitCutV1::ForegroundCompletion
            && let Some(outcome) = outcome.clone()
        {
            self.handle
                .publish_committed_foreground(outcome)
                .map_err(DurableRunFailure::Lifecycle)?;
        }
        if recovered.latest_cut() == DurableCommitCutV1::TerminalCompletion
            && let Some(outcome) = outcome
        {
            let snapshot = self
                .handle
                .snapshot()
                .map_err(DurableRunFailure::Lifecycle)?;
            if snapshot.foreground.is_none() {
                self.handle
                    .publish_committed_foreground(outcome.clone())
                    .map_err(DurableRunFailure::Lifecycle)?;
            }
            self.handle
                .publish_committed_terminal(outcome)
                .map_err(DurableRunFailure::Lifecycle)?;
        }
        self.update_driver_observation(recovered, None);
        Ok(())
    }

    pub(crate) fn finish_driver(&self, recovered: RecoveredDurableStateV1) {
        let mut state = lock_state(&self.state);
        state.last_observation = observation_from_recovered(
            &self.journal_id,
            &self.handle,
            &recovered,
            Some(state.owner.clone()),
            None,
        );
        if let Some(effective_reason) = recovered.cancellation_reason().cloned() {
            state.completed_cancellation = Some(DurableCancelExecutionResult::Accepted {
                effective_reason,
                terminal: Box::new(state.last_observation.clone()),
            });
        }
        state.recovered = Some(recovered);
        state.operation_in_flight = false;
        state.driver_active = false;
        state.driver_cancellation = None;
        state.driver_waker = None;
        state.generation = state.generation.wrapping_add(1);
        let operation_waiters = std::mem::take(&mut state.operation_waiters);
        let observation_waiters = state
            .observation_waiters
            .iter()
            .map(|waiter| waiter.waker.clone())
            .collect::<Vec<_>>();
        drop(state);
        for waiter in operation_waiters.into_iter().chain(observation_waiters) {
            waiter.wake();
        }
    }

    pub(crate) fn fail_driver(
        &self,
        recovered: RecoveredDurableStateV1,
        failure: DurableRunFailure,
    ) {
        let _ = self.handle.publish_run_failed_nondurably();
        let mut state = lock_state(&self.state);
        state.last_observation = observation_from_recovered(
            &self.journal_id,
            &self.handle,
            &recovered,
            Some(state.owner.clone()),
            Some(failure.clone()),
        );
        state.recovered = Some(recovered);
        state.run_failure = Some(failure);
        state.operation_in_flight = false;
        state.driver_active = false;
        state.driver_cancellation = None;
        state.driver_waker = None;
        state.generation = state.generation.wrapping_add(1);
        let operation_waiters = std::mem::take(&mut state.operation_waiters);
        let observation_waiters = state
            .observation_waiters
            .iter()
            .map(|waiter| waiter.waker.clone())
            .collect::<Vec<_>>();
        drop(state);
        for waiter in operation_waiters.into_iter().chain(observation_waiters) {
            waiter.wake();
        }
    }

    fn update_driver_observation(
        &self,
        recovered: &RecoveredDurableStateV1,
        failure: Option<DurableRunFailure>,
    ) {
        let mut state = lock_state(&self.state);
        state.last_observation = observation_from_recovered(
            &self.journal_id,
            &self.handle,
            recovered,
            Some(state.owner.clone()),
            failure,
        );
        let observation_waiters = state
            .observation_waiters
            .iter()
            .map(|waiter| waiter.waker.clone())
            .collect::<Vec<_>>();
        drop(state);
        for waiter in observation_waiters {
            waiter.wake();
        }
    }

    /// Registers an independent durable foreground waiter.
    #[must_use]
    pub fn await_foreground(&self) -> DurableExecutionWait<'_> {
        DurableExecutionWait {
            execution: self,
            terminal: false,
            waiter_id: NEXT_DURABLE_WAITER_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Registers an independent durable terminal waiter.
    #[must_use]
    pub fn await_terminal(&self) -> DurableExecutionWait<'_> {
        DurableExecutionWait {
            execution: self,
            terminal: true,
            waiter_id: NEXT_DURABLE_WAITER_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Commits cancellation before signalling and drives sequential state to a durable terminal cut.
    pub async fn cancel_execution(
        &self,
        execution_id: ProtocolIdentity,
        mut requested_reason: CancellationReason,
    ) -> DurableCancelExecutionResult {
        if execution_id != self.execution_id() {
            return DurableCancelExecutionResult::NotFound { execution_id };
        }
        loop {
            let (mut recovered, generation) = {
                let mut state = lock_state(&self.state);
                if let Some(result) = &state.completed_cancellation {
                    return result.clone();
                }
                if let Some(failure) = &state.run_failure {
                    return DurableCancelExecutionResult::Failed {
                        effective_reason: state.last_observation.cancellation.clone(),
                        failure: failure.clone(),
                        observation: Box::new(state.last_observation.clone()),
                    };
                }
                if state.driver_active {
                    if let Some(reason) = &state.driver_cancellation {
                        requested_reason = reason.clone();
                    } else {
                        state.driver_cancellation = Some(requested_reason.clone());
                    }
                    if let Some(waker) = state.driver_waker.take() {
                        waker.wake();
                    }
                    (None, state.generation)
                } else if state.operation_in_flight {
                    (None, state.generation)
                } else {
                    if let Some(reason) = state.driver_cancellation.take() {
                        requested_reason = reason;
                    }
                    state.operation_in_flight = true;
                    (state.recovered.take(), state.generation)
                }
            };
            let Some(recovered) = recovered.take() else {
                self.wait_for_generation(generation).await;
                continue;
            };
            let (recovered, owner, result, failure) = self
                .drive_cancellation(recovered, requested_reason.clone())
                .await;
            let mut state = lock_state(&self.state);
            state.recovered = Some(recovered);
            state.owner = owner;
            state.run_failure = failure;
            state.operation_in_flight = false;
            state.generation = state.generation.wrapping_add(1);
            state.last_observation = match &result {
                DurableCancelExecutionResult::Accepted { terminal, .. }
                | DurableCancelExecutionResult::AlreadyTerminal(terminal) => (**terminal).clone(),
                DurableCancelExecutionResult::Failed { observation, .. } => (**observation).clone(),
                DurableCancelExecutionResult::NotFound { .. } => state.last_observation.clone(),
            };
            if matches!(
                result,
                DurableCancelExecutionResult::Accepted { .. }
                    | DurableCancelExecutionResult::AlreadyTerminal(_)
            ) {
                state.completed_cancellation = Some(result.clone());
            }
            let operation_waiters = std::mem::take(&mut state.operation_waiters);
            let observation_waiters = state
                .observation_waiters
                .iter()
                .map(|waiter| waiter.waker.clone())
                .collect::<Vec<_>>();
            drop(state);
            for waiter in operation_waiters.into_iter().chain(observation_waiters) {
                waiter.wake();
            }
            return result;
        }
    }

    async fn drive_cancellation(
        &self,
        mut recovered: RecoveredDurableStateV1,
        requested_reason: CancellationReason,
    ) -> (
        RecoveredDurableStateV1,
        DurableJournalOwnerState,
        DurableCancelExecutionResult,
        Option<DurableRunFailure>,
    ) {
        if recovered.latest_cut() == DurableCommitCutV1::TerminalCompletion {
            let owner = self.release_owner().await;
            let observation = observation_from_recovered(
                &self.journal_id,
                &self.handle,
                &recovered,
                Some(owner.clone()),
                None,
            );
            return (
                recovered,
                owner,
                DurableCancelExecutionResult::AlreadyTerminal(Box::new(observation)),
                None,
            );
        }

        let execution_start = recovered
            .execution_start()
            .unwrap_or_else(|| unreachable!("owned execution was validated while opening"));
        let execution_id = execution_start.execution_id();
        let task_id = execution_start.task_id();
        let predecessor = Some((recovered.latest_evidence_id(), recovered.latest_sequence()));
        let sink = DurableTransitionSink::new(
            Arc::clone(&self.storage),
            self.journal_id.clone(),
            self.ownership_token.clone(),
        );
        let mut commits =
            DurableCommitCoordinatorV1::new(&sink, execution_id, task_id, predecessor)
                .unwrap_or_else(|_| unreachable!("validated owned identities and predecessor"));

        let effective_reason = match recovered.cancellation_reason().cloned() {
            Some(reason) => reason,
            None => {
                let reason_text = requested_reason
                    .message
                    .clone()
                    .unwrap_or_else(|| Arc::from(requested_reason.category.wire_name()));
                let mut staged_machine = recovered.machine().clone();
                let _ = staged_machine.cancel(reason_text);
                let commit = match commits
                    .commit_cancellation(
                        requested_reason.clone(),
                        &staged_machine,
                        recovered.sessions(),
                    )
                    .await
                {
                    Ok(commit) => commit,
                    Err(error) => {
                        return self.failed_cancellation(recovered, None, error);
                    }
                };
                if let Err(error) =
                    recovered.record_cancellation_commit(requested_reason.clone(), &commit)
                {
                    return self.failed_cancellation(
                        recovered,
                        Some(requested_reason),
                        DurableCommitError::Evidence(error),
                    );
                }
                *recovered.machine_mut() = staged_machine;
                requested_reason
            }
        };

        if let Err(error) = self
            .handle
            .publish_committed_cancellation(effective_reason.clone())
        {
            let failure = DurableRunFailure::Lifecycle(error);
            let observation = observation_from_recovered(
                &self.journal_id,
                &self.handle,
                &recovered,
                Some(DurableJournalOwnerState::Held),
                Some(failure.clone()),
            );
            return (
                recovered,
                DurableJournalOwnerState::Held,
                DurableCancelExecutionResult::Failed {
                    effective_reason: Some(effective_reason),
                    failure: failure.clone(),
                    observation: Box::new(observation),
                },
                Some(failure),
            );
        }

        loop {
            let step = recovered.machine_mut().step();
            let (cut, published) = match step {
                gantry_runtime::MachineStep::Transition(
                    gantry_runtime::MachineLabel::TaskSettled(_),
                ) => (Some(DurableCommitCutV1::TaskSettlement), None),
                gantry_runtime::MachineStep::Transition(
                    gantry_runtime::MachineLabel::ForegroundCompletion(outcome),
                ) => (
                    Some(DurableCommitCutV1::ForegroundCompletion),
                    Some((false, outcome)),
                ),
                gantry_runtime::MachineStep::Transition(
                    gantry_runtime::MachineLabel::TerminalCompletion(outcome),
                ) => (
                    Some(DurableCommitCutV1::TerminalCompletion),
                    Some((true, outcome)),
                ),
                gantry_runtime::MachineStep::Transition(_) => (None, None),
                gantry_runtime::MachineStep::Complete(_) => break,
                gantry_runtime::MachineStep::YieldRequired
                | gantry_runtime::MachineStep::WaitingOperation(_)
                | gantry_runtime::MachineStep::WaitingSessionScope(_) => continue,
            };
            let Some(cut) = cut else {
                continue;
            };
            let commit = match commits
                .commit_cut(cut, None, recovered.machine(), recovered.sessions())
                .await
            {
                Ok(commit) => commit,
                Err(error) => {
                    return self.failed_cancellation(recovered, Some(effective_reason), error);
                }
            };
            if let Err(error) = recovered.record_semantic_commit(&commit) {
                return self.failed_cancellation(
                    recovered,
                    Some(effective_reason),
                    DurableCommitError::Evidence(error),
                );
            }
            if let Some((terminal, outcome)) = published {
                let published = if terminal {
                    self.handle.publish_committed_terminal(outcome)
                } else {
                    self.handle.publish_committed_foreground(outcome)
                };
                if let Err(error) = published {
                    let failure = DurableRunFailure::Lifecycle(error);
                    let observation = observation_from_recovered(
                        &self.journal_id,
                        &self.handle,
                        &recovered,
                        Some(DurableJournalOwnerState::Held),
                        Some(failure.clone()),
                    );
                    return (
                        recovered,
                        DurableJournalOwnerState::Held,
                        DurableCancelExecutionResult::Failed {
                            effective_reason: Some(effective_reason),
                            failure: failure.clone(),
                            observation: Box::new(observation),
                        },
                        Some(failure),
                    );
                }
            }
        }

        let owner = self.release_owner().await;
        let observation = observation_from_recovered(
            &self.journal_id,
            &self.handle,
            &recovered,
            Some(owner.clone()),
            None,
        );
        (
            recovered,
            owner,
            DurableCancelExecutionResult::Accepted {
                effective_reason,
                terminal: Box::new(observation),
            },
            None,
        )
    }

    fn failed_cancellation(
        &self,
        recovered: RecoveredDurableStateV1,
        effective_reason: Option<CancellationReason>,
        error: DurableCommitError,
    ) -> (
        RecoveredDurableStateV1,
        DurableJournalOwnerState,
        DurableCancelExecutionResult,
        Option<DurableRunFailure>,
    ) {
        let failure = DurableRunFailure::Commit(error);
        let _ = self.handle.publish_run_failed_nondurably();
        let observation = observation_from_recovered(
            &self.journal_id,
            &self.handle,
            &recovered,
            Some(DurableJournalOwnerState::Held),
            Some(failure.clone()),
        );
        (
            recovered,
            DurableJournalOwnerState::Held,
            DurableCancelExecutionResult::Failed {
                effective_reason,
                failure: failure.clone(),
                observation: Box::new(observation),
            },
            Some(failure),
        )
    }

    async fn release_owner(&self) -> DurableJournalOwnerState {
        match self
            .storage
            .release_owner(ReleaseJournalOwnerV1 {
                journal_id: self.journal_id.clone(),
                ownership_token: self.ownership_token.clone(),
            })
            .await
        {
            Ok(()) => DurableJournalOwnerState::Released,
            Err(error) => DurableJournalOwnerState::ReleaseFailed(error),
        }
    }

    async fn release_owner_once(&self) -> DurableExecutionObservation {
        loop {
            let generation = {
                let mut state = lock_state(&self.state);
                if state.owner != DurableJournalOwnerState::Held {
                    return state.last_observation.clone();
                }
                if state.operation_in_flight {
                    Some(state.generation)
                } else {
                    state.operation_in_flight = true;
                    None
                }
            };
            if let Some(generation) = generation {
                self.wait_for_generation(generation).await;
                continue;
            }

            let owner = self.release_owner().await;
            let mut state = lock_state(&self.state);
            state.owner = owner.clone();
            state.last_observation.owner = Some(owner);
            state.operation_in_flight = false;
            state.generation = state.generation.wrapping_add(1);
            let observation = state.last_observation.clone();
            let operation_waiters = std::mem::take(&mut state.operation_waiters);
            let observation_waiters = state
                .observation_waiters
                .iter()
                .map(|waiter| waiter.waker.clone())
                .collect::<Vec<_>>();
            drop(state);
            for waiter in operation_waiters.into_iter().chain(observation_waiters) {
                waiter.wake();
            }
            return observation;
        }
    }

    async fn wait_for_generation(&self, generation: u64) {
        poll_fn(|context| {
            let mut state = lock_state(&self.state);
            if state.generation != generation {
                return Poll::Ready(());
            }
            if !state
                .operation_waiters
                .iter()
                .any(|waiter| waiter.will_wake(context.waker()))
            {
                state.operation_waiters.push(context.waker().clone());
            }
            Poll::Pending
        })
        .await
    }
}

impl Future for DurableExecutionWait<'_> {
    type Output = DurableExecutionObservation;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = lock_state(&self.execution.state);
        let observation = state.last_observation.clone();
        let ready = observation.run_failure.is_some()
            || (self.terminal && observation.terminal.is_some())
            || (!self.terminal && observation.foreground.is_some());
        if ready {
            state
                .observation_waiters
                .retain(|waiter| waiter.waiter_id != self.waiter_id);
            Poll::Ready(observation)
        } else {
            register_durable_waiter(
                &mut state.observation_waiters,
                self.waiter_id,
                context.waker(),
            );
            Poll::Pending
        }
    }
}

impl Drop for DurableExecutionWait<'_> {
    fn drop(&mut self) {
        lock_state(&self.execution.state)
            .observation_waiters
            .retain(|waiter| waiter.waiter_id != self.waiter_id);
    }
}

fn restore_lifecycle(
    handle: &ExecutionHandle,
    recovered: &RecoveredDurableStateV1,
) -> Result<(), ExecutionTransitionError> {
    let snapshot = handle.snapshot()?;
    if snapshot.cancellation.is_none()
        && let Some(reason) = recovered.cancellation_reason().cloned()
    {
        let _ = handle.publish_committed_cancellation(reason)?;
    }
    let outcome = recovered.machine().outcome().cloned();
    if snapshot.foreground.is_none()
        && matches!(
            recovered.latest_cut(),
            DurableCommitCutV1::ForegroundCompletion | DurableCommitCutV1::TerminalCompletion
        )
        && let Some(outcome) = outcome.clone()
    {
        handle.publish_committed_foreground(outcome)?;
    }
    let snapshot = handle.snapshot()?;
    if snapshot.terminal.is_none()
        && recovered.latest_cut() == DurableCommitCutV1::TerminalCompletion
        && let Some(outcome) = outcome
    {
        handle.publish_committed_terminal(outcome)?;
    }
    Ok(())
}

trait ObservationHandle {
    fn snapshot_for_observation(&self) -> Option<gantry_runtime::ExecutionSnapshot>;
}

impl ObservationHandle for ExecutionHandle {
    fn snapshot_for_observation(&self) -> Option<gantry_runtime::ExecutionSnapshot> {
        self.snapshot().ok()
    }
}

impl ObservationHandle for Option<ExecutionHandle> {
    fn snapshot_for_observation(&self) -> Option<gantry_runtime::ExecutionSnapshot> {
        self.as_ref().and_then(|handle| handle.snapshot().ok())
    }
}

fn observation_from_recovered(
    journal_id: &JournalId,
    handle: &impl ObservationHandle,
    recovered: &RecoveredDurableStateV1,
    owner: Option<DurableJournalOwnerState>,
    run_failure: Option<DurableRunFailure>,
) -> DurableExecutionObservation {
    let outcome = recovered.machine().outcome().cloned();
    let foreground = matches!(
        recovered.latest_cut(),
        DurableCommitCutV1::ForegroundCompletion | DurableCommitCutV1::TerminalCompletion
    )
    .then(|| outcome.clone())
    .flatten();
    let terminal = (recovered.latest_cut() == DurableCommitCutV1::TerminalCompletion)
        .then_some(outcome)
        .flatten();
    let state = if run_failure.is_some() {
        ExecutionObservationState::RunFailedNondurably
    } else if terminal.is_some() {
        ExecutionObservationState::Terminal
    } else {
        ExecutionObservationState::NotTerminal
    };
    let lifecycle = handle.snapshot_for_observation();
    DurableExecutionObservation {
        journal_id: journal_id.clone(),
        execution_id: recovered
            .execution_start()
            .map(|start| start.execution_id())
            .unwrap_or_else(|| recovered.machine().execution_id()),
        state,
        foreground,
        terminal,
        cancellation: recovered.cancellation_reason().cloned(),
        required_delivery_failures: lifecycle
            .map(|snapshot| snapshot.required_delivery_failures)
            .unwrap_or_else(|| Arc::from([])),
        owner,
        run_failure,
        latest_sequence: recovered.latest_sequence(),
        latest_evidence_id: recovered.latest_evidence_id(),
    }
}

fn lock_state(
    state: &Mutex<DurableOwnedExecutionState>,
) -> MutexGuard<'_, DurableOwnedExecutionState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_shutdown(state: &Mutex<DurableShutdownState>) -> MutexGuard<'_, DurableShutdownState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn index_owned_executions(
    lifecycle: &InterpreterLifecycle,
    owned_executions: &[Arc<DurableOwnedExecution>],
) -> Result<BTreeMap<ProtocolIdentity, Arc<DurableOwnedExecution>>, DurableShutdownError> {
    let mut owned = BTreeMap::new();
    for execution in owned_executions {
        let execution_id = execution.execution_id();
        if !lifecycle.owns_handle(&execution.handle) {
            return Err(DurableShutdownError::WrongLifecycle(execution_id));
        }
        if owned.insert(execution_id, Arc::clone(execution)).is_some() {
            return Err(DurableShutdownError::DuplicateOwnedExecution(execution_id));
        }
    }
    Ok(owned)
}

fn register_durable_waiter(
    waiters: &mut Vec<DurableRegisteredWaiter>,
    waiter_id: u64,
    waker: &Waker,
) {
    if let Some(waiter) = waiters
        .iter_mut()
        .find(|waiter| waiter.waiter_id == waiter_id)
    {
        waiter.waker = waker.clone();
    } else {
        waiters.push(DurableRegisteredWaiter {
            waiter_id,
            waker: waker.clone(),
        });
    }
}

fn map_event_commit_failure(error: DurableEventCommitError) -> DurableRunFailure {
    match error {
        DurableEventCommitError::Journal(error)
        | DurableEventCommitError::StreamTerminated(error) => {
            DurableRunFailure::Commit(DurableCommitError::Journal(error))
        }
        DurableEventCommitError::InvalidState
        | DurableEventCommitError::DuplicateOccurrence
        | DurableEventCommitError::Evidence(_)
        | DurableEventCommitError::InvalidReceipt => DurableRunFailure::Internal,
    }
}

fn prefix_is_empty(prefix: &JournalPrefixV1) -> bool {
    matches!(
        prefix,
        JournalPrefixV1::Full(prefix)
            if prefix.evidence.is_empty() && prefix.committed_through == 0
    )
}
