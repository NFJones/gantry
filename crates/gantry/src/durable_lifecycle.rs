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
    CancellationReasonCategory, DeliveryOutcome, ExecutionObservationState, IdentityKind,
    JournalOwnerStatus, SinkClass,
};
use gantry_host::contracts::{DurationMicros, FreshIdentityAllocator, IdentitySource};
use gantry_host::event::{
    EventDeliveryRequest, EventDeliveryRuntime, ProtectedPayload, SinkDeliveryPolicy, SinkId,
};
use gantry_host::journal::{
    JournalError, JournalId, JournalOwnershipToken, JournalPayloadKey, JournalPrefixV1,
    JournalStorage, ReadJournalPrefixV1, ReleaseJournalOwnerV1, ResolveJournalPayloadV1,
};
use gantry_observe::{SinkPlan, project_payloads};
#[cfg(all(feature = "concurrent", feature = "durable"))]
use gantry_runtime::{
    CONCURRENT_DURABLE_EVIDENCE_KIND_V4, CONCURRENT_DURABLE_EVIDENCE_KIND_V5,
    CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1, ConcurrentDurableRecoverySnapshotV1,
    DurableGraphTransaction, ExecutionCoordinator, RecoveredConcurrentDurableStateV1,
    recover_concurrent_authoritative_prefix,
};
use gantry_runtime::{
    CancellationReason, DurableCommitCoordinatorV1, DurableCommitCutV1, DurableCommitError,
    DurableDeliveryRecoveryV1, DurableEventBarrierV1, DurableEventCommitCoordinatorV1,
    DurableEventCommitError, DurableEventDispatchedV1, DurableEventOccurrenceV1,
    DurableEventPlanV1, DurableEventSettledV1, DurableEvidenceError, DurableExecutionStartV3,
    DurableOperationEvidenceV1, DurableTransitionSink, ExecutionFailureProjection, ExecutionHandle,
    ExecutionTransitionError, FinalShutdownEventSettlement, InterpreterLifecycle, LifecycleError,
    MachineOutcome, RecoveredDurableEventsV1, RecoveredDurableStateV1, RequiredDeliveryRecordV1,
    RequiredEventDeliveryFailureV1, ShutdownCompletionError, ShutdownReport,
    recover_authoritative_prefix_with_retained_program,
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
    /// A valid concurrent graph was recovered, but replacement task submission is not available.
    RunnableReplacementUnavailable(DurableConcurrentRecovery),
    /// Recovered state could not be reflected in the supplied lifecycle handle.
    Lifecycle(ExecutionTransitionError),
}

/// Bounded coordinates for a recognized concurrent graph awaiting replacement submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableConcurrentRecovery {
    /// Execution identity retained by sequence one and the graph checkpoint.
    pub execution_id: ProtocolIdentity,
    /// Latest authoritative logical sequence in the recovered graph prefix.
    pub latest_sequence: u64,
    /// Latest storage-assigned evidence identity in the recovered graph prefix.
    pub latest_evidence_id: ProtocolIdentity,
    /// Latest committed graph boundary.
    pub latest_cut: DurableCommitCutV1,
}

pub(crate) enum RecoveredDurablePrefix {
    Serial(Box<RecoveredDurableStateV1>),
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    Concurrent {
        execution_start: Box<DurableExecutionStartV3>,
        recovered: Box<RecoveredConcurrentDurableStateV1>,
    },
}

impl RecoveredDurablePrefix {
    pub(crate) fn execution_start(&self) -> Option<&DurableExecutionStartV3> {
        match self {
            Self::Serial(recovered) => recovered.execution_start(),
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            Self::Concurrent {
                execution_start, ..
            } => Some(execution_start),
        }
    }
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
    /// Read-only coordinator frontier, updated only after semantic commits.
    committed_budget: gantry_runtime::ExecutionBudget,
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
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    graph_frontier: Option<(ProtocolIdentity, u64, DurableCommitCutV1)>,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    graph_active: bool,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    graph_failure_pending: Option<DurableRunFailure>,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    graph_cancellation: Option<CancellationReason>,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    graph_cancellation_claimed: bool,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    graph_cancellation_committed: bool,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    graph_driver_wakers: Vec<Waker>,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    graph_owner_release_in_flight: bool,
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

#[derive(Clone)]
struct DurablePendingDelivery {
    occurrence_evidence_id: ProtocolIdentity,
    occurrence_sequence: u64,
    event: gantry_core::event::EventEnvelope,
    sink_id: SinkId,
    policy: SinkDeliveryPolicy,
    recovery: DurableDeliveryRecoveryV1,
}

pub(crate) enum DurableDriverPoll<T> {
    Completed(T),
    CancellationSettled,
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
pub(crate) enum DurableGraphDriverPoll<T> {
    Completed(T),
    CancellationSettled,
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
pub(crate) enum DurableGraphCancellationPoll {
    Continue,
    Claimed(CancellationReason),
    Waiting,
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
            committed_budget: recovered.machine().execution_budget(),
            state: Mutex::new(DurableOwnedExecutionState {
                recovered: Some(recovered),
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_frontier: None,
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_active: false,
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_failure_pending: None,
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_cancellation: None,
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_cancellation_claimed: false,
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_cancellation_committed: false,
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_driver_wakers: Vec::new(),
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_owner_release_in_flight: false,
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
        let recovered =
            recover_durable_prefix(&prefix).map_err(DurableOwnedExecutionOpenError::Format)?;
        let execution_id = recovered
            .execution_start()
            .map(|start| start.execution_id())
            .ok_or(DurableOwnedExecutionOpenError::NotFound)?;
        if execution_id != expected_execution_id || handle.execution_id() != execution_id {
            return Err(DurableOwnedExecutionOpenError::NotFound);
        }
        #[cfg(all(feature = "concurrent", feature = "durable"))]
        if let RecoveredDurablePrefix::Concurrent { recovered, .. } = recovered {
            return Err(
                DurableOwnedExecutionOpenError::RunnableReplacementUnavailable(
                    concurrent_recovery(&recovered),
                ),
            );
        }
        let RecoveredDurablePrefix::Serial(recovered) = recovered else {
            unreachable!("concurrent recovery is handled above")
        };
        let recovered = *recovered;
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
            committed_budget: recovered.machine().execution_budget(),
            state: Mutex::new(DurableOwnedExecutionState {
                recovered: Some(recovered),
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_frontier: None,
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_active: false,
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_failure_pending: None,
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_cancellation: None,
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_cancellation_claimed: false,
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_cancellation_committed: false,
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_driver_wakers: Vec::new(),
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                graph_owner_release_in_flight: false,
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
        let recovered = match recover_durable_prefix(&prefix) {
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

        let observation = match recovered {
            RecoveredDurablePrefix::Serial(recovered) => observation_from_recovered(
                &journal_id,
                &None::<ExecutionHandle>,
                &recovered,
                None,
                None,
            ),
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            RecoveredDurablePrefix::Concurrent {
                execution_start,
                recovered,
            } => observation_from_concurrent(&journal_id, &execution_start, &recovered),
        };
        DurableQueryExecutionResult::Snapshot(Box::new(observation))
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

    /// Copies retained state for committed-prefix conformance assertions.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn test_retained_projection(&self) -> Option<RecoveredDurableStateV1> {
        lock_state(&self.state).recovered.clone()
    }

    /// Reads the committed budget frontier for journal-prefix conformance checks.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn test_committed_budget(&self) -> gantry_runtime::ExecutionBudgetSnapshot {
        self.committed_budget.snapshot()
    }

    /// Freezes the current sink policy for a graph-cut event occurrence.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) fn graph_event_plan(&self) -> Result<DurableEventPlanV1, DurableRunFailure> {
        DurableEventPlanV1::from_sink_plan(&self.event_plan)
            .map_err(|_| DurableRunFailure::Internal)
    }

    /// Commits and publishes one privately staged concurrent graph successor.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) async fn commit_graph_transaction(
        &self,
        coordinator: &ExecutionCoordinator,
        transaction: DurableGraphTransaction<'_>,
        predecessor: (ProtocolIdentity, u64),
        cut: DurableCommitCutV1,
        affected_task: ProtocolIdentity,
    ) -> Result<(ProtocolIdentity, u64), DurableRunFailure> {
        let root_task = coordinator.snapshot().state().root_task_id();
        let sink = DurableTransitionSink::new(
            Arc::clone(&self.storage),
            self.journal_id.clone(),
            self.ownership_token.clone(),
        );
        let mut commits = DurableCommitCoordinatorV1::new(
            &sink,
            self.execution_id(),
            root_task,
            Some(predecessor),
        )
        .map_err(DurableRunFailure::Commit)?;
        if cut == DurableCommitCutV1::Cancellation {
            let reason = lock_state(&self.state)
                .graph_cancellation
                .clone()
                .ok_or(DurableRunFailure::Internal)?;
            commits
                .set_graph_cancellation(reason)
                .map_err(DurableRunFailure::Commit)?;
        }
        transaction
            .commit(&mut commits, cut, affected_task)
            .await
            .map_err(DurableRunFailure::Commit)?;
        let frontier = commits.frontier().ok_or(DurableRunFailure::Internal)?;
        self.publish_graph_progress(coordinator, frontier, cut)?;
        Ok(frontier)
    }

    /// Reflects a committed graph cut into lifecycle observation before gates open.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    fn publish_graph_progress(
        &self,
        coordinator: &ExecutionCoordinator,
        frontier: (ProtocolIdentity, u64),
        cut: DurableCommitCutV1,
    ) -> Result<(), DurableRunFailure> {
        let snapshot = coordinator.snapshot();
        let foreground = snapshot.state().foreground_outcome().cloned();
        let committed_cancellation = if cut == DurableCommitCutV1::Cancellation {
            Some(
                lock_state(&self.state)
                    .graph_cancellation
                    .clone()
                    .ok_or(DurableRunFailure::Internal)?,
            )
        } else {
            None
        };
        if let Some(reason) = &committed_cancellation {
            self.handle
                .publish_committed_cancellation(reason.clone())
                .map_err(DurableRunFailure::Lifecycle)?;
        } else if cut == DurableCommitCutV1::ForegroundCompletion {
            self.handle
                .publish_committed_foreground(
                    foreground.clone().ok_or(DurableRunFailure::Internal)?,
                )
                .map_err(DurableRunFailure::Lifecycle)?;
        } else if cut == DurableCommitCutV1::TerminalCompletion {
            self.handle
                .publish_committed_terminal(foreground.clone().ok_or(DurableRunFailure::Internal)?)
                .map_err(DurableRunFailure::Lifecycle)?;
        }
        self.committed_budget
            .publish_committed_snapshot(
                snapshot
                    .execution_budget()
                    .ok_or(DurableRunFailure::Internal)?,
            )
            .map_err(|error| {
                DurableRunFailure::Commit(DurableCommitError::Evidence(
                    DurableEvidenceError::Checkpoint(error),
                ))
            })?;
        let lifecycle = self
            .handle
            .snapshot()
            .map_err(DurableRunFailure::Lifecycle)?;
        let mut state = lock_state(&self.state);
        state.graph_frontier = Some((frontier.0, frontier.1, cut));
        if committed_cancellation.is_some() {
            state.graph_cancellation_committed = true;
            state.generation = state.generation.wrapping_add(1);
        }
        let observation_state = if lifecycle.terminal.is_some() {
            ExecutionObservationState::Terminal
        } else {
            ExecutionObservationState::NotTerminal
        };
        state.last_observation = DurableExecutionObservation {
            journal_id: self.journal_id.clone(),
            execution_id: self.execution_id(),
            state: observation_state,
            foreground: lifecycle.foreground,
            terminal: lifecycle.terminal,
            cancellation: lifecycle.cancellation,
            required_delivery_failures: lifecycle.required_delivery_failures,
            owner: Some(state.owner.clone()),
            run_failure: None,
            latest_sequence: frontier.1,
            latest_evidence_id: frontier.0,
        };
        let observation_waiters = state
            .observation_waiters
            .iter()
            .map(|waiter| waiter.waker.clone())
            .collect::<Vec<_>>();
        let operation_waiters = if committed_cancellation.is_some() {
            std::mem::take(&mut state.operation_waiters)
        } else {
            Vec::new()
        };
        let graph_waiters = if committed_cancellation.is_some() {
            std::mem::take(&mut state.graph_driver_wakers)
        } else {
            Vec::new()
        };
        drop(state);
        for waiter in operation_waiters
            .into_iter()
            .chain(graph_waiters)
            .chain(observation_waiters)
        {
            waiter.wake();
        }
        Ok(())
    }

    /// Ends graph-owned execution after the committed terminal cut is visible.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) async fn finish_graph_driver(&self) -> DurableExecutionObservation {
        let owner = self.release_graph_owner_once().await;
        let mut state = lock_state(&self.state);
        state.owner = owner;
        state.operation_in_flight = false;
        state.driver_active = false;
        state.graph_active = false;
        state.graph_cancellation_claimed = false;
        state.driver_cancellation = None;
        state.driver_waker = None;
        state.generation = state.generation.wrapping_add(1);
        state.last_observation.owner = Some(state.owner.clone());
        if let Some(effective_reason) = state.last_observation.cancellation.clone() {
            state.completed_cancellation = Some(DurableCancelExecutionResult::Accepted {
                effective_reason,
                terminal: Box::new(state.last_observation.clone()),
            });
        }
        let observation = state.last_observation.clone();
        let operation_waiters = std::mem::take(&mut state.operation_waiters);
        let graph_waiters = std::mem::take(&mut state.graph_driver_wakers);
        let observation_waiters = state
            .observation_waiters
            .iter()
            .map(|waiter| waiter.waker.clone())
            .collect::<Vec<_>>();
        drop(state);
        for waiter in operation_waiters
            .into_iter()
            .chain(graph_waiters)
            .chain(observation_waiters)
        {
            waiter.wake();
        }
        observation
    }

    /// Releases graph ownership before publishing one nondurable run failure.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) async fn finish_failed_graph_driver(
        &self,
        failure: DurableRunFailure,
    ) -> DurableExecutionObservation {
        let failure = {
            let mut state = lock_state(&self.state);
            state.graph_failure_pending.get_or_insert(failure).clone()
        };
        let owner = self.release_graph_owner_once().await;
        let _ = self.handle.publish_run_failed_nondurably();
        let mut state = lock_state(&self.state);
        state.owner = owner;
        state.run_failure = Some(failure.clone());
        state.graph_failure_pending = None;
        state.operation_in_flight = false;
        state.driver_active = false;
        state.graph_active = false;
        state.graph_cancellation_claimed = false;
        state.driver_cancellation = None;
        state.driver_waker = None;
        state.generation = state.generation.wrapping_add(1);
        state.last_observation.state = ExecutionObservationState::RunFailedNondurably;
        state.last_observation.owner = Some(state.owner.clone());
        state.last_observation.run_failure = Some(failure);
        let observation = state.last_observation.clone();
        let operation_waiters = std::mem::take(&mut state.operation_waiters);
        let graph_waiters = std::mem::take(&mut state.graph_driver_wakers);
        let observation_waiters = state
            .observation_waiters
            .iter()
            .map(|waiter| waiter.waker.clone())
            .collect::<Vec<_>>();
        drop(state);
        for waiter in operation_waiters
            .into_iter()
            .chain(graph_waiters)
            .chain(observation_waiters)
        {
            waiter.wake();
        }
        observation
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn release_graph_owner_once(&self) -> DurableJournalOwnerState {
        loop {
            let generation = {
                let mut state = lock_state(&self.state);
                if state.owner != DurableJournalOwnerState::Held {
                    return state.owner.clone();
                }
                if state.graph_owner_release_in_flight {
                    Some(state.generation)
                } else {
                    state.graph_owner_release_in_flight = true;
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
            state.graph_owner_release_in_flight = false;
            state.last_observation.owner = Some(owner.clone());
            state.generation = state.generation.wrapping_add(1);
            let operation_waiters = std::mem::take(&mut state.operation_waiters);
            let graph_waiters = std::mem::take(&mut state.graph_driver_wakers);
            let observation_waiters = state
                .observation_waiters
                .iter()
                .map(|waiter| waiter.waker.clone())
                .collect::<Vec<_>>();
            drop(state);
            for waiter in operation_waiters
                .into_iter()
                .chain(graph_waiters)
                .chain(observation_waiters)
            {
                waiter.wake();
            }
            return owner;
        }
    }

    pub(crate) fn begin_driver(&self) -> Option<RecoveredDurableStateV1> {
        let mut state = lock_state(&self.state);
        if state.operation_in_flight || state.run_failure.is_some() {
            return None;
        }
        state.operation_in_flight = true;
        state.driver_active = true;
        let recovered = state.recovered.as_ref()?;
        // Clone intentionally isolates the driver's speculative budget from
        // the committed budget retained by coordinator observers.
        Some(recovered.clone())
    }

    pub(crate) fn take_driver_cancellation(&self) -> Option<CancellationReason> {
        let mut state = lock_state(&self.state);
        state.driver_waker = None;
        state.driver_cancellation.take()
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) fn activate_graph_driver(&self) {
        let waiters = {
            let mut state = lock_state(&self.state);
            state.graph_active = true;
            if state.graph_cancellation.is_none() {
                state.graph_cancellation = state.driver_cancellation.take();
            }
            std::mem::take(&mut state.graph_driver_wakers)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) fn poll_graph_cancellation(
        &self,
        context: &Context<'_>,
    ) -> DurableGraphCancellationPoll {
        let mut state = lock_state(&self.state);
        if let Some(reason) = state.graph_cancellation.clone()
            && !state.graph_cancellation_committed
        {
            if !state.graph_cancellation_claimed {
                state.graph_cancellation_claimed = true;
                state
                    .graph_driver_wakers
                    .retain(|waiter| !waiter.will_wake(context.waker()));
                return DurableGraphCancellationPoll::Claimed(reason);
            }
            register_graph_driver_waker(&mut state.graph_driver_wakers, context.waker());
            return DurableGraphCancellationPoll::Waiting;
        }
        register_graph_driver_waker(&mut state.graph_driver_wakers, context.waker());
        DurableGraphCancellationPoll::Continue
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) fn clear_graph_driver_waker(&self, waker: &Waker) {
        lock_state(&self.state)
            .graph_driver_wakers
            .retain(|registered| !registered.will_wake(waker));
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) fn request_graph_cancellation(
        &self,
        requested_reason: CancellationReason,
    ) -> CancellationReason {
        let (reason, waiters) = {
            let mut state = lock_state(&self.state);
            let reason = state
                .graph_cancellation
                .get_or_insert(requested_reason)
                .clone();
            (reason, std::mem::take(&mut state.graph_driver_wakers))
        };
        for waiter in waiters {
            waiter.wake();
        }
        reason
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) fn complete_graph_cancellation_without_cut(&self) {
        let waiters = {
            let mut state = lock_state(&self.state);
            state.graph_cancellation_committed = true;
            std::mem::take(&mut state.graph_driver_wakers)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    /// Settles required graph-event obligations through one occurrence frontier.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) async fn drain_graph_required_event_obligations_through(
        &self,
        program: Arc<gantry_ir::MachineProgram>,
        coordinator: &ExecutionCoordinator,
        frontier: u64,
        allocator: &FreshIdentityAllocator,
        identity_source: &dyn IdentitySource,
        runtime: &dyn EventDeliveryRuntime,
    ) -> Result<((ProtocolIdentity, u64), DurableEventBarrierV1), DurableRunFailure> {
        let mut recovered = self
            .recover_graph_authoritative(Arc::clone(&program))
            .await?;
        while let Some(delivery) = next_pending_delivery(recovered.events(), Some(frontier), true)?
        {
            self.drive_pending_graph_delivery(
                &mut recovered,
                Arc::clone(&program),
                coordinator,
                delivery,
                allocator,
                identity_source,
                runtime,
            )
            .await?;
        }
        let barrier = recovered.events().required_barrier_through(frontier);
        if matches!(barrier, DurableEventBarrierV1::Pending { .. }) {
            return Err(DurableRunFailure::Internal);
        }
        Ok((
            (recovered.latest_evidence_id(), recovered.latest_sequence()),
            barrier,
        ))
    }

    /// Settles every finite graph-event obligation and publishes their journal tip.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) async fn drain_graph_event_obligations(
        &self,
        program: Arc<gantry_ir::MachineProgram>,
        coordinator: &ExecutionCoordinator,
        allocator: &FreshIdentityAllocator,
        identity_source: &dyn IdentitySource,
        runtime: &dyn EventDeliveryRuntime,
    ) -> Result<(ProtocolIdentity, u64), DurableRunFailure> {
        let mut recovered = self
            .recover_graph_authoritative(Arc::clone(&program))
            .await?;
        while let Some(delivery) = next_pending_delivery(recovered.events(), None, false)? {
            self.drive_pending_graph_delivery(
                &mut recovered,
                Arc::clone(&program),
                coordinator,
                delivery,
                allocator,
                identity_source,
                runtime,
            )
            .await?;
        }
        self.project_required_delivery_failures_from_events(recovered.events())?;
        Ok((recovered.latest_evidence_id(), recovered.latest_sequence()))
    }

    /// Records one exhausted required graph-event obligation after cancellation is durable.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) fn record_graph_required_delivery_failure(
        &self,
        failure: RequiredEventDeliveryFailureV1,
    ) -> Result<(), DurableRunFailure> {
        self.handle
            .record_required_delivery_failure(failure)
            .map(|_| ())
            .map_err(DurableRunFailure::Lifecycle)
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn drive_pending_graph_delivery(
        &self,
        recovered: &mut RecoveredConcurrentDurableStateV1,
        program: Arc<gantry_ir::MachineProgram>,
        coordinator: &ExecutionCoordinator,
        delivery: DurablePendingDelivery,
        allocator: &FreshIdentityAllocator,
        identity_source: &dyn IdentitySource,
        runtime: &dyn EventDeliveryRuntime,
    ) -> Result<(), DurableRunFailure> {
        if let DurableDeliveryRecoveryV1::RetryDelay { delay_us, .. } = delivery.recovery {
            runtime
                .sleep(delay_us)
                .await
                .map_err(|_| DurableRunFailure::Internal)?;
        }

        let payloads = self.resolve_event_payloads(&delivery.event).await?;
        let projected = project_payloads(&delivery.event, &payloads, &delivery.policy)
            .map_err(|_| DurableRunFailure::Internal)?;
        let retry_number = match delivery.recovery {
            DurableDeliveryRecoveryV1::Pending { retry_number }
            | DurableDeliveryRecoveryV1::Indeterminate { retry_number, .. }
            | DurableDeliveryRecoveryV1::RetryDelay { retry_number, .. } => retry_number,
            DurableDeliveryRecoveryV1::Success { .. }
            | DurableDeliveryRecoveryV1::Terminal { .. } => {
                return Err(DurableRunFailure::Internal);
            }
        };
        if retry_number > delivery.policy.retry.retry_limit {
            return Err(DurableRunFailure::Internal);
        }
        let attempt_id = allocator
            .allocate(identity_source, IdentityKind::DeliveryAttempt)
            .map_err(|_| DurableRunFailure::Internal)?;
        let dispatched = DurableEventDispatchedV1::new(
            delivery.event.event_id(),
            delivery.sink_id.clone(),
            attempt_id,
            retry_number,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        let sink = DurableTransitionSink::new(
            Arc::clone(&self.storage),
            self.journal_id.clone(),
            self.ownership_token.clone(),
        );
        let mut commits = DurableEventCommitCoordinatorV1::from_recovered(
            &sink,
            (recovered.latest_evidence_id(), recovered.latest_sequence()),
            recovered.events(),
        )
        .map_err(map_event_commit_failure)?;
        let dispatch = commits
            .commit_dispatched(delivery.occurrence_evidence_id, &dispatched)
            .await
            .map_err(map_event_commit_failure)?;
        *recovered = self
            .recover_graph_authoritative(Arc::clone(&program))
            .await?;
        self.publish_graph_event_progress(coordinator, recovered)?;

        let outcome = match self.event_plan.registration(&delivery.sink_id) {
            Some(registration) => runtime
                .deliver_with_timeout(
                    registration.sink(),
                    EventDeliveryRequest {
                        event: delivery.event.clone(),
                        protected_payloads: projected,
                        attempt_id,
                        retry_number,
                    },
                    delivery.policy.attempt_timeout_us,
                )
                .await
                .unwrap_or(DeliveryOutcome::Terminal),
            None => DeliveryOutcome::Terminal,
        };
        let remaining_retries = delivery
            .policy
            .retry
            .retry_limit
            .saturating_sub(retry_number);
        let (outcome, selected_delay_us) = if outcome == DeliveryOutcome::Retriable
            && remaining_retries > 0
        {
            let next_retry = retry_number
                .checked_add(1)
                .ok_or(DurableRunFailure::Internal)?;
            let delay =
                gantry_observe::retry::select_delay(&delivery.policy.retry, next_retry, runtime)
                    .map_err(|_| DurableRunFailure::Internal)?;
            (DeliveryOutcome::Retriable, Some(delay))
        } else if outcome == DeliveryOutcome::Success {
            (DeliveryOutcome::Success, None)
        } else {
            (DeliveryOutcome::Terminal, None)
        };
        let settled = DurableEventSettledV1::new(
            delivery.event.event_id(),
            delivery.sink_id,
            attempt_id,
            retry_number,
            outcome,
            remaining_retries,
            selected_delay_us,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        let mut commits = DurableEventCommitCoordinatorV1::from_recovered(
            &sink,
            (recovered.latest_evidence_id(), recovered.latest_sequence()),
            recovered.events(),
        )
        .map_err(map_event_commit_failure)?;
        commits
            .commit_settled(
                delivery.occurrence_evidence_id,
                dispatch.evidence_id,
                &settled,
            )
            .await
            .map_err(map_event_commit_failure)?;
        *recovered = self.recover_graph_authoritative(program).await?;
        self.publish_graph_event_progress(coordinator, recovered)
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn recover_graph_authoritative(
        &self,
        program: Arc<gantry_ir::MachineProgram>,
    ) -> Result<RecoveredConcurrentDurableStateV1, DurableRunFailure> {
        let prefix = self
            .storage
            .read_prefix(ReadJournalPrefixV1 {
                journal_id: self.journal_id.clone(),
            })
            .await
            .map_err(|error| DurableRunFailure::Commit(DurableCommitError::Journal(error)))?;
        recover_concurrent_authoritative_prefix(program, &prefix)
            .map_err(|error| DurableRunFailure::Commit(DurableCommitError::Evidence(error)))
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    fn publish_graph_event_progress(
        &self,
        coordinator: &ExecutionCoordinator,
        recovered: &RecoveredConcurrentDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        coordinator
            .publish_committed_events(recovered.events().clone())
            .map_err(|_| DurableRunFailure::Internal)?;
        let lifecycle = self
            .handle
            .snapshot()
            .map_err(DurableRunFailure::Lifecycle)?;
        let mut state = lock_state(&self.state);
        state.graph_frontier = Some((
            recovered.latest_evidence_id(),
            recovered.latest_sequence(),
            recovered.latest_cut(),
        ));
        state.last_observation.foreground = lifecycle.foreground;
        state.last_observation.terminal = lifecycle.terminal;
        state.last_observation.cancellation = lifecycle.cancellation;
        state.last_observation.required_delivery_failures = lifecycle.required_delivery_failures;
        state.last_observation.latest_sequence = recovered.latest_sequence();
        state.last_observation.latest_evidence_id = recovered.latest_evidence_id();
        let waiters = state
            .observation_waiters
            .iter()
            .map(|waiter| waiter.waker.clone())
            .collect::<Vec<_>>();
        drop(state);
        for waiter in waiters {
            waiter.wake();
        }
        Ok(())
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
            self.publish_committed_budget(recovered)?;
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
            .map_err(|error| DurableRunFailure::Commit(DurableCommitError::Evidence(error)))?;
        self.publish_committed_budget(recovered)
    }

    /// Installs the complete authoritative projection after a serialized commit.
    fn publish_committed_budget(
        &self,
        recovered: &RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        let projection = recovered.clone();
        let mut state = lock_state(&self.state);
        self.committed_budget
            .publish_committed_snapshot(recovered.machine().budget_checkpoint())
            .map_err(|error| {
                DurableRunFailure::Commit(DurableCommitError::Evidence(
                    DurableEvidenceError::Checkpoint(error),
                ))
            })?;
        state.recovered = Some(projection);
        Ok(())
    }

    pub(crate) async fn commit_driver_event(
        &self,
        recovered: &mut RecoveredDurableStateV1,
        event: gantry_core::event::EventEnvelope,
        protected_payloads: &[ProtectedPayload],
    ) -> Result<u64, DurableRunFailure> {
        let cause = recovered.latest_evidence_id();
        let mut active_plan = self.event_plan.clone();
        for prior in recovered.events().events().values() {
            for (sink_id, delivery) in prior.deliveries() {
                let Some(obligation) = prior.occurrence().plan().obligation(sink_id) else {
                    return Err(DurableRunFailure::Internal);
                };
                if obligation.policy().class == SinkClass::Required
                    && matches!(delivery, DurableDeliveryRecoveryV1::Terminal { .. })
                {
                    active_plan = active_plan.without_sink(sink_id);
                }
            }
        }
        let plan = DurableEventPlanV1::from_sink_plan(&active_plan)
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
        self.publish_committed_budget(recovered)?;
        recovered
            .events()
            .event_for_cause(cause)
            .map(|event| event.occurrence_sequence())
            .ok_or(DurableRunFailure::Internal)
    }
}

impl DurableOwnedExecution {
    /// Drains required event obligations through an inclusive occurrence frontier.
    ///
    /// The supplied recovery projection remains owned by the active driver. This
    /// method neither publishes owner state nor changes driver admission state.
    /// Required exhaustion is returned only after its terminal settlement is
    /// authoritative so the driver can durably commit cancellation before
    /// exposing that cancellation through the lifecycle handle.
    pub async fn drain_driver_required_event_obligations_through(
        &self,
        recovered: &mut RecoveredDurableStateV1,
        frontier: u64,
        allocator: &FreshIdentityAllocator,
        identity_source: &dyn IdentitySource,
        runtime: &dyn EventDeliveryRuntime,
    ) -> Result<DurableEventBarrierV1, DurableRunFailure> {
        while let Some(delivery) = next_pending_delivery(recovered.events(), Some(frontier), true)?
        {
            self.drive_pending_delivery(recovered, delivery, allocator, identity_source, runtime)
                .await?;
        }
        match recovered.events().required_barrier_through(frontier) {
            DurableEventBarrierV1::Delivered | DurableEventBarrierV1::RequiredExhausted(_) => {
                Ok(recovered.events().required_barrier_through(frontier))
            }
            DurableEventBarrierV1::Pending { .. } => Err(DurableRunFailure::Internal),
        }
    }

    pub(crate) fn project_driver_required_delivery_failure(
        &self,
        recovered: &mut RecoveredDurableStateV1,
        failure: RequiredEventDeliveryFailureV1,
    ) -> Result<(), DurableRunFailure> {
        let record = self
            .handle
            .record_required_delivery_failure(failure)
            .map_err(DurableRunFailure::Lifecycle)?;
        if matches!(record, RequiredDeliveryRecordV1::PostTerminal(_)) {
            return Ok(());
        }
        let projection = match recovered.latest_cut() {
            DurableCommitCutV1::TaskSettlement => ExecutionFailureProjection::AfterTaskSettlement,
            DurableCommitCutV1::ForegroundCompletion => {
                ExecutionFailureProjection::AfterForegroundCompletion
            }
            _ => ExecutionFailureProjection::Full,
        };
        let _ = recovered.machine_mut().fail_execution(
            gantry_core::portable::RuntimeErrorCategory::RequiredEventDeliveryFailure,
            projection,
        );
        Ok(())
    }

    pub(crate) fn reconcile_driver_required_delivery_failure(
        &self,
        recovered: &mut RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        if recovered.latest_cut() == DurableCommitCutV1::TerminalCompletion {
            return Ok(());
        }
        if let DurableEventBarrierV1::RequiredExhausted(failure) =
            recovered.events().required_barrier_through(u64::MAX)
        {
            self.project_driver_required_delivery_failure(recovered, failure)?;
        }
        Ok(())
    }

    /// Atomically finishes an active driver after every finite obligation settles.
    ///
    /// Terminal ownership is released before terminal lifecycle state is
    /// published. The driver's recovered state, owner result, and durable
    /// observation are then installed together and owner waiters are woken once.
    pub async fn finish_driver_terminal(
        &self,
        mut recovered: RecoveredDurableStateV1,
        allocator: &FreshIdentityAllocator,
        identity_source: &dyn IdentitySource,
        runtime: &dyn EventDeliveryRuntime,
    ) -> Result<DurableExecutionObservation, DurableRunFailure> {
        if recovered.latest_cut() != DurableCommitCutV1::TerminalCompletion {
            self.fail_driver(recovered, DurableRunFailure::Internal);
            return Err(DurableRunFailure::Internal);
        }
        if let Err(failure) = self
            .drive_all_event_obligations(&mut recovered, allocator, identity_source, runtime)
            .await
        {
            self.fail_driver(recovered, failure.clone());
            return Err(failure);
        }

        let outcome = recovered
            .machine()
            .outcome()
            .cloned()
            .ok_or(DurableRunFailure::Internal);
        let lifecycle = self.handle.snapshot().map_err(DurableRunFailure::Lifecycle);
        let outcome = match outcome.and_then(|outcome| {
            lifecycle.and_then(|snapshot| {
                if snapshot.foreground.is_some() && snapshot.terminal.is_none() {
                    Ok(outcome)
                } else {
                    Err(DurableRunFailure::Internal)
                }
            })
        }) {
            Ok(outcome) => outcome,
            Err(failure) => {
                self.fail_driver(recovered, failure.clone());
                return Err(failure);
            }
        };

        let owner = self.release_owner().await;
        if let Err(failure) = self
            .handle
            .publish_committed_terminal(outcome)
            .map_err(DurableRunFailure::Lifecycle)
        {
            self.fail_driver_with_owner(recovered, owner, failure.clone());
            return Err(failure);
        }
        if let Err(failure) = self.project_required_delivery_failures(&recovered) {
            self.fail_driver_with_owner(recovered, owner, failure.clone());
            return Err(failure);
        }

        Ok(self.complete_driver(recovered, owner))
    }

    /// Serially settles every recovered finite event obligation.
    ///
    /// Current adapters are selected by stable sink identity, while projection,
    /// timeout, retry, and class semantics come only from each occurrence's
    /// frozen policy. A terminal execution releases its owner only after all
    /// required and best-effort settlements are authoritative.
    pub(crate) async fn drain_event_obligations(
        &self,
        allocator: &FreshIdentityAllocator,
        identity_source: &dyn IdentitySource,
        runtime: &dyn EventDeliveryRuntime,
    ) -> Result<DurableExecutionObservation, DurableRunFailure> {
        loop {
            let (recovered, generation) = {
                let mut state = lock_state(&self.state);
                if let Some(failure) = &state.run_failure {
                    return Err(failure.clone());
                }
                if state.owner != DurableJournalOwnerState::Held {
                    return Ok(state.last_observation.clone());
                }
                if state.operation_in_flight {
                    (None, state.generation)
                } else {
                    state.operation_in_flight = true;
                    (state.recovered.take(), state.generation)
                }
            };
            let Some(mut recovered) = recovered else {
                self.wait_for_generation(generation).await;
                continue;
            };

            let result = self
                .drive_terminal_resume_event_obligations(
                    &mut recovered,
                    allocator,
                    identity_source,
                    runtime,
                )
                .await;
            let mut state = lock_state(&self.state);
            state.operation_in_flight = false;
            state.generation = state.generation.wrapping_add(1);
            let result = match result {
                Ok(owner) => {
                    state.owner = owner;
                    state.last_observation = observation_from_recovered(
                        &self.journal_id,
                        &self.handle,
                        &recovered,
                        Some(state.owner.clone()),
                        None,
                    );
                    Ok(state.last_observation.clone())
                }
                Err(failure) => {
                    let _ = self.handle.publish_run_failed_nondurably();
                    state.run_failure = Some(failure.clone());
                    state.last_observation = observation_from_recovered(
                        &self.journal_id,
                        &self.handle,
                        &recovered,
                        Some(state.owner.clone()),
                        Some(failure.clone()),
                    );
                    Err(failure)
                }
            };
            state.recovered = Some(recovered);
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

    async fn drive_terminal_resume_event_obligations(
        &self,
        recovered: &mut RecoveredDurableStateV1,
        allocator: &FreshIdentityAllocator,
        identity_source: &dyn IdentitySource,
        runtime: &dyn EventDeliveryRuntime,
    ) -> Result<DurableJournalOwnerState, DurableRunFailure> {
        self.drive_all_event_obligations(recovered, allocator, identity_source, runtime)
            .await?;
        self.project_required_delivery_failures(recovered)?;

        if recovered.latest_cut() == DurableCommitCutV1::TerminalCompletion {
            Ok(self.release_owner().await)
        } else {
            Ok(DurableJournalOwnerState::Held)
        }
    }

    async fn drive_all_event_obligations(
        &self,
        recovered: &mut RecoveredDurableStateV1,
        allocator: &FreshIdentityAllocator,
        identity_source: &dyn IdentitySource,
        runtime: &dyn EventDeliveryRuntime,
    ) -> Result<(), DurableRunFailure> {
        while let Some(delivery) = next_pending_delivery(recovered.events(), None, false)? {
            self.drive_pending_delivery(recovered, delivery, allocator, identity_source, runtime)
                .await?;
        }
        Ok(())
    }

    async fn drive_pending_delivery(
        &self,
        recovered: &mut RecoveredDurableStateV1,
        delivery: DurablePendingDelivery,
        allocator: &FreshIdentityAllocator,
        identity_source: &dyn IdentitySource,
        runtime: &dyn EventDeliveryRuntime,
    ) -> Result<(), DurableRunFailure> {
        if let DurableDeliveryRecoveryV1::RetryDelay { delay_us, .. } = delivery.recovery {
            runtime
                .sleep(delay_us)
                .await
                .map_err(|_| DurableRunFailure::Internal)?;
        }

        let payloads = self.resolve_event_payloads(&delivery.event).await?;
        let projected = project_payloads(&delivery.event, &payloads, &delivery.policy)
            .map_err(|_| DurableRunFailure::Internal)?;
        let retry_number = match delivery.recovery {
            DurableDeliveryRecoveryV1::Pending { retry_number }
            | DurableDeliveryRecoveryV1::Indeterminate { retry_number, .. }
            | DurableDeliveryRecoveryV1::RetryDelay { retry_number, .. } => retry_number,
            DurableDeliveryRecoveryV1::Success { .. }
            | DurableDeliveryRecoveryV1::Terminal { .. } => {
                return Err(DurableRunFailure::Internal);
            }
        };
        if retry_number > delivery.policy.retry.retry_limit {
            return Err(DurableRunFailure::Internal);
        }
        let attempt_id = allocator
            .allocate(identity_source, IdentityKind::DeliveryAttempt)
            .map_err(|_| DurableRunFailure::Internal)?;
        let dispatched = DurableEventDispatchedV1::new(
            delivery.event.event_id(),
            delivery.sink_id.clone(),
            attempt_id,
            retry_number,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        let dispatch_commit = self
            .commit_event_dispatched(recovered, delivery.occurrence_evidence_id, &dispatched)
            .await?;

        let outcome = match self.event_plan.registration(&delivery.sink_id) {
            Some(registration) => runtime
                .deliver_with_timeout(
                    registration.sink(),
                    EventDeliveryRequest {
                        event: delivery.event.clone(),
                        protected_payloads: projected,
                        attempt_id,
                        retry_number,
                    },
                    delivery.policy.attempt_timeout_us,
                )
                .await
                .unwrap_or(DeliveryOutcome::Terminal),
            None => DeliveryOutcome::Terminal,
        };
        let remaining_retries = delivery
            .policy
            .retry
            .retry_limit
            .saturating_sub(retry_number);
        let (outcome, selected_delay_us) = if outcome == DeliveryOutcome::Retriable
            && remaining_retries > 0
        {
            let next_retry = retry_number
                .checked_add(1)
                .ok_or(DurableRunFailure::Internal)?;
            let delay =
                gantry_observe::retry::select_delay(&delivery.policy.retry, next_retry, runtime)
                    .map_err(|_| DurableRunFailure::Internal)?;
            (DeliveryOutcome::Retriable, Some(delay))
        } else if outcome == DeliveryOutcome::Success {
            (DeliveryOutcome::Success, None)
        } else {
            (DeliveryOutcome::Terminal, None)
        };
        let settled = DurableEventSettledV1::new(
            delivery.event.event_id(),
            delivery.sink_id,
            attempt_id,
            retry_number,
            outcome,
            remaining_retries,
            selected_delay_us,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        self.commit_event_settled(
            recovered,
            delivery.occurrence_evidence_id,
            dispatch_commit,
            &settled,
        )
        .await?;
        Ok(())
    }

    async fn commit_event_dispatched(
        &self,
        recovered: &mut RecoveredDurableStateV1,
        occurrence_evidence_id: ProtocolIdentity,
        dispatched: &DurableEventDispatchedV1,
    ) -> Result<ProtocolIdentity, DurableRunFailure> {
        let sink = DurableTransitionSink::new(
            Arc::clone(&self.storage),
            self.journal_id.clone(),
            self.ownership_token.clone(),
        );
        let mut commits = DurableEventCommitCoordinatorV1::from_recovered(
            &sink,
            (recovered.latest_evidence_id(), recovered.latest_sequence()),
            recovered.events(),
        )
        .map_err(map_event_commit_failure)?;
        let commit = commits
            .commit_dispatched(occurrence_evidence_id, dispatched)
            .await
            .map_err(map_event_commit_failure)?;
        self.refresh_authoritative(recovered).await?;
        Ok(commit.evidence_id)
    }

    async fn commit_event_settled(
        &self,
        recovered: &mut RecoveredDurableStateV1,
        occurrence_evidence_id: ProtocolIdentity,
        dispatch_evidence_id: ProtocolIdentity,
        settled: &DurableEventSettledV1,
    ) -> Result<(), DurableRunFailure> {
        let sink = DurableTransitionSink::new(
            Arc::clone(&self.storage),
            self.journal_id.clone(),
            self.ownership_token.clone(),
        );
        let mut commits = DurableEventCommitCoordinatorV1::from_recovered(
            &sink,
            (recovered.latest_evidence_id(), recovered.latest_sequence()),
            recovered.events(),
        )
        .map_err(map_event_commit_failure)?;
        commits
            .commit_settled(occurrence_evidence_id, dispatch_evidence_id, settled)
            .await
            .map_err(map_event_commit_failure)?;
        self.refresh_authoritative(recovered).await
    }

    async fn refresh_authoritative(
        &self,
        recovered: &mut RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
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
        self.publish_committed_budget(recovered)
    }

    async fn resolve_event_payloads(
        &self,
        event: &gantry_core::event::EventEnvelope,
    ) -> Result<Vec<ProtectedPayload>, DurableRunFailure> {
        let mut payloads = Vec::with_capacity(event.protected_references().len());
        for reference in event.protected_references() {
            let key =
                JournalPayloadKey::new(reference.key()).map_err(|_| DurableRunFailure::Internal)?;
            let payload = self
                .storage
                .resolve_payload(ResolveJournalPayloadV1 {
                    journal_id: self.journal_id.clone(),
                    key,
                })
                .await
                .map_err(|error| DurableRunFailure::Commit(DurableCommitError::Journal(error)))?;
            if payload.class != reference.class() {
                return Err(DurableRunFailure::Internal);
            }
            payloads.push(ProtectedPayload {
                reference: reference.clone(),
                bytes: payload.bytes,
            });
        }
        Ok(payloads)
    }

    fn project_required_delivery_failures(
        &self,
        recovered: &RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        self.project_required_delivery_failures_from_events(recovered.events())
    }

    fn project_required_delivery_failures_from_events(
        &self,
        events: &RecoveredDurableEventsV1,
    ) -> Result<(), DurableRunFailure> {
        for failure in required_delivery_failures_from_events(events)
            .iter()
            .cloned()
        {
            self.handle
                .record_required_delivery_failure(failure)
                .map_err(DurableRunFailure::Lifecycle)?;
        }
        Ok(())
    }
}

fn required_delivery_failures_from_events(
    events: &RecoveredDurableEventsV1,
) -> Arc<[RequiredEventDeliveryFailureV1]> {
    let mut failures = events
        .events()
        .values()
        .flat_map(|event| {
            event
                .deliveries()
                .iter()
                .filter_map(move |(sink_id, delivery)| {
                    let obligation = event.occurrence().plan().obligation(sink_id)?;
                    if obligation.policy().class != SinkClass::Required {
                        return None;
                    }
                    let DurableDeliveryRecoveryV1::Terminal { attempt_id } = delivery else {
                        return None;
                    };
                    Some((
                        event.occurrence_sequence(),
                        RequiredEventDeliveryFailureV1 {
                            sink_id: sink_id.clone(),
                            event_id: event.occurrence().event().event_id(),
                            attempt_id: *attempt_id,
                        },
                    ))
                })
        })
        .collect::<Vec<_>>();
    failures.sort_by(|left, right| {
        (left.0, left.1.sink_id.as_str()).cmp(&(right.0, right.1.sink_id.as_str()))
    });
    failures
        .into_iter()
        .map(|(_, failure)| failure)
        .collect::<Vec<_>>()
        .into()
}

impl DurableOwnedExecution {
    pub(crate) fn publish_driver_progress(
        &self,
        recovered: &RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        if recovered.latest_cut() == DurableCommitCutV1::TerminalCompletion {
            return Err(DurableRunFailure::Internal);
        }
        let outcome = recovered.machine().outcome().cloned();
        if recovered.latest_cut() == DurableCommitCutV1::ForegroundCompletion
            && let Some(outcome) = outcome.clone()
        {
            self.handle
                .publish_committed_foreground(outcome)
                .map_err(DurableRunFailure::Lifecycle)?;
        }
        self.update_driver_observation(recovered, None);
        Ok(())
    }

    fn complete_driver(
        &self,
        recovered: RecoveredDurableStateV1,
        owner: DurableJournalOwnerState,
    ) -> DurableExecutionObservation {
        let mut state = lock_state(&self.state);
        state.owner = owner;
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
        state.run_failure = None;
        state.operation_in_flight = false;
        state.driver_active = false;
        state.driver_cancellation = None;
        state.driver_waker = None;
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
        observation
    }

    fn fail_driver_with_owner(
        &self,
        recovered: RecoveredDurableStateV1,
        owner: DurableJournalOwnerState,
        failure: DurableRunFailure,
    ) {
        let _ = self.handle.publish_run_failed_nondurably();
        let mut state = lock_state(&self.state);
        state.owner = owner;
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
                if state.owner != DurableJournalOwnerState::Held
                    && state.recovered.as_ref().is_some_and(|recovered| {
                        recovered.latest_cut() == DurableCommitCutV1::TerminalCompletion
                    })
                {
                    let result = DurableCancelExecutionResult::AlreadyTerminal(Box::new(
                        state.last_observation.clone(),
                    ));
                    state.completed_cancellation = Some(result.clone());
                    return result;
                }
                #[cfg(all(feature = "concurrent", feature = "durable"))]
                if state
                    .graph_frontier
                    .is_some_and(|frontier| frontier.2 == DurableCommitCutV1::TerminalCompletion)
                {
                    let result = DurableCancelExecutionResult::AlreadyTerminal(Box::new(
                        state.last_observation.clone(),
                    ));
                    state.completed_cancellation = Some(result.clone());
                    return result;
                }
                if state.driver_active {
                    #[cfg(all(feature = "concurrent", feature = "durable"))]
                    if state.graph_active {
                        if let Some(reason) = &state.graph_cancellation {
                            requested_reason = reason.clone();
                        } else {
                            state.graph_cancellation = Some(requested_reason.clone());
                        }
                        for waker in std::mem::take(&mut state.graph_driver_wakers) {
                            waker.wake();
                        }
                    } else {
                        if let Some(reason) = &state.driver_cancellation {
                            requested_reason = reason.clone();
                        } else {
                            state.driver_cancellation = Some(requested_reason.clone());
                        }
                        if let Some(waker) = state.driver_waker.take() {
                            waker.wake();
                        }
                    }
                    #[cfg(not(all(feature = "concurrent", feature = "durable")))]
                    {
                        if let Some(reason) = &state.driver_cancellation {
                            requested_reason = reason.clone();
                        } else {
                            state.driver_cancellation = Some(requested_reason.clone());
                        }
                        if let Some(waker) = state.driver_waker.take() {
                            waker.wake();
                        }
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
            let owner = if event_obligations_settled(&recovered) {
                self.release_owner().await
            } else {
                DurableJournalOwnerState::Held
            };
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

        let mut last_committed = recovered.clone();
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
                    return self.failed_cancellation(last_committed, Some(effective_reason), error);
                }
            };
            if let Err(error) = recovered.record_semantic_commit(&commit) {
                return self.failed_cancellation(
                    last_committed,
                    Some(effective_reason),
                    DurableCommitError::Evidence(error),
                );
            }
            last_committed = recovered.clone();
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

        let owner = if event_obligations_settled(&recovered) {
            self.release_owner().await
        } else {
            DurableJournalOwnerState::Held
        };
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
                if state
                    .recovered
                    .as_ref()
                    .is_some_and(|recovered| !event_obligations_settled(recovered))
                {
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
        #[cfg(all(feature = "concurrent", feature = "durable"))]
        let graph_terminal = state.graph_frontier.is_some_and(|frontier| {
            frontier.2 == DurableCommitCutV1::TerminalCompletion
                && state.owner != DurableJournalOwnerState::Held
        });
        #[cfg(not(all(feature = "concurrent", feature = "durable")))]
        let graph_terminal = false;
        let ready = observation.run_failure.is_some()
            || (self.terminal
                && observation.terminal.is_some()
                && (graph_terminal
                    || state
                        .recovered
                        .as_ref()
                        .is_some_and(required_event_obligations_settled)))
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

#[cfg(all(feature = "concurrent", feature = "durable"))]
fn observation_from_concurrent(
    journal_id: &JournalId,
    execution_start: &DurableExecutionStartV3,
    recovered: &RecoveredConcurrentDurableStateV1,
) -> DurableExecutionObservation {
    let state = recovered.execution().scheduler().state();
    let foreground = state.foreground_outcome().cloned();
    let terminal = state
        .terminal_outcome()
        .map(|outcome| outcome.foreground.clone());
    DurableExecutionObservation {
        journal_id: journal_id.clone(),
        execution_id: execution_start.execution_id(),
        state: if terminal.is_some() {
            ExecutionObservationState::Terminal
        } else {
            ExecutionObservationState::NotTerminal
        },
        foreground,
        terminal,
        cancellation: recovered.cancellation_reason().cloned(),
        required_delivery_failures: required_delivery_failures_from_events(recovered.events()),
        owner: None,
        run_failure: None,
        latest_sequence: recovered.latest_sequence(),
        latest_evidence_id: recovered.latest_evidence_id(),
    }
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
pub(crate) fn concurrent_recovery(
    recovered: &RecoveredConcurrentDurableStateV1,
) -> DurableConcurrentRecovery {
    DurableConcurrentRecovery {
        execution_id: recovered.execution().foreground().execution_id(),
        latest_sequence: recovered.latest_sequence(),
        latest_evidence_id: recovered.latest_evidence_id(),
        latest_cut: recovered.latest_cut(),
    }
}

pub(crate) fn recover_durable_prefix(
    prefix: &JournalPrefixV1,
) -> Result<RecoveredDurablePrefix, DurableEvidenceError> {
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    if let JournalPrefixV1::Snapshot(snapshot) = prefix
        && snapshot.snapshot_version == CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1
    {
        let program = Arc::new(ConcurrentDurableRecoverySnapshotV1::retained_program(
            &snapshot.canonical_snapshot,
        )?);
        let execution_start =
            ConcurrentDurableRecoverySnapshotV1::decode(&program, &snapshot.canonical_snapshot)?
                .execution_start()
                .clone();
        let recovered = recover_concurrent_authoritative_prefix(program, prefix)?;
        return Ok(RecoveredDurablePrefix::Concurrent {
            execution_start: Box::new(execution_start),
            recovered: Box::new(recovered),
        });
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    if let JournalPrefixV1::Full(full) = prefix
        && full.evidence.iter().any(|entry| {
            matches!(
                entry.kind.as_ref(),
                CONCURRENT_DURABLE_EVIDENCE_KIND_V4 | CONCURRENT_DURABLE_EVIDENCE_KIND_V5
            )
        })
    {
        let first = full
            .evidence
            .first()
            .ok_or(DurableEvidenceError::MissingRecoveryState)?;
        if first.sequence != 1 || first.kind.as_ref() != "gantry.execution-start/v3" {
            return Err(DurableEvidenceError::InvalidExecutionStart);
        }
        let program = Arc::new(DurableExecutionStartV3::retained_program(
            &first.canonical_body,
        )?);
        let execution_start = DurableExecutionStartV3::decode(&program, &first.canonical_body)?;
        let recovered = recover_concurrent_authoritative_prefix(program, prefix)?;
        return Ok(RecoveredDurablePrefix::Concurrent {
            execution_start: Box::new(execution_start),
            recovered: Box::new(recovered),
        });
    }

    recover_authoritative_prefix_with_retained_program(prefix)
        .map(|(_, recovered)| RecoveredDurablePrefix::Serial(Box::new(recovered)))
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

#[cfg(all(feature = "concurrent", feature = "durable"))]
fn register_graph_driver_waker(waiters: &mut Vec<Waker>, waker: &Waker) {
    if !waiters.iter().any(|registered| registered.will_wake(waker)) {
        waiters.push(waker.clone());
    }
}

fn next_pending_delivery(
    events: &RecoveredDurableEventsV1,
    frontier: Option<u64>,
    required_only: bool,
) -> Result<Option<DurablePendingDelivery>, DurableRunFailure> {
    let mut pending: Option<DurablePendingDelivery> = None;
    for event in events.events().values() {
        if frontier.is_some_and(|frontier| event.occurrence_sequence() > frontier) {
            continue;
        }
        for (sink_id, recovery) in event.deliveries() {
            if matches!(
                recovery,
                DurableDeliveryRecoveryV1::Success { .. }
                    | DurableDeliveryRecoveryV1::Terminal { .. }
            ) {
                continue;
            }
            let obligation = event
                .occurrence()
                .plan()
                .obligation(sink_id)
                .ok_or(DurableRunFailure::Internal)?;
            if required_only && obligation.policy().class != SinkClass::Required {
                continue;
            }
            let candidate = DurablePendingDelivery {
                occurrence_evidence_id: event.occurrence_evidence_id(),
                occurrence_sequence: event.occurrence_sequence(),
                event: event.occurrence().event().clone(),
                sink_id: sink_id.clone(),
                policy: obligation.policy().clone(),
                recovery: recovery.clone(),
            };
            let replace = pending.as_ref().is_none_or(|current| {
                (candidate.occurrence_sequence, candidate.sink_id.as_str())
                    < (current.occurrence_sequence, current.sink_id.as_str())
            });
            if replace {
                pending = Some(candidate);
            }
        }
    }
    Ok(pending)
}

fn event_obligations_settled(recovered: &RecoveredDurableStateV1) -> bool {
    recovered.events().events().values().all(|event| {
        event.deliveries().values().all(|delivery| {
            matches!(
                delivery,
                DurableDeliveryRecoveryV1::Success { .. }
                    | DurableDeliveryRecoveryV1::Terminal { .. }
            )
        })
    })
}

fn required_event_obligations_settled(recovered: &RecoveredDurableStateV1) -> bool {
    !matches!(
        recovered.events().required_barrier_through(u64::MAX),
        DurableEventBarrierV1::Pending { .. }
    )
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
