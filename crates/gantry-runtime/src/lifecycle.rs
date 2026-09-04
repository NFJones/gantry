//! Linearizable interpreter admission, execution observation, and shutdown state.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Waker};

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{
    CancellationReasonCategory, IdentityKind, InterpreterState, ShutdownCause,
};
use gantry_host::contracts::{
    CancellationSignal, DurationMicros, HostError, HostFuture, HostRequest, HostResponse,
    IntegrationPreflight, OwnedTaskCompletion, OwnedTaskPanicOrigin, OwnedTaskResult,
};
use gantry_host::event::SinkId;

use crate::containment::{
    AdapterPoison, BoundaryFailure, PanicOrigin, catch_gantry, catch_integration,
    contain_integration_future,
};
use crate::{
    AbnormalCompletionHandler, AdmissionClass, AdmissionExhaustion, InterpreterConfiguration,
    MachineOutcome, SupervisedTaskDomain, TaskSupervisor,
};

static NEXT_INTERPRETER_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_WAITER_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static ADAPTER_EXTENTS: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

/// One public-operation admission class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionKind {
    /// Validation, analysis, start, or resume work that can create an execution.
    NewWork,
    /// Cancellation, await, or query work associated with an execution identity.
    ExistingExecution(ProtocolIdentity),
}

/// Exact lifecycle rejection code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleCode {
    /// Shutdown has begun with the ordinary requested cause.
    InterpreterShuttingDown,
    /// Shutdown has begun or was upgraded because isolation was not established.
    InterpreterPoisoned,
    /// Shutdown has completed.
    InterpreterTerminated,
    /// Integration recursively entered the same interpreter on one synchronous chain.
    ReentrantInterpreterCall,
}

impl LifecycleCode {
    /// Returns the exact portable lifecycle code.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::InterpreterShuttingDown => "interpreter-shutting-down",
            Self::InterpreterPoisoned => "interpreter-poisoned",
            Self::InterpreterTerminated => "interpreter-terminated",
            Self::ReentrantInterpreterCall => "reentrant-interpreter-call",
        }
    }
}

/// A public operation rejected at its admission linearization point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleError {
    /// Exact lifecycle code.
    pub code: LifecycleCode,
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code.wire_name())
    }
}

impl std::error::Error for LifecycleError {}

/// Typed causal identity admitted in a cancellation reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationCausalIdentity {
    /// One logical operation occurrence.
    Operation(ProtocolIdentity),
    /// One Gantry task occurrence.
    Task(ProtocolIdentity),
}

/// Canonical first-effective cancellation reason retained by the lifecycle owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancellationReason {
    /// Stable reason category.
    pub category: CancellationReasonCategory,
    /// Optional bounded unprotected diagnostic message.
    pub message: Option<Arc<str>>,
    /// Optional typed causal identity.
    pub causal_identity: Option<CancellationCausalIdentity>,
}

impl CancellationReason {
    /// Constructs one reason after checking its String limit and causal identity kind.
    pub fn new(
        category: CancellationReasonCategory,
        message: Option<Arc<str>>,
        causal_identity: Option<CancellationCausalIdentity>,
        maximum_string_scalars: u64,
    ) -> Result<Self, CancellationReasonError> {
        if message.as_deref().is_some_and(|message| {
            u64::try_from(message.chars().count())
                .map_or(true, |count| count > maximum_string_scalars)
        }) {
            return Err(CancellationReasonError::MessageTooLong);
        }
        if causal_identity.is_some_and(|identity| match identity {
            CancellationCausalIdentity::Operation(identity) => {
                identity.kind() != IdentityKind::Operation
            }
            CancellationCausalIdentity::Task(identity) => identity.kind() != IdentityKind::Task,
        }) {
            return Err(CancellationReasonError::WrongCausalIdentityKind);
        }
        Ok(Self {
            category,
            message,
            causal_identity,
        })
    }

    fn shutdown() -> Self {
        Self {
            category: CancellationReasonCategory::Shutdown,
            message: None,
            causal_identity: None,
        }
    }
}

/// Invalid cancellation-reason data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationReasonError {
    /// The diagnostic exceeds the configured maximum String scalar count.
    MessageTooLong,
    /// The identity does not match the operation/task discriminant.
    WrongCausalIdentityKind,
}

/// One internally consistent point-in-time execution projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionSnapshot {
    /// Accepted execution identity.
    pub execution_id: ProtocolIdentity,
    /// First effective cancellation reason, when cancellation has begun.
    pub cancellation: Option<CancellationReason>,
    /// Fixed foreground outcome, when known.
    pub foreground: Option<MachineOutcome>,
    /// Fixed terminal outcome, when known.
    pub terminal: Option<MachineOutcome>,
    /// Required-delivery failures retained separately from language outcomes.
    pub required_delivery_failures: Arc<[RequiredEventDeliveryFailureV1]>,
}

/// Exact required-sink exhaustion retained by one execution lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredEventDeliveryFailureV1 {
    /// Exhausted sink identity.
    pub sink_id: SinkId,
    /// Event whose required obligation exhausted.
    pub event_id: ProtocolIdentity,
    /// Final physical delivery-attempt identity.
    pub attempt_id: ProtocolIdentity,
}

/// Lifecycle effect of recording one required-delivery failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequiredDeliveryRecordV1 {
    /// The first required failure started execution cancellation.
    CancellationStarted,
    /// Cancellation was already effective when this failure was recorded.
    CancellationAlreadyActive,
    /// The terminal language outcome was already fixed and remains unchanged.
    PostTerminal(MachineOutcome),
    /// The same sink/event/attempt failure was already recorded.
    Existing,
}

/// Result of recording an execution cancellation request.
#[derive(Clone, Debug)]
pub enum CancellationRecord {
    /// This call recorded and signalled the first effective reason.
    Accepted {
        /// Canonical effective reason.
        reason: CancellationReason,
        /// Shared monotonic signal supplied to owned work.
        signal: CancellationSignal,
    },
    /// An earlier call already recorded the effective reason.
    Existing {
        /// Preserved first effective reason.
        reason: CancellationReason,
        /// Shared monotonic signal supplied to owned work.
        signal: CancellationSignal,
    },
    /// The execution had already reached terminal state.
    AlreadyTerminal(ExecutionSnapshot),
    /// No accepted execution has this identity.
    NotFound,
}

/// Rejection of an execution-state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionTransitionError {
    /// The handle no longer names a live interpreter owner.
    InterpreterDropped,
    /// No accepted execution has the supplied identity.
    NotFound,
    /// Foreground or terminal state was already fixed.
    AlreadyFixed,
    /// Terminal state cannot be fixed before foreground state.
    ForegroundUnknown,
    /// An internal execution transition received the wrong identity kind.
    WrongIdentityKind,
}

/// Immutable in-process handle to one accepted execution.
#[derive(Clone, Debug)]
pub struct ExecutionHandle {
    inner: Weak<LifecycleInner>,
    execution_id: ProtocolIdentity,
}

impl ExecutionHandle {
    /// Returns the accepted execution identity.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.execution_id
    }

    /// Returns one internally consistent point-in-time execution snapshot.
    pub fn snapshot(&self) -> Result<ExecutionSnapshot, ExecutionTransitionError> {
        let inner = self
            .inner
            .upgrade()
            .ok_or(ExecutionTransitionError::InterpreterDropped)?;
        let data = inner.lock();
        data.executions
            .get(&self.execution_id)
            .map(|execution| execution.snapshot(self.execution_id))
            .ok_or(ExecutionTransitionError::NotFound)
    }

    /// Publishes a cancellation reason whose durable evidence already committed.
    ///
    /// Durable orchestration calls this boundary only after journal acceptance;
    /// the lifecycle then fixes the first reason and signals owned work atomically.
    pub fn publish_committed_cancellation(
        &self,
        reason: CancellationReason,
    ) -> Result<CancellationRecord, ExecutionTransitionError> {
        let inner = self
            .inner
            .upgrade()
            .ok_or(ExecutionTransitionError::InterpreterDropped)?;
        let mut data = inner.lock();
        let execution = data
            .executions
            .get_mut(&self.execution_id)
            .ok_or(ExecutionTransitionError::NotFound)?;
        if execution.terminal.is_some() {
            return Ok(CancellationRecord::AlreadyTerminal(
                execution.snapshot(self.execution_id),
            ));
        }
        if let Some(existing) = &execution.cancellation {
            return Ok(CancellationRecord::Existing {
                reason: existing.clone(),
                signal: execution.cancellation_signal.clone(),
            });
        }
        execution.cancellation = Some(reason.clone());
        execution.cancellation_signal.cancel();
        Ok(CancellationRecord::Accepted {
            reason,
            signal: execution.cancellation_signal.clone(),
        })
    }

    /// Publishes a foreground outcome whose durable evidence already committed.
    pub fn publish_committed_foreground(
        &self,
        outcome: MachineOutcome,
    ) -> Result<(), ExecutionTransitionError> {
        self.publish_committed_outcome(Some(outcome), None)
    }

    /// Publishes a terminal outcome whose durable evidence already committed.
    pub fn publish_committed_terminal(
        &self,
        outcome: MachineOutcome,
    ) -> Result<(), ExecutionTransitionError> {
        self.publish_committed_outcome(None, Some(outcome))
    }

    /// Publishes an operational end to the current durable run without fixing a language outcome.
    ///
    /// This boundary signals execution-owned work and releases shutdown progress only after
    /// durable orchestration has established that the journal can no longer advance this run.
    pub fn publish_run_failed_nondurably(&self) -> Result<(), ExecutionTransitionError> {
        let inner = self
            .inner
            .upgrade()
            .ok_or(ExecutionTransitionError::InterpreterDropped)?;
        let mut data = inner.lock();
        let waiters = {
            let execution = data
                .executions
                .get_mut(&self.execution_id)
                .ok_or(ExecutionTransitionError::NotFound)?;
            if execution.terminal.is_some() {
                return Err(ExecutionTransitionError::AlreadyFixed);
            }
            if execution.run_failed_nondurably {
                return Ok(());
            }
            execution.run_failed_nondurably = true;
            execution.cancellation_signal.cancel();
            std::mem::take(&mut execution.waiters)
        };
        let progress = std::mem::take(&mut data.progress_waiters);
        drop(data);
        wake_all(
            waiters
                .into_iter()
                .map(|registered| registered.waker)
                .chain(progress)
                .collect(),
        );
        Ok(())
    }

    fn publish_committed_outcome(
        &self,
        foreground: Option<MachineOutcome>,
        terminal: Option<MachineOutcome>,
    ) -> Result<(), ExecutionTransitionError> {
        let inner = self
            .inner
            .upgrade()
            .ok_or(ExecutionTransitionError::InterpreterDropped)?;
        let mut data = inner.lock();
        let waiters = {
            let execution = data
                .executions
                .get_mut(&self.execution_id)
                .ok_or(ExecutionTransitionError::NotFound)?;
            if let Some(outcome) = foreground {
                if execution.foreground.is_some() {
                    return Err(ExecutionTransitionError::AlreadyFixed);
                }
                execution.foreground = Some(outcome);
            }
            if let Some(outcome) = terminal {
                if execution.terminal.is_some() {
                    return Err(ExecutionTransitionError::AlreadyFixed);
                }
                if execution.foreground.is_none() {
                    return Err(ExecutionTransitionError::ForegroundUnknown);
                }
                execution.terminal = Some(outcome);
            }
            std::mem::take(&mut execution.waiters)
        };
        let progress = std::mem::take(&mut data.progress_waiters);
        drop(data);
        wake_all(
            waiters
                .into_iter()
                .map(|registered| registered.waker)
                .chain(progress)
                .collect(),
        );
        Ok(())
    }

    /// Returns the monotonic execution-owned cancellation signal.
    pub fn cancellation_signal(&self) -> Result<CancellationSignal, ExecutionTransitionError> {
        let inner = self
            .inner
            .upgrade()
            .ok_or(ExecutionTransitionError::InterpreterDropped)?;
        let data = inner.lock();
        data.executions
            .get(&self.execution_id)
            .map(|execution| execution.cancellation_signal.clone())
            .ok_or(ExecutionTransitionError::NotFound)
    }

    /// Records a required-delivery barrier without replacing a language outcome.
    pub fn record_required_delivery_failure(
        &self,
        failure: RequiredEventDeliveryFailureV1,
    ) -> Result<RequiredDeliveryRecordV1, ExecutionTransitionError> {
        if failure.event_id.kind() != IdentityKind::Event
            || failure.attempt_id.kind() != IdentityKind::DeliveryAttempt
        {
            return Err(ExecutionTransitionError::WrongIdentityKind);
        }
        let inner = self
            .inner
            .upgrade()
            .ok_or(ExecutionTransitionError::InterpreterDropped)?;
        let mut data = inner.lock();
        let execution = data
            .executions
            .get_mut(&self.execution_id)
            .ok_or(ExecutionTransitionError::NotFound)?;
        if execution.required_delivery_failures.contains(&failure) {
            return Ok(RequiredDeliveryRecordV1::Existing);
        }
        execution.required_delivery_failures.push(failure);
        if let Some(terminal) = &execution.terminal {
            return Ok(RequiredDeliveryRecordV1::PostTerminal(terminal.clone()));
        }
        if execution.cancellation.is_some() {
            return Ok(RequiredDeliveryRecordV1::CancellationAlreadyActive);
        }
        execution.cancellation = Some(CancellationReason {
            category: CancellationReasonCategory::Runtime,
            message: None,
            causal_identity: None,
        });
        execution.cancellation_signal.cancel();
        Ok(RequiredDeliveryRecordV1::CancellationStarted)
    }
}

/// One linearizable interpreter lifecycle owner.
#[derive(Clone)]
pub struct InterpreterLifecycle {
    inner: Arc<LifecycleInner>,
}

impl std::fmt::Debug for InterpreterLifecycle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InterpreterLifecycle")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

impl InterpreterLifecycle {
    /// Publishes a running lifecycle using the configuration's finite defaults.
    #[must_use]
    pub fn new(configuration: &InterpreterConfiguration) -> Self {
        let supervisor = TaskSupervisor::new(
            configuration.executor_arc(),
            configuration.async_admission(),
        );
        Self {
            inner: Arc::new(LifecycleInner {
                id: NEXT_INTERPRETER_ID.fetch_add(1, Ordering::Relaxed),
                default_durations: ShutdownDurations {
                    graceful: configuration.graceful_shutdown_timeout(),
                    drain: configuration.post_cancellation_drain(),
                },
                supervisor,
                data: Mutex::new(LifecycleData {
                    state: LifecyclePhase::Running,
                    admitted_calls: 0,
                    owned_activities: 0,
                    reserved_executions: BTreeSet::new(),
                    executions: BTreeMap::new(),
                    progress_waiters: Vec::new(),
                    shutdown_waiters: Vec::new(),
                }),
            }),
        }
    }

    /// Returns whether an execution handle belongs to this interpreter lifecycle.
    #[must_use]
    pub fn owns_handle(&self, handle: &ExecutionHandle) -> bool {
        handle
            .inner
            .upgrade()
            .is_some_and(|inner| Arc::ptr_eq(&self.inner, &inner))
    }

    /// Admits one public operation at a single lifecycle linearization point.
    pub fn admit(&self, kind: AdmissionKind) -> Result<OperationAdmission, LifecycleError> {
        self.check_reentry()?;
        let mut data = self.inner.lock();
        match &data.state {
            LifecyclePhase::Running => {}
            LifecyclePhase::ShuttingDown(shutdown) => match kind {
                AdmissionKind::ExistingExecution(execution_id)
                    if shutdown.cohort.contains(&execution_id) => {}
                _ => return Err(error_for_shutdown(shutdown.cause)),
            },
            LifecyclePhase::Terminated(_) => {
                return Err(LifecycleError {
                    code: LifecycleCode::InterpreterTerminated,
                });
            }
        }
        data.admitted_calls = data.admitted_calls.saturating_add(1);
        Ok(OperationAdmission {
            inner: Arc::clone(&self.inner),
            kind,
            active: true,
            reserved_execution: None,
        })
    }

    /// Returns one linearizable lifecycle projection.
    #[must_use]
    pub fn snapshot(&self) -> LifecycleSnapshot {
        let data = self.inner.lock();
        lifecycle_snapshot(&data)
    }

    /// Returns the interpreter-wide physical task supervision owner.
    #[must_use]
    pub fn task_supervisor(&self) -> TaskSupervisor {
        self.inner.supervisor.clone()
    }

    /// Starts synchronous unclean cleanup for the last external facade owner.
    ///
    /// Internal lifecycle clones never invoke this transition. Once orderly or
    /// poisoned shutdown has begun, dropping a facade does not replace it with
    /// an unclean report.
    pub fn begin_unclean_drop(&self) {
        self.inner.unclean_drop(false);
    }

    /// Falls back to synchronous unclean cleanup when the owned shutdown task cannot run.
    pub fn fail_owned_shutdown(&self) {
        self.inner.unclean_drop(true);
    }

    /// Transfers one preflight operation to caller-independent owned activity state.
    ///
    /// The returned waiter may be dropped without cancelling the operation. A
    /// pending operation retains its integration service, operational permit,
    /// and executor handle until the owned task reaches its terminal boundary.
    #[must_use]
    pub fn call_owned_preflight(
        &self,
        service: Arc<dyn IntegrationPreflight>,
        poison: AdapterPoison,
        request: HostRequest,
    ) -> OwnedPreflightWait {
        let reservation = match self
            .inner
            .supervisor
            .try_reserve(AdmissionClass::PublicActivity)
        {
            Ok(reservation) => reservation,
            Err(error) => {
                let state = Arc::new(Mutex::new(OwnedPreflightState::default()));
                settle_owned_preflight(&state, Err(OwnedActivityError::Admission(error)));
                return OwnedPreflightWait { state };
            }
        };
        let state = Arc::new(Mutex::new(OwnedPreflightState {
            result: None,
            waiters: Vec::new(),
            lease: Some(OwnedActivityLease {
                _token: OwnedActivityToken::new(&self.inner),
            }),
        }));
        let interpreter_id = self.inner.id;
        let mut operation = Box::pin(async move {
            let future = {
                let _extent = AdapterExtent::enter(interpreter_id);
                catch_integration(&poison, || service.call(request))
                    .map_err(OwnedActivityError::Boundary)?
            };
            let response = AdapterFuture {
                interpreter_id,
                future: Some(contain_integration_future(future, poison)),
            }
            .await
            .map_err(OwnedActivityError::Boundary)?
            .map_err(OwnedActivityError::Host)?;
            Ok(response)
        });

        let mut context = Context::from_waker(Waker::noop());
        if let Poll::Ready(result) = operation.as_mut().poll(&mut context) {
            settle_owned_preflight(&state, result);
            return OwnedPreflightWait { state };
        }

        let abnormal_state = Arc::clone(&state);
        let abnormal: AbnormalCompletionHandler = Arc::new(move |completion| {
            settle_owned_preflight(
                &abnormal_state,
                Err(owned_activity_completion_failure(completion)),
            );
        });
        let registration = self
            .inner
            .supervisor
            .prepare(SupervisedTaskDomain::PublicActivity, Some(abnormal));
        let signal = registration.signal();
        let task_state = Arc::clone(&state);
        let task = Box::pin(async move {
            let result = operation.await;
            settle_owned_preflight(&task_state, result);
            signal.settle();
            OwnedTaskResult::new()
        });
        match self
            .inner
            .supervisor
            .submit(registration, task, reservation.transfer())
        {
            Ok(handle) => handle.relinquish(),
            Err(error) => {
                settle_owned_preflight(&state, Err(OwnedActivityError::Executor(error)));
            }
        }
        OwnedPreflightWait { state }
    }

    /// Transfers one event-delivery operation to caller-independent owned activity state.
    ///
    /// The operation is first polled only after the executor accepts ownership.
    /// Its future and output are then retained by a supervised event-delivery
    /// task independently of the returned waiter.
    pub fn call_owned_event_delivery<T, F>(
        &self,
        operation: F,
    ) -> impl Future<Output = Result<T, OwnedActivityError>> + Send + 'static
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let reservation = match self
            .inner
            .supervisor
            .try_reserve(AdmissionClass::EventDelivery)
        {
            Ok(reservation) => reservation,
            Err(error) => {
                let state = Arc::new(Mutex::new(OwnedActivityState {
                    settled: true,
                    result: Some(Err(OwnedActivityError::Admission(error))),
                    waiters: Vec::new(),
                    lease: None,
                }));
                return OwnedActivityWait { state };
            }
        };
        let state = Arc::new(Mutex::new(OwnedActivityState {
            settled: false,
            result: None,
            waiters: Vec::new(),
            lease: Some(OwnedActivityLease {
                _token: OwnedActivityToken::new(&self.inner),
            }),
        }));
        let abnormal_state = Arc::clone(&state);
        let abnormal: AbnormalCompletionHandler = Arc::new(move |completion| {
            settle_owned_activity(
                &abnormal_state,
                Err(owned_activity_completion_failure(completion)),
            );
        });
        let registration = self
            .inner
            .supervisor
            .prepare(SupervisedTaskDomain::EventDelivery, Some(abnormal));
        let signal = registration.signal();
        let task_state = Arc::clone(&state);
        let task = Box::pin(async move {
            let result = operation.await;
            settle_owned_activity(&task_state, Ok(result));
            signal.settle();
            OwnedTaskResult::new()
        });
        match self
            .inner
            .supervisor
            .submit(registration, task, reservation.transfer())
        {
            Ok(handle) => handle.relinquish(),
            Err(error) => {
                settle_owned_activity(&state, Err(OwnedActivityError::Executor(error)));
            }
        }
        OwnedActivityWait { state }
    }

    /// Returns submitted activity handles retained for later physical supervision.
    #[must_use]
    pub fn owned_activity_submitted_task_count(&self) -> usize {
        self.inner
            .supervisor
            .active_count(SupervisedTaskDomain::PublicActivity)
    }

    /// Performs a snapshot-consistent in-process execution query.
    pub fn query_execution(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Result<Option<ExecutionSnapshot>, LifecycleError> {
        let _admission = self.admit(AdmissionKind::ExistingExecution(execution_id))?;
        let data = self.inner.lock();
        Ok(data
            .executions
            .get(&execution_id)
            .map(|execution| execution.snapshot(execution_id)))
    }

    /// Registers an independent foreground waiter.
    pub fn await_foreground(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Result<ExecutionWait, LifecycleError> {
        let admission = self.admit(AdmissionKind::ExistingExecution(execution_id))?;
        Ok(ExecutionWait {
            admission: Some(admission),
            execution_id,
            kind: WaitKind::Foreground,
            waiter_id: NEXT_WAITER_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    /// Registers an independent terminal waiter.
    pub fn await_terminal(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Result<ExecutionWait, LifecycleError> {
        let admission = self.admit(AdmissionKind::ExistingExecution(execution_id))?;
        Ok(ExecutionWait {
            admission: Some(admission),
            execution_id,
            kind: WaitKind::Terminal,
            waiter_id: NEXT_WAITER_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    /// Records the first cancellation reason and signals execution-owned work.
    pub fn cancel_execution(
        &self,
        execution_id: ProtocolIdentity,
        reason: CancellationReason,
    ) -> Result<CancellationRecord, LifecycleError> {
        let _admission = self.admit(AdmissionKind::ExistingExecution(execution_id))?;
        let mut data = self.inner.lock();
        let Some(execution) = data.executions.get_mut(&execution_id) else {
            return Ok(CancellationRecord::NotFound);
        };
        if execution.terminal.is_some() {
            return Ok(CancellationRecord::AlreadyTerminal(
                execution.snapshot(execution_id),
            ));
        }
        if let Some(existing) = &execution.cancellation {
            return Ok(CancellationRecord::Existing {
                reason: existing.clone(),
                signal: execution.cancellation_signal.clone(),
            });
        }
        execution.cancellation = Some(reason.clone());
        execution.cancellation_signal.cancel();
        Ok(CancellationRecord::Accepted {
            reason,
            signal: execution.cancellation_signal.clone(),
        })
    }

    /// Fixes the foreground language outcome exactly once.
    pub fn complete_foreground(
        &self,
        handle: &ExecutionHandle,
        outcome: MachineOutcome,
    ) -> Result<(), ExecutionTransitionError> {
        self.complete_execution(handle, Some(outcome), None)
    }

    /// Fixes the terminal language outcome exactly once after foreground completion.
    pub fn complete_terminal(
        &self,
        handle: &ExecutionHandle,
        outcome: MachineOutcome,
    ) -> Result<(), ExecutionTransitionError> {
        self.complete_execution(handle, None, Some(outcome))
    }

    /// Begins or joins the unique shutdown coordinator and snapshots first-call durations.
    pub fn begin_shutdown(
        &self,
        graceful_override: Option<DurationMicros>,
        drain_override: Option<DurationMicros>,
    ) -> Result<ShutdownAdmission, LifecycleError> {
        self.check_reentry()?;
        let mut data = self.inner.lock();
        if let LifecyclePhase::Terminated(report) = &data.state {
            return Ok(ShutdownAdmission {
                coordinator: None,
                wait: ShutdownWait {
                    inner: Arc::downgrade(&self.inner),
                    completed: Some(Arc::clone(report)),
                },
                durations: report.durations,
            });
        }

        if matches!(data.state, LifecyclePhase::Running) {
            let cohort = data
                .executions
                .iter()
                .filter_map(|(identity, execution)| {
                    execution.terminal.is_none().then_some(*identity)
                })
                .collect::<BTreeSet<_>>();
            data.state = LifecyclePhase::ShuttingDown(ShutdownState {
                cause: ShutdownCause::Requested,
                durations: ShutdownDurations {
                    graceful: graceful_override.unwrap_or(self.inner.default_durations.graceful),
                    drain: drain_override.unwrap_or(self.inner.default_durations.drain),
                },
                initial_cohort: cohort.clone(),
                cohort,
                coordinator_active: false,
            });
        }

        let (durations, claim_coordinator) = match &mut data.state {
            LifecyclePhase::ShuttingDown(shutdown) => {
                let claim = !shutdown.coordinator_active;
                if claim {
                    shutdown.coordinator_active = true;
                }
                (shutdown.durations, claim)
            }
            LifecyclePhase::Running | LifecyclePhase::Terminated(_) => unreachable!(),
        };
        drop(data);
        Ok(ShutdownAdmission {
            coordinator: claim_coordinator.then(|| ShutdownCoordinator {
                inner: Arc::clone(&self.inner),
                active: true,
            }),
            wait: ShutdownWait {
                inner: Arc::downgrade(&self.inner),
                completed: None,
            },
            durations,
        })
    }

    /// Publishes or upgrades poisoned shutdown and signals the complete current cohort.
    pub fn poison(&self) {
        let mut data = self.inner.lock();
        if matches!(data.state, LifecyclePhase::Terminated(_)) {
            return;
        }
        if matches!(data.state, LifecyclePhase::Running) {
            let cohort = data
                .executions
                .iter()
                .filter_map(|(identity, execution)| {
                    execution.terminal.is_none().then_some(*identity)
                })
                .collect::<BTreeSet<_>>();
            data.state = LifecyclePhase::ShuttingDown(ShutdownState {
                cause: ShutdownCause::Poisoned,
                durations: self.inner.default_durations,
                initial_cohort: cohort.clone(),
                cohort,
                coordinator_active: false,
            });
        } else if let LifecyclePhase::ShuttingDown(shutdown) = &mut data.state {
            shutdown.cause = ShutdownCause::Poisoned;
        }
        let cohort = match &data.state {
            LifecyclePhase::ShuttingDown(shutdown) => shutdown.cohort.clone(),
            LifecyclePhase::Running | LifecyclePhase::Terminated(_) => BTreeSet::new(),
        };
        for execution_id in cohort {
            if let Some(execution) = data.executions.get_mut(&execution_id)
                && execution.terminal.is_none()
            {
                if execution.cancellation.is_none() {
                    execution.cancellation = Some(CancellationReason::shutdown());
                }
                execution.cancellation_signal.cancel();
            }
        }
        let waiters = take_all_waiters(&mut data);
        drop(data);
        wake_all(waiters);
    }

    /// Contains one Gantry public operation and initiates poisoned shutdown on panic.
    pub fn catch_public<T>(&self, invoke: impl FnOnce() -> T) -> Result<T, BoundaryFailure> {
        catch_gantry(invoke).inspect_err(|_failure| {
            self.poison();
        })
    }

    /// Contains polling and destruction of one Gantry-owned public operation.
    pub fn contain_public_future<'a, T: Send + 'a>(
        &self,
        future: HostFuture<'a, T>,
    ) -> HostFuture<'a, Result<T, BoundaryFailure>> {
        Box::pin(PublicFuture {
            lifecycle: self.clone(),
            future: Some(future),
        })
    }

    /// Invokes synchronous integration code with reentry detection and adapter poisoning.
    pub fn catch_adapter<T>(
        &self,
        poison: &AdapterPoison,
        invoke: impl FnOnce() -> T,
    ) -> Result<T, BoundaryFailure> {
        let _extent = AdapterExtent::enter(self.inner.id);
        catch_integration(poison, invoke)
    }

    /// Contains every adapter-future poll and destruction under a reentrant extent.
    pub fn contain_adapter_future<'a, T: Send + 'a>(
        &self,
        future: HostFuture<'a, T>,
        poison: AdapterPoison,
    ) -> HostFuture<'a, Result<T, BoundaryFailure>> {
        Box::pin(AdapterFuture {
            interpreter_id: self.inner.id,
            future: Some(contain_integration_future(future, poison)),
        })
    }

    fn complete_execution(
        &self,
        handle: &ExecutionHandle,
        foreground: Option<MachineOutcome>,
        terminal: Option<MachineOutcome>,
    ) -> Result<(), ExecutionTransitionError> {
        let Some(inner) = handle.inner.upgrade() else {
            return Err(ExecutionTransitionError::InterpreterDropped);
        };
        if !Arc::ptr_eq(&inner, &self.inner) {
            return Err(ExecutionTransitionError::NotFound);
        }
        let mut data = inner.lock();
        let waiters = {
            let execution = data
                .executions
                .get_mut(&handle.execution_id)
                .ok_or(ExecutionTransitionError::NotFound)?;
            if let Some(outcome) = foreground {
                if execution.foreground.is_some() {
                    return Err(ExecutionTransitionError::AlreadyFixed);
                }
                execution.foreground = Some(outcome);
            }
            if let Some(outcome) = terminal {
                if execution.terminal.is_some() {
                    return Err(ExecutionTransitionError::AlreadyFixed);
                }
                if execution.foreground.is_none() {
                    return Err(ExecutionTransitionError::ForegroundUnknown);
                }
                execution.terminal = Some(outcome);
            }
            std::mem::take(&mut execution.waiters)
        };
        let progress = std::mem::take(&mut data.progress_waiters);
        drop(data);
        wake_all(
            waiters
                .into_iter()
                .map(|registered| registered.waker)
                .chain(progress)
                .collect(),
        );
        Ok(())
    }

    fn check_reentry(&self) -> Result<(), LifecycleError> {
        let reentrant = ADAPTER_EXTENTS.with(|extents| extents.borrow().contains(&self.inner.id));
        if reentrant {
            Err(LifecycleError {
                code: LifecycleCode::ReentrantInterpreterCall,
            })
        } else {
            Ok(())
        }
    }
}

/// One admitted public invocation removed automatically on completion or cancellation.
pub struct OperationAdmission {
    inner: Arc<LifecycleInner>,
    kind: AdmissionKind,
    active: bool,
    reserved_execution: Option<ProtocolIdentity>,
}

impl std::fmt::Debug for OperationAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperationAdmission")
            .field("kind", &self.kind)
            .field("active", &self.active)
            .field("reserved_execution", &self.reserved_execution)
            .finish()
    }
}

impl OperationAdmission {
    /// Reserves one execution identity without publishing accepted lifecycle state.
    pub fn reserve_execution(
        &mut self,
        execution_id: ProtocolIdentity,
    ) -> Result<(), AcceptExecutionError> {
        if !self.active {
            return Err(AcceptExecutionError::AdmissionTransferred);
        }
        if self.kind != AdmissionKind::NewWork {
            return Err(AcceptExecutionError::WrongAdmissionKind);
        }
        if execution_id.kind() != IdentityKind::Execution {
            return Err(AcceptExecutionError::WrongIdentityKind);
        }
        if self.reserved_execution.is_some() {
            return Err(AcceptExecutionError::AdmissionTransferred);
        }
        let mut data = self.inner.lock();
        if data.executions.contains_key(&execution_id)
            || !data.reserved_executions.insert(execution_id)
        {
            return Err(AcceptExecutionError::DuplicateIdentity);
        }
        self.reserved_execution = Some(execution_id);
        Ok(())
    }

    /// Publishes a previously reserved identity as accepted execution state.
    pub fn accept_reserved_execution(
        &mut self,
        execution_id: ProtocolIdentity,
    ) -> Result<ExecutionHandle, AcceptExecutionError> {
        if !self.active {
            return Err(AcceptExecutionError::AdmissionTransferred);
        }
        if self.reserved_execution != Some(execution_id) {
            return Err(AcceptExecutionError::ReservationMismatch);
        }
        let mut data = self.inner.lock();
        if !data.reserved_executions.remove(&execution_id)
            || data
                .executions
                .insert(execution_id, ExecutionRecord::new())
                .is_some()
        {
            return Err(AcceptExecutionError::ReservationMismatch);
        }
        if let LifecyclePhase::ShuttingDown(shutdown) = &mut data.state {
            shutdown.cohort.insert(execution_id);
        }
        self.reserved_execution = None;
        self.active = false;
        data.admitted_calls = data.admitted_calls.saturating_sub(1);
        let progress = std::mem::take(&mut data.progress_waiters);
        drop(data);
        wake_all(progress);
        Ok(ExecutionHandle {
            inner: Arc::downgrade(&self.inner),
            execution_id,
        })
    }

    /// Transfers admitted new work into an accepted execution state.
    pub fn accept_execution(
        &mut self,
        execution_id: ProtocolIdentity,
    ) -> Result<ExecutionHandle, AcceptExecutionError> {
        self.reserve_execution(execution_id)?;
        self.accept_reserved_execution(execution_id)
    }
}

impl Drop for OperationAdmission {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let mut data = self.inner.lock();
        if let Some(execution_id) = self.reserved_execution.take() {
            data.reserved_executions.remove(&execution_id);
        }
        data.admitted_calls = data.admitted_calls.saturating_sub(1);
        let progress = std::mem::take(&mut data.progress_waiters);
        drop(data);
        wake_all(progress);
    }
}

/// Failure while admitting or running one caller-independent lifecycle activity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedActivityError {
    /// The selected bounded activity class was saturated before invocation.
    Admission(AdmissionExhaustion),
    /// The executor could not accept the owned activity task.
    Executor(HostError),
    /// Integration code returned a structured host failure.
    Host(HostError),
    /// Integration code panicked while invoked, polled, cancelled, or destroyed.
    Boundary(BoundaryFailure),
}

/// Caller-facing observation of one caller-independent preflight operation.
///
/// Dropping this waiter removes only the caller's observation. The owned
/// activity retains its service, permit, and executor task until settlement.
pub struct OwnedPreflightWait {
    state: Arc<Mutex<OwnedPreflightState>>,
}

impl Future for OwnedPreflightWait {
    type Output = Result<HostResponse, OwnedActivityError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = lock_owned_preflight(&self.state);
        if let Some(result) = &state.result {
            return Poll::Ready(result.clone());
        }
        register_waker(&mut state.waiters, context.waker());
        Poll::Pending
    }
}

#[derive(Default)]
struct OwnedPreflightState {
    result: Option<Result<HostResponse, OwnedActivityError>>,
    waiters: Vec<Waker>,
    lease: Option<OwnedActivityLease>,
}

fn settle_owned_preflight(
    state: &Mutex<OwnedPreflightState>,
    result: Result<HostResponse, OwnedActivityError>,
) {
    let (waiters, lease) = {
        let mut state = lock_owned_preflight(state);
        if state.result.is_some() {
            return;
        }
        state.result = Some(result);
        (std::mem::take(&mut state.waiters), state.lease.take())
    };
    drop(lease);
    wake_all(waiters);
}

fn lock_owned_preflight(state: &Mutex<OwnedPreflightState>) -> MutexGuard<'_, OwnedPreflightState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct OwnedActivityWait<T> {
    state: Arc<Mutex<OwnedActivityState<T>>>,
}

impl<T> Future for OwnedActivityWait<T> {
    type Output = Result<T, OwnedActivityError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = lock_owned_activity(&self.state);
        if let Some(result) = state.result.take() {
            return Poll::Ready(result);
        }
        register_waker(&mut state.waiters, context.waker());
        Poll::Pending
    }
}

struct OwnedActivityState<T> {
    settled: bool,
    result: Option<Result<T, OwnedActivityError>>,
    waiters: Vec<Waker>,
    lease: Option<OwnedActivityLease>,
}

fn settle_owned_activity<T>(
    state: &Mutex<OwnedActivityState<T>>,
    result: Result<T, OwnedActivityError>,
) {
    let (waiters, lease) = {
        let mut state = lock_owned_activity(state);
        if state.settled {
            return;
        }
        state.settled = true;
        state.result = Some(result);
        (std::mem::take(&mut state.waiters), state.lease.take())
    };
    drop(lease);
    wake_all(waiters);
}

fn lock_owned_activity<T>(
    state: &Mutex<OwnedActivityState<T>>,
) -> MutexGuard<'_, OwnedActivityState<T>> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn owned_activity_completion_failure(completion: OwnedTaskCompletion) -> OwnedActivityError {
    match completion {
        OwnedTaskCompletion::Panicked { origin, .. } => {
            OwnedActivityError::Boundary(BoundaryFailure {
                origin: match origin {
                    OwnedTaskPanicOrigin::Integration => PanicOrigin::Integration,
                    OwnedTaskPanicOrigin::GantryInvariant => PanicOrigin::GantryInvariant,
                },
            })
        }
        OwnedTaskCompletion::Failed(error) => OwnedActivityError::Executor(error),
        OwnedTaskCompletion::Completed(_) | OwnedTaskCompletion::Stopped => {
            OwnedActivityError::Executor(HostError {
                code: Arc::from("executor-failure"),
                protected_diagnostic: None,
            })
        }
    }
}

struct OwnedActivityLease {
    _token: OwnedActivityToken,
}

struct OwnedActivityToken {
    inner: Arc<LifecycleInner>,
}

impl OwnedActivityToken {
    fn new(inner: &Arc<LifecycleInner>) -> Self {
        let mut data = inner.lock();
        data.owned_activities = data.owned_activities.saturating_add(1);
        drop(data);
        Self {
            inner: Arc::clone(inner),
        }
    }
}

impl Drop for OwnedActivityToken {
    fn drop(&mut self) {
        let mut data = self.inner.lock();
        data.owned_activities = data.owned_activities.saturating_sub(1);
        let progress = std::mem::take(&mut data.progress_waiters);
        drop(data);
        wake_all(progress);
    }
}

/// Rejection while transferring an admitted invocation into execution state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptExecutionError {
    /// This invocation already transferred its continuing work.
    AdmissionTransferred,
    /// Only new-work admission may accept an execution.
    WrongAdmissionKind,
    /// The identity is not an execution identity.
    WrongIdentityKind,
    /// This interpreter already owns the execution identity.
    DuplicateIdentity,
    /// The reserved identity is absent or differs from the accepted identity.
    ReservationMismatch,
}

/// Future for one independent foreground or terminal observation.
pub struct ExecutionWait {
    admission: Option<OperationAdmission>,
    execution_id: ProtocolIdentity,
    kind: WaitKind,
    waiter_id: u64,
}

impl Future for ExecutionWait {
    type Output = Option<ExecutionSnapshot>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(admission) = self.admission.as_ref() else {
            panic!("execution waiter polled after completion");
        };
        let inner = Arc::clone(&admission.inner);
        let execution_id = self.execution_id;
        let kind = self.kind;
        let waiter_id = self.waiter_id;
        let mut data = inner.lock();
        let Some(execution) = data.executions.get_mut(&execution_id) else {
            drop(data);
            self.admission = None;
            return Poll::Ready(None);
        };
        let ready = match kind {
            WaitKind::Foreground => execution.foreground.is_some(),
            WaitKind::Terminal => execution.terminal.is_some(),
        };
        if ready {
            execution
                .waiters
                .retain(|registered| registered.waiter_id != waiter_id);
            let snapshot = execution.snapshot(execution_id);
            drop(data);
            self.admission = None;
            Poll::Ready(Some(snapshot))
        } else {
            register_execution_waker(&mut execution.waiters, waiter_id, context.waker());
            Poll::Pending
        }
    }
}

impl Drop for ExecutionWait {
    fn drop(&mut self) {
        let Some(admission) = self.admission.as_ref() else {
            return;
        };
        let mut data = admission.inner.lock();
        if let Some(execution) = data.executions.get_mut(&self.execution_id) {
            execution
                .waiters
                .retain(|registered| registered.waiter_id != self.waiter_id);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaitKind {
    Foreground,
    Terminal,
}

/// Effective finite durations captured by the first shutdown transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownDurations {
    /// Natural-completion grace period.
    pub graceful: DurationMicros,
    /// Post-cancellation drain period.
    pub drain: DurationMicros,
}

/// Settlement of the one final interpreter-wide nondurable shutdown event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalShutdownEventSettlement {
    /// Every required and finite best-effort obligation settled successfully.
    Settled,
    /// Delivery reached a terminal required or best-effort exhaustion result.
    Exhausted,
    /// Event construction or delivery infrastructure failed before sink exhaustion.
    Failed(FinalShutdownEventFailure),
    /// Unclean synchronous destruction does not create a standard event.
    NotAttemptedUnclean,
}

/// Operational failure of the final shutdown event, distinct from sink exhaustion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalShutdownEventFailure {
    /// Activity, event, or attempt identity allocation failed.
    IdentityGeneration,
    /// The clock or executor-neutral delivery runtime failed.
    Executor,
    /// Event construction or projection violated an internal contract.
    Internal,
}

/// Immutable shutdown result returned to every caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    /// Final monotonic shutdown cause.
    pub cause: ShutdownCause,
    /// Durations captured by the first shutdown transition.
    pub durations: ShutdownDurations,
    /// Stable shutdown cohort in execution-identity order.
    pub cohort: Arc<[ExecutionSnapshot]>,
    /// Whether all cleanup, release, and required delivery obligations were orderly.
    pub orderly: bool,
    /// Whether destruction occurred without completed asynchronous shutdown.
    pub unclean: bool,
    /// Final nondurable shutdown-event settlement.
    pub final_event: FinalShutdownEventSettlement,
}

/// First-call shutdown admission and a future shared by all callers.
pub struct ShutdownAdmission {
    /// Present only for the one caller responsible for cleanup coordination.
    pub coordinator: Option<ShutdownCoordinator>,
    /// Resolves to the immutable report published at termination.
    pub wait: ShutdownWait,
    /// Effective first-call duration snapshot.
    pub durations: ShutdownDurations,
}

/// Unique shutdown cleanup authority.
pub struct ShutdownCoordinator {
    inner: Arc<LifecycleInner>,
    active: bool,
}

impl ShutdownCoordinator {
    /// Returns a future that resolves after every previously admitted call has
    /// either completed or transferred into accepted lifecycle state.
    #[must_use]
    pub fn wait_for_admission_handoffs(&self) -> ShutdownAdmissionProgress {
        ShutdownAdmissionProgress {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Returns a future that resolves after prior calls transfer or finish and the cohort settles.
    #[must_use]
    pub fn wait_for_quiescence(&self) -> ShutdownProgress {
        ShutdownProgress {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Returns the immutable execution cohort fixed by shutdown linearization.
    #[must_use]
    pub fn initial_executions(&self) -> Arc<[ProtocolIdentity]> {
        let data = self.inner.lock();
        let LifecyclePhase::ShuttingDown(shutdown) = &data.state else {
            return Arc::from([]);
        };
        Arc::from(shutdown.initial_cohort.iter().copied().collect::<Vec<_>>())
    }

    /// Returns every execution admitted into this shutdown cohort so far.
    #[must_use]
    pub fn cohort_executions(&self) -> Arc<[ProtocolIdentity]> {
        let data = self.inner.lock();
        let LifecyclePhase::ShuttingDown(shutdown) = &data.state else {
            return Arc::from([]);
        };
        Arc::from(shutdown.cohort.iter().copied().collect::<Vec<_>>())
    }

    /// Signals shutdown cancellation to every remaining cohort execution.
    pub fn cancel_remaining(&self) -> Arc<[ProtocolIdentity]> {
        let mut data = self.inner.lock();
        let cohort = match &data.state {
            LifecyclePhase::ShuttingDown(shutdown) => shutdown.cohort.clone(),
            LifecyclePhase::Running | LifecyclePhase::Terminated(_) => BTreeSet::new(),
        };
        let mut cancelled = Vec::new();
        for execution_id in cohort {
            if let Some(execution) = data.executions.get_mut(&execution_id)
                && execution.terminal.is_none()
            {
                if execution.cancellation.is_none() {
                    execution.cancellation = Some(CancellationReason::shutdown());
                }
                execution.cancellation_signal.cancel();
                cancelled.push(execution_id);
            }
        }
        Arc::from(cancelled)
    }

    /// Returns the current nonterminal cohort identities without advancing execution.
    #[must_use]
    pub fn pending_executions(&self) -> Arc<[ProtocolIdentity]> {
        let data = self.inner.lock();
        Arc::from(pending_executions(&data))
    }

    /// Publishes the immutable report only after all admitted calls and executions settle.
    pub fn complete(
        mut self,
        orderly: bool,
        final_event: FinalShutdownEventSettlement,
    ) -> Result<Arc<ShutdownReport>, ShutdownCompletionError> {
        if final_event == FinalShutdownEventSettlement::NotAttemptedUnclean {
            return Err(ShutdownCompletionError::FinalEventUnsettled);
        }
        let mut data = self.inner.lock();
        if data.admitted_calls != 0 {
            return Err(ShutdownCompletionError::AdmittedCallsPending);
        }
        if data.owned_activities != 0 {
            return Err(ShutdownCompletionError::OwnedActivitiesPending);
        }
        if !self.inner.supervisor.is_shutdown_quiescent() {
            return Err(ShutdownCompletionError::SupervisedTasksPending);
        }
        if !pending_executions(&data).is_empty() {
            return Err(ShutdownCompletionError::ExecutionsPending);
        }
        let LifecyclePhase::ShuttingDown(shutdown) = &data.state else {
            return match &data.state {
                LifecyclePhase::Terminated(report) => Ok(Arc::clone(report)),
                LifecyclePhase::Running => Err(ShutdownCompletionError::NotShuttingDown),
                LifecyclePhase::ShuttingDown(_) => unreachable!(),
            };
        };
        let cause = shutdown.cause;
        let durations = shutdown.durations;
        let cohort = shutdown
            .cohort
            .iter()
            .filter_map(|identity| {
                data.executions
                    .get(identity)
                    .map(|execution| execution.snapshot(*identity))
            })
            .collect::<Vec<_>>();
        let report = Arc::new(ShutdownReport {
            cause,
            durations,
            cohort: Arc::from(cohort),
            orderly: orderly && cause != ShutdownCause::Poisoned,
            unclean: false,
            final_event,
        });
        data.state = LifecyclePhase::Terminated(Arc::clone(&report));
        let waiters = take_all_waiters(&mut data);
        self.active = false;
        drop(data);
        wake_all(waiters);
        Ok(report)
    }
}

impl Drop for ShutdownCoordinator {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut data = self.inner.lock();
        if let LifecyclePhase::ShuttingDown(shutdown) = &mut data.state {
            shutdown.coordinator_active = false;
        }
        let waiters = std::mem::take(&mut data.shutdown_waiters);
        drop(data);
        wake_all(waiters);
    }
}

/// Reason a shutdown report could not yet be fixed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownCompletionError {
    /// Shutdown was not initiated.
    NotShuttingDown,
    /// Previously admitted public invocations have not finished or transferred work.
    AdmittedCallsPending,
    /// Caller-independent activities have not reached their terminal ownership state.
    OwnedActivitiesPending,
    /// Executor-submitted tasks have not reached physical settlement.
    SupervisedTasksPending,
    /// At least one cohort execution remains nonterminal.
    ExecutionsPending,
    /// Clean shutdown must settle or exhaust the final standard event.
    FinalEventUnsettled,
}

/// Shared future for the immutable completed shutdown report.
pub struct ShutdownWait {
    inner: Weak<LifecycleInner>,
    completed: Option<Arc<ShutdownReport>>,
}

impl Future for ShutdownWait {
    type Output = Arc<ShutdownReport>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(report) = &self.completed {
            return Poll::Ready(Arc::clone(report));
        }
        let Some(inner) = self.inner.upgrade() else {
            panic!("shutdown owner disappeared before publishing a report");
        };
        let mut data = inner.lock();
        if let LifecyclePhase::Terminated(report) = &data.state {
            let report = Arc::clone(report);
            drop(data);
            self.completed = Some(Arc::clone(&report));
            Poll::Ready(report)
        } else {
            register_waker(&mut data.shutdown_waiters, context.waker());
            Poll::Pending
        }
    }
}

/// Future resolving when shutdown owns no pending public invocation or cohort execution.
pub struct ShutdownProgress {
    inner: Weak<LifecycleInner>,
}

/// Future resolving when every admitted call has completed or transferred its work.
pub struct ShutdownAdmissionProgress {
    inner: Weak<LifecycleInner>,
}

impl Future for ShutdownAdmissionProgress {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(inner) = self.inner.upgrade() else {
            return Poll::Ready(());
        };
        let mut data = inner.lock();
        if data.admitted_calls == 0 {
            Poll::Ready(())
        } else {
            register_waker(&mut data.progress_waiters, context.waker());
            Poll::Pending
        }
    }
}

impl Future for ShutdownProgress {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(inner) = self.inner.upgrade() else {
            return Poll::Ready(());
        };
        let mut data = inner.lock();
        let lifecycle_ready = data.admitted_calls == 0
            && data.owned_activities == 0
            && pending_executions(&data).is_empty();
        if !lifecycle_ready {
            register_waker(&mut data.progress_waiters, context.waker());
        }
        drop(data);
        let supervision_ready = inner
            .supervisor
            .poll_shutdown_quiescence(context)
            .is_ready();
        if lifecycle_ready && supervision_ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Point-in-time interpreter lifecycle projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleSnapshot {
    /// Monotonic coarse state.
    pub state: InterpreterState,
    /// Shutdown cause when shutdown has begun.
    pub cause: Option<ShutdownCause>,
    /// First-call effective durations when shutdown has begun.
    pub durations: Option<ShutdownDurations>,
    /// Number of admitted public invocations not yet completed or transferred.
    pub admitted_calls: u64,
    /// Number of caller-independent activities not yet settled.
    pub owned_activities: u64,
    /// Current shutdown cohort in execution-identity order.
    pub cohort: Arc<[ProtocolIdentity]>,
}

struct LifecycleInner {
    id: u64,
    default_durations: ShutdownDurations,
    supervisor: TaskSupervisor,
    data: Mutex<LifecycleData>,
}

impl LifecycleInner {
    fn lock(&self) -> MutexGuard<'_, LifecycleData> {
        self.data
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn unclean_drop(&self, failed_owned_shutdown: bool) {
        let mut data = self.lock();
        let (cause, durations, cohort_ids) = match &data.state {
            LifecyclePhase::Running => (
                ShutdownCause::Requested,
                self.default_durations,
                data.executions
                    .iter()
                    .filter_map(|(identity, execution)| {
                        execution.terminal.is_none().then_some(*identity)
                    })
                    .collect::<BTreeSet<_>>(),
            ),
            LifecyclePhase::ShuttingDown(shutdown) if shutdown.cause == ShutdownCause::Poisoned => {
                (shutdown.cause, shutdown.durations, shutdown.cohort.clone())
            }
            LifecyclePhase::ShuttingDown(shutdown) if failed_owned_shutdown => {
                (shutdown.cause, shutdown.durations, shutdown.cohort.clone())
            }
            LifecyclePhase::ShuttingDown(_) | LifecyclePhase::Terminated(_) => return,
        };
        for execution in data.executions.values_mut() {
            if execution.terminal.is_none() {
                if execution.cancellation.is_none() {
                    execution.cancellation = Some(CancellationReason::shutdown());
                }
                execution.cancellation_signal.cancel();
            }
        }
        let cohort = cohort_ids
            .iter()
            .filter_map(|identity| {
                data.executions
                    .get(identity)
                    .map(|execution| execution.snapshot(*identity))
            })
            .collect::<Vec<_>>();
        let report = Arc::new(ShutdownReport {
            cause,
            durations,
            cohort: Arc::from(cohort),
            orderly: false,
            unclean: true,
            final_event: FinalShutdownEventSettlement::NotAttemptedUnclean,
        });
        data.state = LifecyclePhase::Terminated(report);
        let waiters = take_all_waiters(&mut data);
        drop(data);
        self.supervisor.abort_and_relinquish_all();
        wake_all(waiters);
    }
}

struct LifecycleData {
    state: LifecyclePhase,
    admitted_calls: u64,
    owned_activities: u64,
    reserved_executions: BTreeSet<ProtocolIdentity>,
    executions: BTreeMap<ProtocolIdentity, ExecutionRecord>,
    progress_waiters: Vec<Waker>,
    shutdown_waiters: Vec<Waker>,
}

enum LifecyclePhase {
    Running,
    ShuttingDown(ShutdownState),
    Terminated(Arc<ShutdownReport>),
}

struct ShutdownState {
    cause: ShutdownCause,
    durations: ShutdownDurations,
    initial_cohort: BTreeSet<ProtocolIdentity>,
    cohort: BTreeSet<ProtocolIdentity>,
    coordinator_active: bool,
}

struct ExecutionRecord {
    cancellation_signal: CancellationSignal,
    cancellation: Option<CancellationReason>,
    foreground: Option<MachineOutcome>,
    terminal: Option<MachineOutcome>,
    run_failed_nondurably: bool,
    required_delivery_failures: Vec<RequiredEventDeliveryFailureV1>,
    waiters: Vec<RegisteredWaiter>,
}

struct RegisteredWaiter {
    waiter_id: u64,
    waker: Waker,
}

impl ExecutionRecord {
    fn new() -> Self {
        Self {
            cancellation_signal: CancellationSignal::default(),
            cancellation: None,
            foreground: None,
            terminal: None,
            run_failed_nondurably: false,
            required_delivery_failures: Vec::new(),
            waiters: Vec::new(),
        }
    }

    fn snapshot(&self, execution_id: ProtocolIdentity) -> ExecutionSnapshot {
        ExecutionSnapshot {
            execution_id,
            cancellation: self.cancellation.clone(),
            foreground: self.foreground.clone(),
            terminal: self.terminal.clone(),
            required_delivery_failures: Arc::from(self.required_delivery_failures.clone()),
        }
    }
}

struct AdapterExtent {
    interpreter_id: u64,
}

impl AdapterExtent {
    fn enter(interpreter_id: u64) -> Self {
        ADAPTER_EXTENTS.with(|extents| extents.borrow_mut().push(interpreter_id));
        Self { interpreter_id }
    }
}

impl Drop for AdapterExtent {
    fn drop(&mut self) {
        ADAPTER_EXTENTS.with(|extents| {
            let popped = extents.borrow_mut().pop();
            debug_assert_eq!(popped, Some(self.interpreter_id));
        });
    }
}

struct PublicFuture<'a, T> {
    lifecycle: InterpreterLifecycle,
    future: Option<HostFuture<'a, T>>,
}

impl<T> PublicFuture<'_, T> {
    fn failure(&self) -> BoundaryFailure {
        self.lifecycle.poison();
        BoundaryFailure {
            origin: PanicOrigin::GantryInvariant,
        }
    }

    fn drop_future(&mut self) -> Result<(), BoundaryFailure> {
        let future = self.future.take();
        catch_unwind(AssertUnwindSafe(|| drop(future))).map_err(|_| self.failure())
    }
}

impl<T> Future for PublicFuture<'_, T> {
    type Output = Result<T, BoundaryFailure>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(future) = self.future.as_mut() else {
            return Poll::Ready(Err(self.failure()));
        };
        let polled = catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context)));
        match polled {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(output)) => match self.drop_future() {
                Ok(()) => Poll::Ready(Ok(output)),
                Err(failure) => Poll::Ready(Err(failure)),
            },
            Err(_) => {
                let failure = self.failure();
                let _ = self.drop_future();
                Poll::Ready(Err(failure))
            }
        }
    }
}

impl<T> Drop for PublicFuture<'_, T> {
    fn drop(&mut self) {
        let _ = self.drop_future();
    }
}

struct AdapterFuture<'a, T> {
    interpreter_id: u64,
    future: Option<HostFuture<'a, Result<T, BoundaryFailure>>>,
}

impl<T> Future for AdapterFuture<'_, T> {
    type Output = Result<T, BoundaryFailure>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let _extent = AdapterExtent::enter(self.interpreter_id);
        let future = self
            .future
            .as_mut()
            .unwrap_or_else(|| panic!("adapter future polled after completion"));
        match future.as_mut().poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.future = None;
                Poll::Ready(result)
            }
        }
    }
}

impl<T> Drop for AdapterFuture<'_, T> {
    fn drop(&mut self) {
        let _extent = AdapterExtent::enter(self.interpreter_id);
        self.future = None;
    }
}

fn error_for_shutdown(cause: ShutdownCause) -> LifecycleError {
    LifecycleError {
        code: match cause {
            ShutdownCause::Requested => LifecycleCode::InterpreterShuttingDown,
            ShutdownCause::Poisoned => LifecycleCode::InterpreterPoisoned,
        },
    }
}

fn lifecycle_snapshot(data: &LifecycleData) -> LifecycleSnapshot {
    match &data.state {
        LifecyclePhase::Running => LifecycleSnapshot {
            state: InterpreterState::Running,
            cause: None,
            durations: None,
            admitted_calls: data.admitted_calls,
            owned_activities: data.owned_activities,
            cohort: Arc::from([]),
        },
        LifecyclePhase::ShuttingDown(shutdown) => LifecycleSnapshot {
            state: InterpreterState::ShuttingDown,
            cause: Some(shutdown.cause),
            durations: Some(shutdown.durations),
            admitted_calls: data.admitted_calls,
            owned_activities: data.owned_activities,
            cohort: Arc::from(shutdown.cohort.iter().copied().collect::<Vec<_>>()),
        },
        LifecyclePhase::Terminated(report) => LifecycleSnapshot {
            state: InterpreterState::Terminated,
            cause: Some(report.cause),
            durations: Some(report.durations),
            admitted_calls: data.admitted_calls,
            owned_activities: data.owned_activities,
            cohort: Arc::from(
                report
                    .cohort
                    .iter()
                    .map(|execution| execution.execution_id)
                    .collect::<Vec<_>>(),
            ),
        },
    }
}

fn pending_executions(data: &LifecycleData) -> Vec<ProtocolIdentity> {
    let LifecyclePhase::ShuttingDown(shutdown) = &data.state else {
        return Vec::new();
    };
    shutdown
        .cohort
        .iter()
        .filter(|identity| {
            data.executions.get(identity).is_some_and(|execution| {
                execution.terminal.is_none() && !execution.run_failed_nondurably
            })
        })
        .copied()
        .collect()
}

fn register_waker(waiters: &mut Vec<Waker>, waker: &Waker) {
    if !waiters.iter().any(|candidate| candidate.will_wake(waker)) {
        waiters.push(waker.clone());
    }
}

fn register_execution_waker(waiters: &mut Vec<RegisteredWaiter>, waiter_id: u64, waker: &Waker) {
    if let Some(registered) = waiters
        .iter_mut()
        .find(|registered| registered.waiter_id == waiter_id)
    {
        registered.waker = waker.clone();
    } else {
        waiters.push(RegisteredWaiter {
            waiter_id,
            waker: waker.clone(),
        });
    }
}

fn take_all_waiters(data: &mut LifecycleData) -> Vec<Waker> {
    let mut waiters = std::mem::take(&mut data.progress_waiters);
    waiters.append(&mut data.shutdown_waiters);
    for execution in data.executions.values_mut() {
        waiters.extend(
            std::mem::take(&mut execution.waiters)
                .into_iter()
                .map(|registered| registered.waker),
        );
    }
    waiters
}

fn wake_all(waiters: Vec<Waker>) {
    for waiter in waiters {
        waiter.wake();
    }
}
