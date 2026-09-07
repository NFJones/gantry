//! Deliberate public composition of package admission, the shared machine, and lifecycle control.
//!
//! The facade owns orchestration only. Source analysis, machine transitions,
//! cancellation, waits, and shutdown remain in their existing subsystem owners.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

#[cfg(all(feature = "concurrent", feature = "durable"))]
use std::task::Wake;

#[cfg(all(feature = "concurrent", feature = "durable"))]
use std::collections::VecDeque;
#[cfg(all(feature = "durable", feature = "test-support"))]
use std::sync::Condvar;

use gantry_analysis::{DeclaredValueShape, DeclaredValueShapes};
use gantry_core::canonical_json::CanonicalJson;
use gantry_core::identity::ProtocolIdentity;
use gantry_core::numeric::{GantryFloat, GantryInt};
use gantry_core::portable::{
    CancellationReasonCategory, DeterministicEvaluationCode, IdentityKind,
    ResumeStartFailureCategory, RuntimeErrorCategory, StartFailureCategory,
};
use gantry_core::strict_json::{JsonLimits, JsonNode, JsonNodeId, StrictJsonDocument};
use gantry_core::value::{LogicalValue, OperationErrorValue, ValueLimits};
use gantry_host::contracts::{
    CancellationSignal, CancellationToken, DeadlineOutcome, DurationMicros, ExecutorAdapter,
    FreshIdentityAllocator, HookFactory, HostError, HostFuture, InclusiveJitterRange,
    IntegrationPreflight, OwnedTaskAbort, OwnedTaskCompletion, OwnedTaskFuture, OwnedTaskResult,
    RuntimeSessionService, UtcClock, deadline_race,
};
use gantry_host::event::{EventDeliveryRequest, EventDeliveryRuntime, EventSink};
use gantry_ir::TypeDescriptor;
use gantry_ir::generated::{OperationSiteKind, TaskControlSiteKind, TypeKind};
use gantry_observe::{
    ActivityBarrier, DeliveryError, DeliveryKernel, EventCompleter, EventCompletionError, SinkPlan,
    SinkSettlementStatus,
};
use gantry_runtime::{
    AbnormalCompletionHandler, AcceptedTranscriptResultV1, ActionOperationRequestV1, AdapterPoison,
    AdmissionClass, AdmissionExhaustion, AdmissionKind, CancellationReason, CancellationRecord,
    CapturedOperationRequestV1, CompletedExecutionEventV1, ConcurrentTaskStateV1,
    ExecutionCoordinator, ExecutionEventDraftV1, ExecutionEventError, ExecutionEventPipeline,
    ExecutionHandle, ExecutionSnapshot, FinalShutdownEventFailure, FinalShutdownEventSettlement,
    InterpolationInputV1, InterpreterConfiguration, InterpreterLifecycle, LifecycleError,
    LogicalSessionRegistryV1, Machine, MachineBuildError, MachineFailure, MachineLabel,
    MachineOutcome, MachineStep, ModelOperationRequestV1, ModelSessionUseV1, NamedInputV1,
    OperationLifecycle, OperationLifecycleError, OperationLifecycleFailureV1,
    OperationRequestHeaderV1, OperationRetryPolicyV1, OwnedEventDeliveryReservation,
    OwnedEventDeliveryReservationWait, PhysicalCompletionHandler, ProcessedHookOutcomeV1,
    RootSessionProvenanceV1, RuntimeCode, SessionCreationModeV1, SessionEstablisher,
    SessionEstablishmentV1, ShutdownAdmission, ShutdownCompletionError, ShutdownEventSummaryV1,
    ShutdownJournalOwnerRelease, ShutdownJournalOwnerReleaseStatus, ShutdownReport, SupervisedTask,
    SupervisedTaskDomain, SupervisionSignal, TaskContextV1, TaskHook, TaskHookError,
    TaskSessionContextV1, TaskStateError, TranscriptResultKindV1, TranscriptTurnV1,
    TypedActionArgumentV1, catch_integration, contain_integration_future, machine_lifecycle_event,
    shutdown_event,
};
#[cfg(feature = "concurrent")]
use gantry_runtime::{
    ConcurrentTaskStatusV1, ExecutionBudget, JoinResolutionV1, JoinStartV1, MachineSpawnSuspension,
    TaskCreationRequestV1, TaskOwnershipChangedV1, concurrent_detach_event, concurrent_join_event,
    concurrent_spawn_event, concurrent_terminal_event,
};

#[cfg(feature = "durable")]
use gantry_host::journal::JournalStorage;
#[cfg(all(feature = "concurrent", feature = "durable"))]
use gantry_runtime::AdmissionReservation;
#[cfg(feature = "durable")]
use gantry_runtime::{
    DurableCommitCutV1, DurableDeliveryRecoveryV1, DurableEventBarrierV1,
    DurableOperationEvidenceV1, DurableOperationRecoveryV1, OperationResultEventKindV1,
    RecoveredDurableEventsV1, operation_completion_event, operation_dispatch_event,
    operation_result_event,
};

use crate::start::{PreparedExecutionStart, StartExecutionCoordinator};
use crate::{
    AnalyzePackageCoordinator, AnalyzePackageResult, StartExecutionAccepted, StartExecutionFailure,
    StartExecutionRequest, StartExecutionResult,
};

#[cfg(feature = "durable")]
use crate::durable_start::{
    DurableRegistrationEvent, DurableStartExecutionCoordinator, PreparedDurableRecovery,
    PreparedDurableResume,
};
#[cfg(feature = "durable")]
use crate::{
    DurableResumeExecutionFailure, DurableResumeExecutionRequest, DurableResumeExecutionResult,
    DurableRunFailure, DurableStartExecutionFailure, DurableStartExecutionRequest,
    DurableStartExecutionResult,
};

/// Executor-neutral interpreter facade over injected host integrations.
///
/// The configured executor owns physical polling while Gantry owns every
/// accepted root, resumed driver, source child, and control-plane task through
/// semantic and physical settlement. Clones are public facade owners; dropping
/// the last clone without first awaiting [`Self::shutdown`] begins bounded
/// unclean cleanup, rejects new work, signals cancellation, and requests abort
/// without waiting or claiming that cleanup completed.
///
/// Start and resume operations return observation/control capabilities. There
/// is no supported API for manually polling the underlying machine.
pub struct Interpreter {
    inner: Arc<InterpreterInner>,
    external_owner: bool,
}

struct InterpreterInner {
    external_owners: AtomicUsize,
    shutdown_started: AtomicBool,
    shutdown: Arc<SharedShutdown>,
    nondurable_executions: NondurableExecutionRegistry,
    #[cfg(all(feature = "concurrent", feature = "test-support"))]
    nondurable_before_child_executor_submit: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(all(feature = "concurrent", feature = "test-support"))]
    nondurable_cancel_before_child_submit: Mutex<Option<CancellationSignal>>,
    #[cfg(all(feature = "concurrent", feature = "test-support"))]
    nondurable_cancel_after_child_resolution: Mutex<Option<CancellationSignal>>,
    #[cfg(all(feature = "concurrent", feature = "durable", feature = "test-support"))]
    durable_cancel_before_child_submit: Mutex<Option<CancellationReason>>,
    #[cfg(all(feature = "concurrent", feature = "durable", feature = "test-support"))]
    durable_cancel_after_child_submit: Mutex<Option<CancellationReason>>,
    #[cfg(all(feature = "concurrent", feature = "durable", feature = "test-support"))]
    durable_cancel_after_child_session_establishment: Mutex<Option<CancellationReason>>,
    #[cfg(all(feature = "concurrent", feature = "durable", feature = "test-support"))]
    durable_cancelled_child_continuations: AtomicUsize,
    #[cfg(feature = "durable")]
    durable_executions: DurableExecutionRegistry,
    #[cfg(all(feature = "durable", feature = "test-support"))]
    durable_handoff_test_gate: Mutex<Option<Arc<DurableHandoffTestGate>>>,
    configuration: InterpreterConfiguration,
    lifecycle: InterpreterLifecycle,
    allocator: FreshIdentityAllocator,
    blocking_work_poison: AdapterPoison,
    clock: Arc<dyn UtcClock>,
    preflight: Arc<dyn IntegrationPreflight>,
    session_establisher: SessionEstablisher,
    hook_factory: Arc<dyn HookFactory>,
    event_delivery_runtime: Arc<dyn EventDeliveryRuntime>,
    event_delivery: SinkPlan,
}

#[derive(Default)]
struct NondurableExecutionRegistry {
    state: Mutex<NondurableExecutionRegistryState>,
}

#[derive(Default)]
struct NondurableExecutionRegistryState {
    executions: BTreeMap<ProtocolIdentity, NondurableExecutionRegistration>,
    waiters: BTreeMap<ProtocolIdentity, Vec<Waker>>,
}

enum NondurableExecutionRegistration {
    Pending {
        coordinator: ExecutionCoordinator,
        workflow: gantry_ir::CanonicalPath,
    },
    Owned(Arc<NondurableExecutionOwner>),
}

struct NondurableExecutionOwner {
    coordinator: ExecutionCoordinator,
    workflow: gantry_ir::CanonicalPath,
    handle: ExecutionHandle,
    cancellation: Arc<SharedNondurableCancellation>,
}

#[derive(Default)]
struct SharedNondurableCancellation {
    state: Mutex<SharedNondurableCancellationState>,
}

#[derive(Default)]
struct SharedNondurableCancellationState {
    requested_reason: Option<CancellationReason>,
    started: bool,
    control_active: bool,
    result: Option<Result<CancellationRecord, CancelExecutionError>>,
    aborts: Vec<Arc<[SupervisedTask]>>,
    waiters: Vec<Waker>,
}

struct ExecutorEventDeliveryRuntime {
    executor: Arc<dyn ExecutorAdapter>,
}

impl EventDeliveryRuntime for ExecutorEventDeliveryRuntime {
    fn deliver_with_timeout<'a>(
        &'a self,
        sink: &'a dyn EventSink,
        request: EventDeliveryRequest,
        timeout_us: u64,
    ) -> HostFuture<'a, Result<gantry_core::portable::DeliveryOutcome, HostError>> {
        let timeout = DurationMicros::new(timeout_us)
            .unwrap_or_else(|| unreachable!("validated event timeout is portable"));
        Box::pin(async move {
            match deadline_race(&*self.executor, sink.deliver(request), timeout, None).await {
                DeadlineOutcome::Completed(result) => result,
                DeadlineOutcome::TimedOut => Ok(gantry_core::portable::DeliveryOutcome::Retriable),
                DeadlineOutcome::Failed(error) => Err(error),
                DeadlineOutcome::Cancelled => Err(HostError {
                    code: Arc::from("event-delivery-cancelled"),
                    protected_diagnostic: None,
                }),
            }
        })
    }

    fn sleep<'a>(&'a self, delay_us: u64) -> HostFuture<'a, Result<(), HostError>> {
        let delay = DurationMicros::new(delay_us)
            .unwrap_or_else(|| unreachable!("validated event delay is portable"));
        self.executor.sleep(delay)
    }

    fn sample_full_jitter(&self, ceiling_us: u64) -> Result<u64, HostError> {
        let range = InclusiveJitterRange::new(0, ceiling_us)
            .unwrap_or_else(|| unreachable!("event jitter range begins at zero"));
        self.executor.sample_inclusive(range)
    }
}

impl NondurableExecutionRegistry {
    fn mark(
        &self,
        execution_id: ProtocolIdentity,
        coordinator: ExecutionCoordinator,
        workflow: gantry_ir::CanonicalPath,
    ) {
        let mut state = lock_shutdown(&self.state);
        state
            .executions
            .entry(execution_id)
            .or_insert(NondurableExecutionRegistration::Pending {
                coordinator,
                workflow,
            });
    }

    fn publish(&self, execution_id: ProtocolIdentity, handle: ExecutionHandle) {
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            let Some(NondurableExecutionRegistration::Pending {
                coordinator,
                workflow,
            }) = state.executions.remove(&execution_id)
            else {
                return;
            };
            state.executions.insert(
                execution_id,
                NondurableExecutionRegistration::Owned(Arc::new(NondurableExecutionOwner {
                    coordinator,
                    workflow,
                    handle,
                    cancellation: Arc::new(SharedNondurableCancellation::default()),
                })),
            );
            state.waiters.remove(&execution_id).unwrap_or_default()
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn abandon(&self, execution_id: ProtocolIdentity) {
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            state.executions.remove(&execution_id);
            state.waiters.remove(&execution_id).unwrap_or_default()
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn coordinator(&self, execution_id: ProtocolIdentity) -> Option<ExecutionCoordinator> {
        match lock_shutdown(&self.state).executions.get(&execution_id) {
            Some(NondurableExecutionRegistration::Pending { coordinator, .. }) => {
                Some(coordinator.clone())
            }
            Some(NondurableExecutionRegistration::Owned(owner)) => Some(owner.coordinator.clone()),
            None => None,
        }
    }

    fn cancellation_control_is_active(&self) -> bool {
        lock_shutdown(&self.state)
            .executions
            .values()
            .any(|registration| match registration {
                NondurableExecutionRegistration::Pending { .. } => false,
                NondurableExecutionRegistration::Owned(owner) => {
                    owner.cancellation.control_is_active()
                }
            })
    }

    fn requested_executions(&self, execution_ids: &[ProtocolIdentity]) -> Vec<ProtocolIdentity> {
        let state = lock_shutdown(&self.state);
        execution_ids
            .iter()
            .copied()
            .filter(|execution_id| {
                matches!(
                    state.executions.get(execution_id),
                    Some(NondurableExecutionRegistration::Owned(owner))
                        if owner.cancellation.is_requested()
                )
            })
            .collect()
    }

    fn poll_cancellation_requested(
        &self,
        execution_ids: &[ProtocolIdentity],
        context: &mut Context<'_>,
    ) -> Poll<()> {
        let owners = {
            let mut state = lock_shutdown(&self.state);
            let mut owners = Vec::new();
            for execution_id in execution_ids {
                match state.executions.get(execution_id) {
                    Some(NondurableExecutionRegistration::Owned(owner)) => {
                        owners.push(Arc::clone(owner));
                    }
                    Some(NondurableExecutionRegistration::Pending { .. }) => {
                        let waiters = state.waiters.entry(*execution_id).or_default();
                        if !waiters
                            .iter()
                            .any(|waiter| waiter.will_wake(context.waker()))
                        {
                            waiters.push(context.waker().clone());
                        }
                    }
                    None => {}
                }
            }
            owners
        };
        if owners
            .iter()
            .any(|owner| owner.cancellation.poll_requested(context).is_ready())
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn confirmed_stopped_abort_ids(&self, execution_ids: &[ProtocolIdentity]) -> Vec<u64> {
        let state = lock_shutdown(&self.state);
        execution_ids
            .iter()
            .filter_map(|execution_id| match state.executions.get(execution_id) {
                Some(NondurableExecutionRegistration::Owned(owner)) => Some(owner),
                Some(NondurableExecutionRegistration::Pending { .. }) | None => None,
            })
            .flat_map(|owner| owner.cancellation.confirmed_stopped_abort_ids())
            .collect()
    }

    async fn owner(&self, execution_id: ProtocolIdentity) -> Option<Arc<NondurableExecutionOwner>> {
        std::future::poll_fn(|context| {
            let mut state = lock_shutdown(&self.state);
            match state.executions.get(&execution_id) {
                Some(NondurableExecutionRegistration::Owned(owner)) => {
                    Poll::Ready(Some(Arc::clone(owner)))
                }
                Some(NondurableExecutionRegistration::Pending { .. }) => {
                    let waiters = state.waiters.entry(execution_id).or_default();
                    if !waiters
                        .iter()
                        .any(|waiter| waiter.will_wake(context.waker()))
                    {
                        waiters.push(context.waker().clone());
                    }
                    Poll::Pending
                }
                None => Poll::Ready(None),
            }
        })
        .await
    }
}

impl SharedNondurableCancellation {
    fn request(&self, reason: CancellationReason) {
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            if state.requested_reason.is_some() {
                return;
            }
            state.requested_reason = Some(reason);
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn is_requested(&self) -> bool {
        lock_shutdown(&self.state).requested_reason.is_some()
    }

    fn poll_requested(&self, context: &mut Context<'_>) -> Poll<()> {
        let mut state = lock_shutdown(&self.state);
        if state.requested_reason.is_some() {
            return Poll::Ready(());
        }
        if !state
            .waiters
            .iter()
            .any(|waiter| waiter.will_wake(context.waker()))
        {
            state.waiters.push(context.waker().clone());
        }
        Poll::Pending
    }

    fn claim(&self) -> bool {
        let mut state = lock_shutdown(&self.state);
        if state.started {
            false
        } else {
            state.started = true;
            true
        }
    }

    fn release_claim(&self) {
        let mut state = lock_shutdown(&self.state);
        if state.result.is_none() {
            state.started = false;
        }
    }

    fn mark_control_active(&self) {
        lock_shutdown(&self.state).control_active = true;
    }

    fn mark_physically_completed(&self) {
        lock_shutdown(&self.state).control_active = false;
    }

    fn control_is_active(&self) -> bool {
        let state = lock_shutdown(&self.state);
        state.control_active || (state.started && state.result.is_none())
    }

    fn requested_reason(&self) -> Option<CancellationReason> {
        lock_shutdown(&self.state).requested_reason.clone()
    }

    fn retain_aborts(&self, aborts: Arc<[SupervisedTask]>) {
        if !aborts.is_empty() {
            lock_shutdown(&self.state).aborts.push(aborts);
        }
    }

    fn confirmed_stopped_abort_ids(&self) -> Vec<u64> {
        lock_shutdown(&self.state)
            .aborts
            .iter()
            .flat_map(|tasks| tasks.iter())
            .filter(|task| task.snapshot().abort_result == Some(OwnedTaskAbort::Stopped))
            .map(SupervisedTask::id)
            .collect()
    }

    fn publish(&self, result: Result<CancellationRecord, CancelExecutionError>) {
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            if state.result.is_some() {
                return;
            }
            state.result = Some(result);
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn poll(
        &self,
        context: &mut Context<'_>,
    ) -> Poll<Result<CancellationRecord, CancelExecutionError>> {
        let mut state = lock_shutdown(&self.state);
        if let Some(result) = &state.result {
            return Poll::Ready(result.clone());
        }
        if !state
            .waiters
            .iter()
            .any(|waiter| waiter.will_wake(context.waker()))
        {
            state.waiters.push(context.waker().clone());
        }
        Poll::Pending
    }
}

#[cfg(feature = "durable")]
#[derive(Default)]
struct DurableExecutionRegistry {
    state: Mutex<DurableExecutionRegistryState>,
}

#[cfg(feature = "durable")]
#[derive(Default)]
struct DurableExecutionRegistryState {
    executions: BTreeMap<ProtocolIdentity, DurableExecutionRegistration>,
    waiters: BTreeMap<ProtocolIdentity, Vec<Waker>>,
    shutdown_fenced: bool,
}

#[cfg(feature = "durable")]
enum DurableExecutionRegistration {
    Pending,
    Owned(Arc<crate::DurableOwnedExecution>),
}

#[cfg(feature = "durable")]
struct DurableRootSubmissionClaim<'a> {
    _state: MutexGuard<'a, DurableExecutionRegistryState>,
}

/// Test-support gate that pauses a durable start after lifecycle acceptance
/// and before its durable owner is published to the interpreter registry.
#[cfg(all(feature = "durable", feature = "test-support"))]
#[doc(hidden)]
#[derive(Default)]
pub struct DurableHandoffTestGate {
    state: Mutex<DurableHandoffTestGateState>,
    changed: Condvar,
}

#[cfg(all(feature = "durable", feature = "test-support"))]
#[derive(Default)]
struct DurableHandoffTestGateState {
    accepted: Option<ExecutionHandle>,
    released: bool,
}

#[cfg(all(feature = "durable", feature = "test-support"))]
impl DurableHandoffTestGate {
    /// Waits until lifecycle acceptance has completed and returns its handle.
    #[must_use]
    pub fn wait_until_accepted(&self) -> ExecutionHandle {
        let mut state = lock_shutdown(&self.state);
        while state.accepted.is_none() {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        state
            .accepted
            .clone()
            .unwrap_or_else(|| unreachable!("accepted handoff gate retains its handle"))
    }

    /// Releases the paused durable owner publication.
    pub fn release(&self) {
        let mut state = lock_shutdown(&self.state);
        state.released = true;
        self.changed.notify_all();
    }

    fn pause(&self, handle: ExecutionHandle) {
        let mut state = lock_shutdown(&self.state);
        state.accepted = Some(handle);
        self.changed.notify_all();
        while !state.released {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

#[cfg(feature = "durable")]
impl DurableExecutionRegistry {
    fn fence_root_submission(&self) {
        lock_shutdown(&self.state).shutdown_fenced = true;
    }

    fn mark(&self, execution_id: ProtocolIdentity) {
        let mut state = lock_shutdown(&self.state);
        state
            .executions
            .entry(execution_id)
            .or_insert(DurableExecutionRegistration::Pending);
    }

    fn claim_root_submission(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Option<DurableRootSubmissionClaim<'_>> {
        let state = lock_shutdown(&self.state);
        if state.shutdown_fenced
            || !matches!(
                state.executions.get(&execution_id),
                Some(DurableExecutionRegistration::Owned(_))
            )
        {
            return None;
        }
        Some(DurableRootSubmissionClaim { _state: state })
    }

    fn all_owned(&self) -> Vec<Arc<crate::DurableOwnedExecution>> {
        lock_shutdown(&self.state)
            .executions
            .values()
            .filter_map(|registration| match registration {
                DurableExecutionRegistration::Owned(owner) => Some(Arc::clone(owner)),
                DurableExecutionRegistration::Pending => None,
            })
            .collect()
    }

    fn contains(&self, execution_id: ProtocolIdentity) -> bool {
        lock_shutdown(&self.state)
            .executions
            .contains_key(&execution_id)
    }

    fn publish(&self, owner: Arc<crate::DurableOwnedExecution>) {
        let execution_id = owner.execution_id();
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            state
                .executions
                .insert(execution_id, DurableExecutionRegistration::Owned(owner));
            state.waiters.remove(&execution_id).unwrap_or_default()
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn abandon(&self, execution_id: ProtocolIdentity) {
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            state.executions.remove(&execution_id);
            state.waiters.remove(&execution_id).unwrap_or_default()
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    async fn owner(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Option<Arc<crate::DurableOwnedExecution>> {
        std::future::poll_fn(|context| {
            let mut state = lock_shutdown(&self.state);
            match state.executions.get(&execution_id) {
                Some(DurableExecutionRegistration::Owned(owner)) => {
                    Poll::Ready(Some(Arc::clone(owner)))
                }
                Some(DurableExecutionRegistration::Pending) => {
                    let waiters = state.waiters.entry(execution_id).or_default();
                    if !waiters
                        .iter()
                        .any(|waiter| waiter.will_wake(context.waker()))
                    {
                        waiters.push(context.waker().clone());
                    }
                    Poll::Pending
                }
                None => Poll::Ready(None),
            }
        })
        .await
    }
}

#[cfg(feature = "durable")]
struct OwnedDurableResumeRequest {
    journal_id: gantry_host::journal::JournalId,
    protocol_selection: gantry_core::protocol::ProtocolSelection,
    candidate_package_root: Option<PathBuf>,
    expected_execution_id: Option<ProtocolIdentity>,
    event_delivery: Option<gantry_observe::SinkPlan>,
}

#[cfg(feature = "durable")]
impl OwnedDurableResumeRequest {
    fn borrowed(&self) -> DurableResumeExecutionRequest<'_> {
        DurableResumeExecutionRequest {
            journal_id: self.journal_id.clone(),
            protocol_selection: &self.protocol_selection,
            candidate_package_root: self.candidate_package_root.as_deref(),
            expected_execution_id: self.expected_execution_id,
            event_delivery: self.event_delivery.as_ref(),
        }
    }
}

#[cfg(feature = "durable")]
struct RecoveredRootDriver {
    coordinator: ExecutionCoordinator,
    task_id: ProtocolIdentity,
    create_request: gantry_host::contracts::HostRequest,
    operations: DurableOperationContext,
    #[cfg(feature = "concurrent")]
    program: Arc<gantry_ir::MachineProgram>,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    root_supervision: Arc<Mutex<Option<SupervisedTask>>>,
}

/// Privately owned machine graph shared by independent durable task futures.
#[cfg(all(feature = "concurrent", feature = "durable"))]
struct DurableMachineGraph {
    foreground: Machine,
    children: BTreeMap<ProtocolIdentity, Machine>,
    frontier: (ProtocolIdentity, u64),
    next_event_sequence: BTreeMap<ProtocolIdentity, u64>,
}

/// Wake-driven exclusive access to one durable machine graph.
#[cfg(all(feature = "concurrent", feature = "durable"))]
struct SharedDurableMachineGraph {
    state: Mutex<SharedDurableMachineGraphState>,
    owner: std::sync::Weak<crate::DurableOwnedExecution>,
    program: Arc<gantry_ir::MachineProgram>,
    operations: DurableOperationContext,
}

/// Accepted owners installed behind every pre-submitted recovered graph gate.
#[cfg(all(feature = "concurrent", feature = "durable"))]
#[derive(Clone)]
struct RecoveredDurableGraphRuntime {
    graph: Arc<SharedDurableMachineGraph>,
    owner: Arc<crate::DurableOwnedExecution>,
    coordinator: ExecutionCoordinator,
    program: Arc<gantry_ir::MachineProgram>,
    operations: DurableOperationContext,
    drive_recovered_root: bool,
}

/// One reconstructed task-hook context retained until its recovered gate opens.
#[cfg(all(feature = "concurrent", feature = "durable"))]
struct RecoveredDurableTaskDriver {
    task_id: ProtocolIdentity,
    workflow: Option<gantry_ir::CanonicalPath>,
    create_request: gantry_host::contracts::HostRequest,
    model_session_occurrence: u64,
    submission: Option<RecoveredDurableTaskSubmission>,
}

/// One committed task creation whose replacement driver must publish submission resolution.
#[cfg(all(feature = "concurrent", feature = "durable"))]
struct RecoveredDurableTaskSubmission {
    parent_task_id: ProtocolIdentity,
    created: gantry_runtime::TaskCreationV1,
    suspension: MachineSpawnSuspension,
    machine: Machine,
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
struct SharedDurableMachineGraphState {
    graph: Option<DurableMachineGraph>,
    failed: bool,
    finalization_requested: bool,
    delivery_enabled: bool,
    live_delivery_queued: bool,
    live_delivery_requested_through: u64,
    live_delivery_completed_through: u64,
    cancellation_drains: BTreeSet<ProtocolIdentity>,
    control_started: bool,
    control_reservation: Option<AdmissionReservation>,
    tasks: BTreeMap<ProtocolIdentity, SupervisedTask>,
    recovered_submissions: BTreeMap<ProtocolIdentity, ProtocolIdentity>,
    operation_recoveries: BTreeMap<ProtocolIdentity, DurableOperationRecoveryV1>,
    commands: VecDeque<DurableGraphControlCommand>,
    control_waker: Option<Waker>,
    waiters: Vec<Waker>,
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
enum DurableGraphControlCommand {
    DeliverCommittedEvents,
    DeliverCommittedEventsFinished {
        result: Box<Result<(DurableMachineGraphLease, DurableEventBarrierV1), DurableRunFailure>>,
    },
    SettleAbnormalChild {
        task_id: ProtocolIdentity,
        outcome: MachineOutcome,
    },
    DrainCancellation {
        task_id: ProtocolIdentity,
    },
    Complete,
    FinishRecoveredTerminal,
    Fail(DurableRunFailure),
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
enum DurableTaskControlOutcome {
    Continue,
    Finished,
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
type DurableStagedTaskControl = (Option<JoinStartV1>, Option<TaskOwnershipChangedV1>);

/// One allocation-bounded wake-driven owner used only when reserved submission rejects.
#[cfg(all(feature = "concurrent", feature = "durable"))]
struct DurableGraphControlFallback {
    state: Mutex<DurableGraphControlFallbackState>,
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
struct DurableGraphControlFallbackState {
    future: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
    polling: bool,
    queued: bool,
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
impl DurableGraphControlFallback {
    fn start(future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) {
        let fallback = Arc::new(Self {
            state: Mutex::new(DurableGraphControlFallbackState {
                future: Some(future),
                polling: false,
                queued: false,
            }),
        });
        Self::schedule(&fallback);
    }

    fn schedule(this: &Arc<Self>) {
        let should_poll = {
            let mut state = lock_shutdown(&this.state);
            if state.polling {
                state.queued = true;
                false
            } else if state.future.is_some() {
                state.polling = true;
                state.queued = true;
                true
            } else {
                false
            }
        };
        if should_poll {
            Self::drain(this);
        }
    }

    fn drain(this: &Arc<Self>) {
        loop {
            let mut future = {
                let mut state = lock_shutdown(&this.state);
                if !state.queued {
                    state.polling = false;
                    return;
                }
                state.queued = false;
                state
                    .future
                    .take()
                    .unwrap_or_else(|| unreachable!("polling fallback retains its future"))
            };
            let waker = Waker::from(Arc::clone(this));
            let mut context = Context::from_waker(&waker);
            match future.as_mut().poll(&mut context) {
                Poll::Ready(()) => {
                    let mut state = lock_shutdown(&this.state);
                    state.polling = false;
                    state.queued = false;
                    return;
                }
                Poll::Pending => {
                    let mut state = lock_shutdown(&this.state);
                    state.future = Some(future);
                    if !state.queued {
                        state.polling = false;
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
impl Wake for DurableGraphControlFallback {
    fn wake(self: Arc<Self>) {
        Self::schedule(&self);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        Self::schedule(self);
    }
}

/// RAII graph lease restored to the wake-driven owner on every normal return.
#[cfg(all(feature = "concurrent", feature = "durable"))]
struct DurableMachineGraphLease {
    shared: Arc<SharedDurableMachineGraph>,
    graph: Option<DurableMachineGraph>,
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
impl SharedDurableMachineGraph {
    #[allow(clippy::too_many_arguments)]
    fn new(
        graph: DurableMachineGraph,
        initial_delivery_pending: bool,
        root_task_id: ProtocolIdentity,
        root_supervision: SupervisedTask,
        control_reservation: AdmissionReservation,
        owner: &Arc<crate::DurableOwnedExecution>,
        program: Arc<gantry_ir::MachineProgram>,
        operations: DurableOperationContext,
    ) -> Arc<Self> {
        let initial_frontier = graph.frontier.1;
        Arc::new(Self {
            state: Mutex::new(SharedDurableMachineGraphState {
                graph: Some(graph),
                failed: false,
                finalization_requested: false,
                delivery_enabled: initial_delivery_pending,
                live_delivery_queued: initial_delivery_pending,
                live_delivery_requested_through: initial_frontier,
                live_delivery_completed_through: if initial_delivery_pending {
                    0
                } else {
                    initial_frontier
                },
                cancellation_drains: BTreeSet::new(),
                control_started: false,
                control_reservation: Some(control_reservation),
                tasks: BTreeMap::from([(root_task_id, root_supervision)]),
                recovered_submissions: BTreeMap::new(),
                operation_recoveries: BTreeMap::new(),
                commands: if initial_delivery_pending {
                    VecDeque::from([DurableGraphControlCommand::DeliverCommittedEvents])
                } else {
                    VecDeque::new()
                },
                control_waker: None,
                waiters: Vec::new(),
            }),
            owner: Arc::downgrade(owner),
            program,
            operations,
        })
    }

    /// Installs a recovered graph whose control activity is already submitted and gated.
    #[allow(clippy::too_many_arguments)]
    fn new_recovered(
        graph: DurableMachineGraph,
        delivery_enabled: bool,
        initial_delivery_pending: bool,
        terminal: bool,
        tasks: BTreeMap<ProtocolIdentity, SupervisedTask>,
        recovered_submissions: BTreeMap<ProtocolIdentity, ProtocolIdentity>,
        operation_recoveries: BTreeMap<ProtocolIdentity, DurableOperationRecoveryV1>,
        owner: &Arc<crate::DurableOwnedExecution>,
        program: Arc<gantry_ir::MachineProgram>,
        operations: DurableOperationContext,
    ) -> Arc<Self> {
        let initial_frontier = graph.frontier.1;
        let mut commands = VecDeque::new();
        if initial_delivery_pending {
            commands.push_back(DurableGraphControlCommand::DeliverCommittedEvents);
        }
        if terminal {
            commands.push_back(DurableGraphControlCommand::FinishRecoveredTerminal);
        }
        Arc::new(Self {
            state: Mutex::new(SharedDurableMachineGraphState {
                graph: Some(graph),
                failed: false,
                finalization_requested: terminal,
                delivery_enabled,
                live_delivery_queued: initial_delivery_pending,
                live_delivery_requested_through: initial_frontier,
                live_delivery_completed_through: if initial_delivery_pending {
                    0
                } else {
                    initial_frontier
                },
                cancellation_drains: BTreeSet::new(),
                control_started: true,
                control_reservation: None,
                tasks,
                recovered_submissions,
                operation_recoveries,
                commands,
                control_waker: None,
                waiters: Vec::new(),
            }),
            owner: Arc::downgrade(owner),
            program,
            operations,
        })
    }

    async fn acquire(self: &Arc<Self>) -> Option<DurableMachineGraphLease> {
        std::future::poll_fn(|context| {
            let mut state = lock_shutdown(&self.state);
            if state.failed {
                return Poll::Ready(None);
            }
            if let Some(graph) = state.graph.take() {
                return Poll::Ready(Some(DurableMachineGraphLease {
                    shared: Arc::clone(self),
                    graph: Some(graph),
                }));
            }
            if !state
                .waiters
                .iter()
                .any(|waiter| waiter.will_wake(context.waker()))
            {
                state.waiters.push(context.waker().clone());
            }
            Poll::Pending
        })
        .await
    }

    fn request_failure(&self, failure: DurableRunFailure) {
        let (control_waker, waiters) = {
            let mut state = lock_shutdown(&self.state);
            if state.failed {
                return;
            }
            state.failed = true;
            state.finalization_requested = true;
            state
                .commands
                .push_back(DurableGraphControlCommand::Fail(failure));
            (
                state.control_waker.take(),
                std::mem::take(&mut state.waiters),
            )
        };
        if let Some(waker) = control_waker {
            waker.wake();
        }
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn require_failure_finalization(&self, failure: DurableRunFailure) {
        let (control_waker, waiters) = {
            let mut state = lock_shutdown(&self.state);
            if !state.failed {
                state.failed = true;
                state.finalization_requested = true;
                state.commands.clear();
                state
                    .commands
                    .push_back(DurableGraphControlCommand::Fail(failure));
            }
            (
                state.control_waker.take(),
                std::mem::take(&mut state.waiters),
            )
        };
        if let Some(waker) = control_waker {
            waker.wake();
        }
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn request_abnormal_child_settlement(
        &self,
        task_id: ProtocolIdentity,
        outcome: MachineOutcome,
    ) {
        let control_waker = {
            let mut state = lock_shutdown(&self.state);
            if state.failed || state.finalization_requested {
                return;
            }
            state
                .commands
                .push_back(DurableGraphControlCommand::SettleAbnormalChild { task_id, outcome });
            state.control_waker.take()
        };
        if let Some(waker) = control_waker {
            waker.wake();
        }
    }

    fn request_cancellation_drain(&self, task_id: ProtocolIdentity) {
        let control_waker = {
            let mut state = lock_shutdown(&self.state);
            if state.failed || state.finalization_requested {
                return;
            }
            if !state.cancellation_drains.insert(task_id) {
                return;
            }
            state
                .commands
                .push_back(DurableGraphControlCommand::DrainCancellation { task_id });
            state.control_waker.take()
        };
        if let Some(waker) = control_waker {
            waker.wake();
        }
    }

    fn complete_live_delivery(&self, frontier: u64) {
        let (control_waker, waiters) = {
            let mut state = lock_shutdown(&self.state);
            state.live_delivery_completed_through =
                state.live_delivery_completed_through.max(frontier);
            state.live_delivery_queued = false;
            if state.failed
                || state.finalization_requested
                || state.live_delivery_requested_through <= state.live_delivery_completed_through
            {
                (None, std::mem::take(&mut state.waiters))
            } else {
                state.live_delivery_queued = true;
                state
                    .commands
                    .push_back(DurableGraphControlCommand::DeliverCommittedEvents);
                (
                    state.control_waker.take(),
                    std::mem::take(&mut state.waiters),
                )
            }
        };
        if let Some(waker) = control_waker {
            waker.wake();
        }
        for waiter in waiters {
            waiter.wake();
        }
    }

    async fn wait_for_live_delivery(&self, frontier: u64) -> bool {
        std::future::poll_fn(|context| {
            let mut state = lock_shutdown(&self.state);
            if state.live_delivery_completed_through >= frontier {
                Poll::Ready(true)
            } else if state.failed {
                Poll::Ready(false)
            } else {
                if !state
                    .waiters
                    .iter()
                    .any(|waiter| waiter.will_wake(context.waker()))
                {
                    state.waiters.push(context.waker().clone());
                }
                Poll::Pending
            }
        })
        .await
    }

    fn request_completion(&self) {
        let control_waker = {
            let mut state = lock_shutdown(&self.state);
            if state.failed || state.finalization_requested {
                return;
            }
            state.finalization_requested = true;
            state
                .commands
                .push_back(DurableGraphControlCommand::Complete);
            state.control_waker.take()
        };
        if let Some(waker) = control_waker {
            waker.wake();
        }
    }

    async fn next_control_command(
        &self,
        lifecycle: &InterpreterLifecycle,
    ) -> (
        DurableGraphControlCommand,
        Option<OwnedEventDeliveryReservation>,
    ) {
        let mut delivery_wait: Option<OwnedEventDeliveryReservationWait> = None;
        std::future::poll_fn(|context| {
            let mut state = lock_shutdown(&self.state);
            if let Some(position) = state.commands.iter().position(|command| {
                matches!(
                    command,
                    DurableGraphControlCommand::DeliverCommittedEventsFinished { .. }
                )
            }) {
                let command = state
                    .commands
                    .remove(position)
                    .unwrap_or_else(|| unreachable!("located delivery result remains queued"));
                return Poll::Ready((command, None));
            }
            if matches!(
                state.commands.front(),
                Some(DurableGraphControlCommand::DeliverCommittedEvents)
            ) {
                let wait = delivery_wait
                    .get_or_insert_with(|| lifecycle.owned_event_delivery_reservation());
                if let Poll::Ready(reservation) = Pin::new(wait).poll(context) {
                    let command = state
                        .commands
                        .pop_front()
                        .unwrap_or_else(|| unreachable!("delivery command remains queued"));
                    return Poll::Ready((command, Some(reservation)));
                }
            }
            if matches!(
                state.commands.front(),
                Some(DurableGraphControlCommand::DeliverCommittedEvents)
            ) {
                if let Some(position) = state.commands.iter().position(|command| {
                    matches!(
                        command,
                        DurableGraphControlCommand::DrainCancellation { .. }
                            | DurableGraphControlCommand::Fail(_)
                    )
                }) {
                    let command = state
                        .commands
                        .remove(position)
                        .unwrap_or_else(|| unreachable!("located cleanup command remains queued"));
                    return Poll::Ready((command, None));
                }
                state.control_waker = Some(context.waker().clone());
                return Poll::Pending;
            }
            if state.live_delivery_queued {
                if let Some(position) = state.commands.iter().position(|command| {
                    matches!(
                        command,
                        DurableGraphControlCommand::DrainCancellation { .. }
                            | DurableGraphControlCommand::Fail(_)
                    )
                }) {
                    let command = state
                        .commands
                        .remove(position)
                        .unwrap_or_else(|| unreachable!("located cleanup command remains queued"));
                    return Poll::Ready((command, None));
                }
                state.control_waker = Some(context.waker().clone());
                return Poll::Pending;
            }
            if let Some(position) = state.commands.iter().position(|command| {
                !matches!(command, DurableGraphControlCommand::DeliverCommittedEvents)
            }) {
                let command = state
                    .commands
                    .remove(position)
                    .unwrap_or_else(|| unreachable!("located control command remains queued"));
                return Poll::Ready((command, None));
            }
            state.control_waker = Some(context.waker().clone());
            Poll::Pending
        })
        .await
    }

    fn finish_live_delivery(
        &self,
        result: Result<(DurableMachineGraphLease, DurableEventBarrierV1), DurableRunFailure>,
    ) {
        let control_waker = {
            let mut state = lock_shutdown(&self.state);
            state
                .commands
                .push_back(DurableGraphControlCommand::DeliverCommittedEventsFinished {
                    result: Box::new(result),
                });
            state.control_waker.take()
        };
        if let Some(waker) = control_waker {
            waker.wake();
        }
    }

    fn register_task(&self, task_id: ProtocolIdentity, task: SupervisedTask) {
        let mut state = lock_shutdown(&self.state);
        if state.tasks.insert(task_id, task).is_some() {
            unreachable!("one supervised handle exists per durable graph task");
        }
    }

    async fn wait_for_recovered_submission(&self, parent_task_id: ProtocolIdentity) -> bool {
        std::future::poll_fn(|context| {
            let mut state = lock_shutdown(&self.state);
            if state.failed {
                return Poll::Ready(false);
            }
            if !state.recovered_submissions.contains_key(&parent_task_id) {
                return Poll::Ready(true);
            }
            if !state
                .waiters
                .iter()
                .any(|waiter| waiter.will_wake(context.waker()))
            {
                state.waiters.push(context.waker().clone());
            }
            Poll::Pending
        })
        .await
    }

    fn finish_recovered_submission(
        &self,
        parent_task_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
    ) -> bool {
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            if state.recovered_submissions.remove(&parent_task_id) != Some(task_id) {
                return false;
            }
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
        true
    }

    /// Reads recovery state without consuming the driver's pending handoff.
    fn operation_recovery(&self, task_id: ProtocolIdentity) -> Option<DurableOperationRecoveryV1> {
        lock_shutdown(&self.state)
            .operation_recoveries
            .get(&task_id)
            .cloned()
    }

    fn take_operation_recovery(
        &self,
        task_id: ProtocolIdentity,
    ) -> Option<DurableOperationRecoveryV1> {
        lock_shutdown(&self.state)
            .operation_recoveries
            .remove(&task_id)
    }

    fn take_tasks(&self) -> Vec<SupervisedTask> {
        std::mem::take(&mut lock_shutdown(&self.state).tasks)
            .into_values()
            .collect()
    }

    fn begin_control(&self) -> Result<Option<AdmissionReservation>, DurableRunFailure> {
        let mut state = lock_shutdown(&self.state);
        if state.control_started {
            return Ok(None);
        }
        state.control_started = true;
        state
            .control_reservation
            .take()
            .map(Some)
            .ok_or(DurableRunFailure::Internal)
    }
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
impl std::ops::Deref for DurableMachineGraphLease {
    type Target = DurableMachineGraph;

    fn deref(&self) -> &Self::Target {
        self.graph
            .as_ref()
            .unwrap_or_else(|| unreachable!("live graph lease retains its graph"))
    }
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
impl std::ops::DerefMut for DurableMachineGraphLease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.graph
            .as_mut()
            .unwrap_or_else(|| unreachable!("live graph lease retains its graph"))
    }
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
impl Drop for DurableMachineGraphLease {
    fn drop(&mut self) {
        let Some(graph) = self.graph.take() else {
            return;
        };
        let frontier = graph.frontier.1;
        let (control_waker, waiters) = {
            let mut state = lock_shutdown(&self.shared.state);
            if !state.failed {
                state.graph = Some(graph);
            }
            state.live_delivery_requested_through =
                state.live_delivery_requested_through.max(frontier);
            if !state.delivery_enabled {
                state.live_delivery_completed_through =
                    state.live_delivery_completed_through.max(frontier);
            }
            let control_waker = if state.delivery_enabled
                && !state.failed
                && !state.finalization_requested
                && !state.live_delivery_queued
                && state.live_delivery_requested_through > state.live_delivery_completed_through
            {
                state.live_delivery_queued = true;
                state
                    .commands
                    .push_back(DurableGraphControlCommand::DeliverCommittedEvents);
                state.control_waker.take()
            } else {
                None
            };
            (control_waker, std::mem::take(&mut state.waiters))
        };
        if let Some(waker) = control_waker {
            waker.wake();
        }
        for waiter in waiters {
            waiter.wake();
        }
    }
}

#[cfg(feature = "durable")]
#[derive(Clone)]
struct DurableOperationContext {
    execution_id: ProtocolIdentity,
    activity_id: ProtocolIdentity,
    mapping_revisions: crate::MappingRevisions,
    declared_value_shapes: Option<DeclaredValueShapes>,
    schemas: BTreeMap<TypeDescriptor, Arc<[u8]>>,
}

#[cfg(feature = "durable")]
impl DurableOperationContext {
    fn from_start(accepted: &StartExecutionAccepted) -> Self {
        let analysis = accepted
            .package_activity
            .analysis
            .as_ref()
            .unwrap_or_else(|| unreachable!("accepted durable start retains analysis"));
        let schemas = analysis
            .schemas()
            .map(|schemas| schemas.entries().iter().cloned().collect())
            .unwrap_or_default();
        Self {
            execution_id: accepted.execution_id,
            activity_id: accepted.package_activity.activity_id,
            mapping_revisions: accepted.mapping_revisions.clone(),
            declared_value_shapes: analysis.declared_value_shapes().cloned(),
            schemas,
        }
    }

    fn schema(&self, ty: &TypeDescriptor) -> Option<Arc<[u8]>> {
        self.schemas.get(ty).cloned()
    }
}

#[cfg(feature = "durable")]
#[derive(Default)]
struct SharedResume {
    state: Mutex<SharedResumeState>,
}

#[cfg(feature = "durable")]
#[derive(Default)]
struct SharedResumeState {
    published: Option<DurableResumeExecutionResult>,
    waiters: Vec<Waker>,
}

#[cfg(feature = "durable")]
impl SharedResume {
    fn publish(&self, result: DurableResumeExecutionResult) {
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            if state.published.is_some() {
                return;
            }
            state.published = Some(result);
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn poll(&self, context: &mut Context<'_>) -> Poll<DurableResumeExecutionResult> {
        let mut state = lock_shutdown(&self.state);
        if let Some(result) = &state.published {
            return Poll::Ready(result.clone());
        }
        if !state
            .waiters
            .iter()
            .any(|waiter| waiter.will_wake(context.waker()))
        {
            state.waiters.push(context.waker().clone());
        }
        Poll::Pending
    }
}

struct PreparedRootDriver {
    machine: Machine,
    coordinator: ExecutionCoordinator,
    task_id: ProtocolIdentity,
    workflow: gantry_ir::CanonicalPath,
    create_request: gantry_host::contracts::HostRequest,
    #[cfg(feature = "concurrent")]
    program: Arc<gantry_ir::MachineProgram>,
    #[cfg(feature = "concurrent")]
    execution_budget: ExecutionBudget,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    root_supervision: Arc<Mutex<Option<SupervisedTask>>>,
}

struct PreparedTaskDriver {
    machine: Machine,
    coordinator: ExecutionCoordinator,
    task_id: ProtocolIdentity,
    workflow: gantry_ir::CanonicalPath,
    create_request: gantry_host::contracts::HostRequest,
    base_session: Option<ProtocolIdentity>,
    #[cfg(feature = "concurrent")]
    program: Arc<gantry_ir::MachineProgram>,
    #[cfg(feature = "concurrent")]
    execution_budget: ExecutionBudget,
}

impl From<PreparedRootDriver> for PreparedTaskDriver {
    fn from(root: PreparedRootDriver) -> Self {
        Self {
            machine: root.machine,
            coordinator: root.coordinator,
            task_id: root.task_id,
            workflow: root.workflow,
            create_request: root.create_request,
            base_session: None,
            #[cfg(feature = "concurrent")]
            program: root.program,
            #[cfg(feature = "concurrent")]
            execution_budget: root.execution_budget,
        }
    }
}

impl PreparedRootDriver {
    fn new_for_prepared(
        inner: &InterpreterInner,
        prepared: &PreparedExecutionStart,
    ) -> Result<Self, RunExecutionError> {
        Self::new(
            inner,
            prepared.execution_id,
            &prepared.package_activity,
            prepared.entry_input.as_ref(),
            &prepared.root_session,
            true,
            None,
        )
    }

    #[cfg(all(feature = "durable", feature = "concurrent"))]
    fn new_for_durable_accepted(
        inner: &InterpreterInner,
        accepted: &StartExecutionAccepted,
        execution_budget: gantry_runtime::ExecutionBudget,
    ) -> Result<Self, RunExecutionError> {
        Self::new(
            inner,
            accepted.execution_id,
            &accepted.package_activity,
            accepted.entry_input.as_ref(),
            &accepted.root_session,
            true,
            Some(execution_budget),
        )
    }

    #[cfg(all(feature = "durable", not(feature = "concurrent")))]
    fn new_for_durable_accepted(
        inner: &InterpreterInner,
        accepted: &StartExecutionAccepted,
    ) -> Result<Self, RunExecutionError> {
        Self::new(
            inner,
            accepted.execution_id,
            &accepted.package_activity,
            accepted.entry_input.as_ref(),
            &accepted.root_session,
            true,
            None,
        )
    }

    fn new(
        inner: &InterpreterInner,
        execution_id: ProtocolIdentity,
        package_activity: &AnalyzePackageResult,
        entry_input: Option<&crate::ValidatedEntryInput>,
        root_session: &crate::RootSessionState,
        submitting: bool,
        execution_budget: Option<gantry_runtime::ExecutionBudget>,
    ) -> Result<Self, RunExecutionError> {
        let analysis = package_activity
            .analysis
            .as_ref()
            .ok_or(RunExecutionError::MissingAnalysis)?;
        let entry = analysis
            .entry()
            .cloned()
            .ok_or(RunExecutionError::MissingEntry)?;
        let program = analysis
            .executable_program()
            .cloned()
            .ok_or(RunExecutionError::MissingExecutableProgram)?;
        let arguments = entry_input
            .map(|input| {
                decode_logical_value(
                    input.canonical_json.bytes(),
                    &input.ty,
                    inner.configuration.required().value_limits,
                    analysis.declared_value_shapes(),
                )
                .map(|value| vec![value])
            })
            .transpose()?
            .unwrap_or_default();
        let initial_agent = analysis.structure().default_agent().map(Arc::from);
        let program = Arc::new(program);
        let machine_limits = inner.configuration.machine_limits();
        #[cfg(feature = "concurrent")]
        let execution_budget =
            execution_budget.unwrap_or_else(|| ExecutionBudget::new(execution_id, machine_limits));
        #[cfg(feature = "concurrent")]
        let machine = Machine::new_concurrent_root_with_budget_and_context(
            Arc::clone(&program),
            &entry.path,
            arguments,
            execution_id,
            machine_limits,
            execution_budget.clone(),
            initial_agent.clone(),
            Some(root_session.id),
        )
        .map_err(RunExecutionError::MachineBuild)?;
        #[cfg(not(feature = "concurrent"))]
        let machine = Machine::new_with_context(
            Arc::clone(&program),
            &entry.path,
            arguments,
            execution_id,
            machine_limits,
            initial_agent.clone(),
            Some(root_session.id),
        )
        .map_err(RunExecutionError::MachineBuild)?;
        let task_id = root_task_identity(execution_id);
        let root_mode = match root_session.provenance {
            crate::RootSessionProvenance::EmbedderSupplied => SessionCreationModeV1::EmbedderRoot,
            crate::RootSessionProvenance::GantryCreated => SessionCreationModeV1::GantryRoot,
        };
        let sessions = LogicalSessionRegistryV1::new(
            execution_id,
            root_session.id,
            root_mode,
            root_session.transcript.clone(),
        )
        .map_err(RunExecutionError::Session)?;
        let tasks = if submitting {
            ConcurrentTaskStateV1::with_submitting_root(
                execution_id,
                task_id,
                inner.configuration.maximum_tasks_per_execution(),
            )
        } else {
            ConcurrentTaskStateV1::new(
                execution_id,
                task_id,
                inner.configuration.maximum_tasks_per_execution(),
            )
        }
        .map_err(RunExecutionError::TaskState)?;
        #[cfg(feature = "concurrent")]
        let coordinator =
            ExecutionCoordinator::new_with_budget(tasks, sessions, execution_budget.clone())
                .map_err(RunExecutionError::TaskState)?;
        #[cfg(not(feature = "concurrent"))]
        let coordinator = {
            let _ = execution_budget;
            ExecutionCoordinator::new(tasks, sessions).map_err(RunExecutionError::TaskState)?
        };
        let create_request = TaskContextV1 {
            execution_id,
            task_id,
            inherited_agent: initial_agent,
            session: TaskSessionContextV1::Root {
                root_session_id: root_session.id,
                provenance: match root_session.provenance {
                    crate::RootSessionProvenance::EmbedderSupplied => {
                        RootSessionProvenanceV1::EmbedderSupplied
                    }
                    crate::RootSessionProvenance::GantryCreated => {
                        RootSessionProvenanceV1::GantryCreated
                    }
                },
            },
        }
        .into_host_request()
        .map_err(RunExecutionError::HookRequest)?;
        Ok(Self {
            machine,
            coordinator,
            task_id,
            workflow: entry.path,
            create_request,
            #[cfg(feature = "concurrent")]
            program,
            #[cfg(feature = "concurrent")]
            execution_budget,
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            root_supervision: Arc::new(Mutex::new(None)),
        })
    }
}

#[derive(Default)]
struct RootStartGate {
    state: std::sync::atomic::AtomicU8,
    waiters: Mutex<Vec<Waker>>,
}

struct NondurableTaskCancellation {
    execution: CancellationSignal,
    coordinator: ExecutionCoordinator,
    task_id: ProtocolIdentity,
}

impl CancellationToken for NondurableTaskCancellation {
    fn is_cancelled(&self) -> bool {
        self.execution.is_cancelled()
            || self
                .coordinator
                .snapshot()
                .state()
                .task_cancellation_reason(self.task_id)
                .is_some()
    }
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
struct DurableTaskCancellation {
    execution: CancellationSignal,
    coordinator: ExecutionCoordinator,
    task_id: ProtocolIdentity,
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
impl CancellationToken for DurableTaskCancellation {
    fn is_cancelled(&self) -> bool {
        self.execution.is_cancelled()
            || self
                .coordinator
                .snapshot()
                .state()
                .task_cancellation_reason(self.task_id)
                .is_some()
    }
}

impl RootStartGate {
    async fn wait(&self) -> bool {
        std::future::poll_fn(|context| {
            let state = self.state.load(Ordering::Acquire);
            if state != 0 {
                return Poll::Ready(state == 1);
            }
            let mut waiters = lock_shutdown(&self.waiters);
            let state = self.state.load(Ordering::Acquire);
            if state != 0 {
                return Poll::Ready(state == 1);
            }
            if !waiters
                .iter()
                .any(|waiter| waiter.will_wake(context.waker()))
            {
                waiters.push(context.waker().clone());
            }
            Poll::Pending
        })
        .await
    }

    fn release(&self) {
        self.finish(1);
    }

    fn cancel(&self) {
        self.finish(2);
    }

    fn finish(&self, state: u8) {
        if self
            .state
            .compare_exchange(0, state, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let waiters = std::mem::take(&mut *lock_shutdown(&self.waiters));
        for waiter in waiters {
            waiter.wake();
        }
    }
}

impl Clone for Interpreter {
    fn clone(&self) -> Self {
        self.inner.external_owners.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: Arc::clone(&self.inner),
            external_owner: true,
        }
    }
}

impl Drop for Interpreter {
    fn drop(&mut self) {
        if self.external_owner && self.inner.external_owners.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.lifecycle.begin_unclean_drop();
        }
    }
}

impl std::fmt::Debug for Interpreter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Interpreter")
            .field("configuration", &self.inner.configuration)
            .field("lifecycle", &self.inner.lifecycle)
            .finish_non_exhaustive()
    }
}

impl Interpreter {
    /// Constructs one running interpreter from explicit executor-neutral integrations.
    ///
    /// The configuration supplies the mandatory executor and bounded admission
    /// policy. Gantry does not construct, drive, or shut down the executor's
    /// runtime; the embedder must keep that runtime alive until orderly
    /// [`Self::shutdown`] completes.
    #[must_use]
    pub fn new(
        configuration: InterpreterConfiguration,
        clock: Arc<dyn UtcClock>,
        preflight: Arc<dyn IntegrationPreflight>,
        runtime_sessions: Arc<dyn RuntimeSessionService>,
        hook_factory: Arc<dyn HookFactory>,
    ) -> Self {
        let event_delivery_runtime = Arc::new(ExecutorEventDeliveryRuntime {
            executor: configuration.executor_arc(),
        });
        Self::new_with_event_delivery(
            configuration,
            clock,
            preflight,
            runtime_sessions,
            hook_factory,
            event_delivery_runtime,
            SinkPlan::default(),
        )
    }

    /// Constructs one interpreter with explicit event-delivery services and a default sink plan.
    ///
    /// Service references are retained for accepted work and shutdown even when
    /// a caller drops an individual start, observation, or cancellation future.
    /// Prefer [`Self::shutdown`] before releasing the last facade clone.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_event_delivery(
        configuration: InterpreterConfiguration,
        clock: Arc<dyn UtcClock>,
        preflight: Arc<dyn IntegrationPreflight>,
        runtime_sessions: Arc<dyn RuntimeSessionService>,
        hook_factory: Arc<dyn HookFactory>,
        event_delivery_runtime: Arc<dyn EventDeliveryRuntime>,
        event_delivery: SinkPlan,
    ) -> Self {
        let lifecycle = InterpreterLifecycle::new(&configuration);
        let session_establisher = SessionEstablisher::new(
            lifecycle.task_supervisor(),
            runtime_sessions,
            AdapterPoison::default(),
        );
        Self {
            inner: Arc::new(InterpreterInner {
                external_owners: AtomicUsize::new(1),
                shutdown_started: AtomicBool::new(false),
                shutdown: Arc::new(SharedShutdown::default()),
                nondurable_executions: NondurableExecutionRegistry::default(),
                #[cfg(all(feature = "concurrent", feature = "test-support"))]
                nondurable_before_child_executor_submit: Mutex::new(None),
                #[cfg(all(feature = "concurrent", feature = "test-support"))]
                nondurable_cancel_before_child_submit: Mutex::new(None),
                #[cfg(all(feature = "concurrent", feature = "test-support"))]
                nondurable_cancel_after_child_resolution: Mutex::new(None),
                #[cfg(all(feature = "concurrent", feature = "durable", feature = "test-support"))]
                durable_cancel_before_child_submit: Mutex::new(None),
                #[cfg(all(feature = "concurrent", feature = "durable", feature = "test-support"))]
                durable_cancel_after_child_submit: Mutex::new(None),
                #[cfg(all(feature = "concurrent", feature = "durable", feature = "test-support"))]
                durable_cancel_after_child_session_establishment: Mutex::new(None),
                #[cfg(all(feature = "concurrent", feature = "durable", feature = "test-support"))]
                durable_cancelled_child_continuations: AtomicUsize::new(0),
                #[cfg(feature = "durable")]
                durable_executions: DurableExecutionRegistry::default(),
                #[cfg(all(feature = "durable", feature = "test-support"))]
                durable_handoff_test_gate: Mutex::new(None),
                configuration,
                lifecycle,
                allocator: FreshIdentityAllocator::default(),
                blocking_work_poison: AdapterPoison::default(),
                clock,
                preflight,
                session_establisher,
                hook_factory,
                event_delivery_runtime,
                event_delivery,
            }),
            external_owner: true,
        }
    }

    /// Installs the one-shot durable acceptance handoff gate used by
    /// deterministic conformance tests.
    #[cfg(all(feature = "durable", feature = "test-support"))]
    #[doc(hidden)]
    pub fn install_durable_handoff_test_gate(&self, gate: Arc<DurableHandoffTestGate>) {
        *lock_shutdown(&self.inner.durable_handoff_test_gate) = Some(gate);
    }

    /// Runs preflight, publishes accepted state, and submits the root to the configured executor.
    ///
    /// Predictable setup and root-capacity exhaustion reject before acceptance.
    /// Once accepted state is published, the gated root is registered with
    /// supervision before source progress is released. The returned handle is
    /// for observation and control; the root may already have progressed or
    /// settled when the caller observes this result. Exceptional executor
    /// rejection after acceptance settles that same execution as an executor
    /// failure rather than retroactively rejecting the start.
    pub async fn start_execution(
        &self,
        request: StartExecutionRequest<'_>,
    ) -> StartExecutionResult {
        let event_delivery = request.event_delivery.unwrap_or(&self.inner.event_delivery);
        let request = StartExecutionRequest {
            event_delivery: Some(event_delivery),
            ..request
        };
        let package = AnalyzePackageCoordinator::new(
            &self.inner.allocator,
            self.inner.configuration.identity_source(),
            self.inner.clock.as_ref(),
            self.inner.configuration.blocking_work(),
        )
        .with_blocking_work_poison(self.inner.blocking_work_poison.clone())
        .with_delivery_runtime(self.inner.event_delivery_runtime.as_ref());
        let coordinator = StartExecutionCoordinator::new(
            &package,
            &self.inner.lifecycle,
            &self.inner.configuration,
            &self.inner.allocator,
            Arc::clone(&self.inner.preflight),
        )
        .with_owned_event_delivery(owned_event_delivery_factory(Arc::clone(&self.inner)));
        let prepared = match coordinator.prepare(request).await {
            Ok(prepared) => prepared,
            Err(failure) => return StartExecutionResult::Rejected(failure),
        };
        let root = match PreparedRootDriver::new_for_prepared(&self.inner, &prepared) {
            Ok(root) => root,
            Err(error) => {
                return StartExecutionResult::Rejected(prepared_start_failure(
                    prepared,
                    StartFailureCategory::Internal,
                    preparation_error_code(&error),
                ));
            }
        };
        let workflow = root.workflow.clone();
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve(AdmissionClass::RootTask) {
            Ok(reservation) => reservation,
            Err(_) => {
                return StartExecutionResult::Rejected(prepared_start_failure(
                    prepared,
                    StartFailureCategory::ImplementationResourceExhaustion,
                    "root-task-capacity",
                ));
            }
        };
        let execution_id = root.coordinator.snapshot().state().execution_id();
        self.inner.nondurable_executions.mark(
            execution_id,
            root.coordinator.clone(),
            workflow.clone(),
        );
        let accepted = match prepared.accept_state() {
            Ok(accepted) => accepted,
            Err(failure) => {
                self.inner.nondurable_executions.abandon(execution_id);
                return StartExecutionResult::Rejected(failure);
            }
        };
        self.inner
            .nondurable_executions
            .publish(execution_id, accepted.handle.clone());
        let driver = TaskDriver::from_prepared(Arc::clone(&self.inner), accepted.clone(), root);
        let task_coordinator = driver.coordinator();
        let abnormal = driver.abnormal_completion_handler();
        let completion = driver.physical_completion_handler();
        let root_task_id = task_coordinator.snapshot().state().root_task_id();
        let registration = supervisor.prepare_owned_with_completion(
            SupervisedTaskDomain::Root,
            accepted.execution_id,
            root_task_id,
            Some(abnormal),
            Some(completion),
        );
        let signal = registration.signal();
        let gate = Arc::new(RootStartGate::default());
        let task = driver.into_gated_owned_task(signal, Arc::clone(&gate));
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => {
                if task_coordinator.resolve_root_submission().is_ok() {
                    task.relinquish();
                    gate.release();
                } else {
                    let outcome = root_start_failure(&workflow, RuntimeCode::InternalInvariant);
                    let _ = settle_root_start_failure(
                        &self.inner.lifecycle,
                        &accepted,
                        &task_coordinator,
                        outcome,
                        false,
                    );
                    gate.cancel();
                    task.relinquish();
                }
            }
            Err(_) => {
                let outcome = root_start_failure(&workflow, RuntimeCode::RootSubmissionFailure);
                let _ = settle_root_start_failure(
                    &self.inner.lifecycle,
                    &accepted,
                    &task_coordinator,
                    outcome,
                    true,
                );
            }
        }
        StartExecutionResult::Accepted(Box::new(accepted))
    }

    /// Commits durable acceptance, publishes owned state, and submits the root automatically.
    ///
    /// Sequence-one evidence and journal ownership become authoritative before
    /// acceptance. The root then follows the same gated registration and
    /// automatic-progress contract as [`Self::start_execution`]. Dropping this
    /// caller stops only result observation; accepted journal and driver
    /// ownership remain internal.
    #[cfg(feature = "durable")]
    pub async fn start_durable_execution(
        &self,
        storage: Arc<dyn JournalStorage>,
        request: DurableStartExecutionRequest<'_>,
    ) -> DurableStartExecutionResult {
        let event_delivery = request
            .start
            .event_delivery
            .unwrap_or(&self.inner.event_delivery);
        let request = DurableStartExecutionRequest {
            journal_id: request.journal_id,
            start: StartExecutionRequest {
                event_delivery: Some(event_delivery),
                ..request.start
            },
        };
        let journal_id = request.journal_id.clone();
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve(AdmissionClass::RootTask) {
            Ok(reservation) => reservation,
            Err(_) => {
                return DurableStartExecutionResult::Rejected(DurableStartExecutionFailure {
                    journal_id,
                    failure: StartExecutionFailure {
                        category: StartFailureCategory::ImplementationResourceExhaustion,
                        code: Arc::from("root-task-capacity"),
                        package_activity: None,
                    },
                    release_error: None,
                });
            }
        };
        let package = AnalyzePackageCoordinator::new(
            &self.inner.allocator,
            self.inner.configuration.identity_source(),
            self.inner.clock.as_ref(),
            self.inner.configuration.blocking_work(),
        )
        .with_blocking_work_poison(self.inner.blocking_work_poison.clone())
        .with_delivery_runtime(self.inner.event_delivery_runtime.as_ref());
        let start = StartExecutionCoordinator::new(
            &package,
            &self.inner.lifecycle,
            &self.inner.configuration,
            &self.inner.allocator,
            Arc::clone(&self.inner.preflight),
        )
        .with_owned_event_delivery(owned_event_delivery_factory(Arc::clone(&self.inner)));
        let durable = DurableStartExecutionCoordinator::new(
            start,
            &self.inner.configuration,
            Arc::clone(&storage),
        );
        let registry = &self.inner.durable_executions;
        let accepted = match durable
            .start_with_registration(request, |event| match event {
                DurableRegistrationEvent::Marked(execution_id) => registry.mark(execution_id),
                #[cfg(feature = "test-support")]
                DurableRegistrationEvent::Accepted(handle) => {
                    let gate = lock_shutdown(&self.inner.durable_handoff_test_gate).clone();
                    if let Some(gate) = gate {
                        gate.pause(handle);
                    }
                }
                DurableRegistrationEvent::Published(owner) => registry.publish(owner),
                DurableRegistrationEvent::Abandoned(execution_id) => registry.abandon(execution_id),
            })
            .await
        {
            DurableStartExecutionResult::Accepted(accepted) => accepted,
            rejected => return rejected,
        };
        let Some(_root_submission_claim) = self
            .inner
            .durable_executions
            .claim_root_submission(accepted.start.execution_id)
        else {
            return DurableStartExecutionResult::Accepted(accepted);
        };
        #[cfg(feature = "concurrent")]
        let prepared = PreparedRootDriver::new_for_durable_accepted(
            &self.inner,
            &accepted.start,
            accepted.execution_budget.clone(),
        )
        .unwrap_or_else(|_| unreachable!("committed start retained validated root state"));
        #[cfg(not(feature = "concurrent"))]
        let prepared = PreparedRootDriver::new_for_durable_accepted(&self.inner, &accepted.start)
            .unwrap_or_else(|_| unreachable!("committed start retained validated root state"));
        let task_id = prepared.task_id;
        let task_coordinator = prepared.coordinator.clone();
        #[cfg(feature = "concurrent")]
        let root_supervision = Arc::clone(&prepared.root_supervision);
        let completion_coordinator = task_coordinator.clone();
        let completion: PhysicalCompletionHandler = Arc::new(move |_| {
            let _ = completion_coordinator.mark_driver_physically_settled(task_id);
        });
        let registration = supervisor.prepare_owned_with_completion(
            SupervisedTaskDomain::Root,
            accepted.execution_id(),
            task_id,
            None,
            Some(completion),
        );
        let signal = registration.signal();
        let gate = Arc::new(RootStartGate::default());
        let owner = Arc::clone(&accepted.owned);
        let driver_owner = Arc::clone(&owner);
        let driver_inner = Arc::clone(&self.inner);
        let driver_accepted = accepted.start.clone();
        let driver_gate = Arc::clone(&gate);
        let task: OwnedTaskFuture = Box::pin(async move {
            if driver_gate.wait().await {
                let interpreter = Interpreter {
                    inner: driver_inner,
                    external_owner: false,
                };
                interpreter
                    .drive_durable_execution(driver_accepted, prepared, driver_owner)
                    .await;
            }
            let _ = signal.settle();
            OwnedTaskResult::new()
        });
        let submission = supervisor.submit(registration, task, reservation.transfer());
        drop(_root_submission_claim);
        match submission {
            Ok(task) => {
                if task_coordinator.resolve_root_submission().is_ok() {
                    #[cfg(feature = "concurrent")]
                    {
                        *lock_shutdown(&root_supervision) = Some(task);
                    }
                    #[cfg(not(feature = "concurrent"))]
                    task.relinquish();
                    gate.release();
                } else {
                    gate.cancel();
                    task.relinquish();
                    if let Some(recovered) = owner.begin_driver() {
                        owner.fail_driver(recovered, DurableRunFailure::Internal);
                    }
                }
            }
            Err(_) => {
                self.start_owned_durable_submission_failure(
                    task_coordinator,
                    owner,
                    accepted.start.package_activity.activity_id,
                    task_id,
                );
            }
        }
        DurableStartExecutionResult::Accepted(accepted)
    }

    /// Reconstructs and atomically admits one existing durable execution.
    ///
    /// Recovery acquires fencing, validates compatibility, reconstructs the
    /// complete unfinished graph, reserves the runnable set, submits it behind
    /// closed gates, and registers every driver before accepting resume. Any
    /// pre-acceptance failure rolls that work back without publishing semantic
    /// progress. An already terminal execution is accepted for observation
    /// without creating a source driver. Physical replacement submissions may
    /// repeat, but logical identities and transitions do not.
    #[cfg(feature = "durable")]
    pub async fn resume_durable_execution(
        &self,
        storage: Arc<dyn JournalStorage>,
        request: DurableResumeExecutionRequest<'_>,
    ) -> DurableResumeExecutionResult {
        let request = OwnedDurableResumeRequest {
            journal_id: request.journal_id,
            protocol_selection: request.protocol_selection.clone(),
            candidate_package_root: request.candidate_package_root.map(PathBuf::from),
            expected_execution_id: request.expected_execution_id,
            event_delivery: Some(
                request
                    .event_delivery
                    .cloned()
                    .unwrap_or_else(|| self.inner.event_delivery.clone()),
            ),
        };
        let result = Arc::new(SharedResume::default());
        self.start_owned_durable_resume(storage, request, Arc::clone(&result));
        std::future::poll_fn(|context| result.poll(context)).await
    }

    #[cfg(feature = "durable")]
    fn start_owned_durable_resume(
        &self,
        storage: Arc<dyn JournalStorage>,
        request: OwnedDurableResumeRequest,
        result: Arc<SharedResume>,
    ) {
        let journal_id = request.journal_id.clone();
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve(AdmissionClass::PublicActivity) {
            Ok(reservation) => reservation,
            Err(_) => {
                result.publish(resume_failure(
                    journal_id,
                    ResumeStartFailureCategory::ImplementationResourceExhaustion,
                    "resume-activity-capacity",
                ));
                return;
            }
        };
        let abnormal_result = Arc::clone(&result);
        let abnormal_journal = journal_id.clone();
        let abnormal: AbnormalCompletionHandler = Arc::new(move |_| {
            abnormal_result.publish(resume_failure(
                abnormal_journal.clone(),
                ResumeStartFailureCategory::Internal,
                "resume-coordinator-failure",
            ));
        });
        let registration = supervisor.prepare(SupervisedTaskDomain::PublicActivity, Some(abnormal));
        let signal = registration.signal();
        let inner = Arc::clone(&self.inner);
        let task_result = Arc::clone(&result);
        let task: OwnedTaskFuture = Box::pin(async move {
            let interpreter = Interpreter {
                inner,
                external_owner: false,
            };
            let package = AnalyzePackageCoordinator::new(
                &interpreter.inner.allocator,
                interpreter.inner.configuration.identity_source(),
                interpreter.inner.clock.as_ref(),
                interpreter.inner.configuration.blocking_work(),
            )
            .with_blocking_work_poison(interpreter.inner.blocking_work_poison.clone())
            .with_delivery_runtime(interpreter.inner.event_delivery_runtime.as_ref());
            let start = StartExecutionCoordinator::new(
                &package,
                &interpreter.inner.lifecycle,
                &interpreter.inner.configuration,
                &interpreter.inner.allocator,
                Arc::clone(&interpreter.inner.preflight),
            )
            .with_owned_event_delivery(owned_event_delivery_factory(Arc::clone(
                &interpreter.inner,
            )));
            let durable = DurableStartExecutionCoordinator::new(
                start,
                &interpreter.inner.configuration,
                storage,
            );
            let resumed = durable
                .resume_with_handoff(request.borrowed(), |prepared| {
                    interpreter.handoff_prepared_resume(&durable, prepared)
                })
                .await;
            task_result.publish(resumed);
            let _ = signal.settle();
            OwnedTaskResult::new()
        });
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => task.relinquish(),
            Err(_) => result.publish(resume_failure(
                journal_id,
                ResumeStartFailureCategory::Internal,
                "resume-coordinator-submission-failure",
            )),
        }
    }

    #[cfg(feature = "durable")]
    async fn handoff_prepared_resume(
        &self,
        durable: &DurableStartExecutionCoordinator<'_>,
        mut prepared: PreparedDurableResume,
    ) -> DurableResumeExecutionResult {
        #[cfg(all(feature = "concurrent", feature = "durable"))]
        if matches!(
            prepared.recovered,
            PreparedDurableRecovery::Concurrent { .. }
        ) {
            return self
                .handoff_prepared_concurrent_resume(durable, prepared)
                .await;
        }

        if prepared.recovered.latest_cut() == DurableCommitCutV1::TerminalCompletion {
            if let Err(failure) = durable.commit_prepared_resume_revision(&mut prepared).await {
                return durable.reject_prepared_resume_with(prepared, failure).await;
            }
            self.mark_durable_execution(prepared.execution_id);
            let accepted = match durable.publish_prepared_resume(prepared) {
                Ok(accepted) => accepted,
                Err(prepared) => {
                    self.abandon_durable_execution(prepared.execution_id);
                    unreachable!("reserved resume identity remains publishable")
                }
            };
            self.register_durable_execution(Arc::clone(&accepted.owned));
            let _ = accepted
                .owned
                .drain_event_obligations(
                    &self.inner.allocator,
                    self.inner.configuration.identity_source(),
                    self.inner.event_delivery_runtime.as_ref(),
                )
                .await;
            return DurableResumeExecutionResult::Accepted(Box::new(accepted));
        }

        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve(AdmissionClass::ResumeRunnableTask) {
            Ok(reservation) => reservation,
            Err(_) => {
                return durable
                    .reject_prepared_resume(
                        prepared,
                        ResumeStartFailureCategory::ImplementationResourceExhaustion,
                        "resume-runnable-task-capacity",
                    )
                    .await;
            }
        };
        let driver = match self.recovered_root_driver(&prepared) {
            Ok(driver) => driver,
            Err(code) => {
                return durable
                    .reject_prepared_resume(
                        prepared,
                        ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                        code,
                    )
                    .await;
            }
        };
        let task_id = driver.task_id;
        #[cfg(feature = "concurrent")]
        let root_supervision = Arc::clone(&driver.root_supervision);
        let completion_coordinator = driver.coordinator.clone();
        let completion: PhysicalCompletionHandler = Arc::new(move |_| {
            let _ = completion_coordinator.mark_driver_physically_settled(task_id);
        });
        let registration = supervisor.prepare_owned_with_completion(
            SupervisedTaskDomain::Resume,
            prepared.execution_id,
            task_id,
            None,
            Some(completion),
        );
        let signal = registration.signal();
        let gate = Arc::new(RootStartGate::default());
        let task_gate = Arc::clone(&gate);
        let inner = Arc::clone(&self.inner);
        let slot = Arc::new(Mutex::new(None));
        let task_slot = Arc::clone(&slot);
        let task: OwnedTaskFuture = Box::pin(async move {
            if task_gate.wait().await {
                let (driver, owner) = lock_shutdown(&task_slot)
                    .take()
                    .unwrap_or_else(|| unreachable!("released resume gate retains its driver"));
                let interpreter = Interpreter {
                    inner,
                    external_owner: false,
                };
                interpreter
                    .drive_recovered_durable_execution(driver, owner)
                    .await;
            }
            let _ = signal.settle();
            OwnedTaskResult::new()
        });
        let submitted = match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => task,
            Err(_) => {
                return durable
                    .reject_prepared_resume(
                        prepared,
                        ResumeStartFailureCategory::Internal,
                        "resume-task-submission-failure",
                    )
                    .await;
            }
        };
        if let Err(failure) = durable.commit_prepared_resume_revision(&mut prepared).await {
            rollback_submitted_resume(
                submitted,
                gate,
                self.inner.configuration.executor(),
                self.inner.configuration.post_cancellation_drain(),
            )
            .await;
            return durable.reject_prepared_resume_with(prepared, failure).await;
        }
        self.mark_durable_execution(prepared.execution_id);
        let accepted = match durable.publish_prepared_resume(prepared) {
            Ok(accepted) => accepted,
            Err(prepared) => {
                self.abandon_durable_execution(prepared.execution_id);
                unreachable!("reserved resume identity remains publishable")
            }
        };
        self.register_durable_execution(Arc::clone(&accepted.owned));
        *lock_shutdown(&slot) = Some((driver, Arc::clone(&accepted.owned)));
        #[cfg(feature = "concurrent")]
        {
            *lock_shutdown(&root_supervision) = Some(submitted);
        }
        #[cfg(not(feature = "concurrent"))]
        submitted.relinquish();
        gate.release();
        DurableResumeExecutionResult::Accepted(Box::new(accepted))
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn handoff_prepared_concurrent_resume(
        &self,
        durable: &DurableStartExecutionCoordinator<'_>,
        mut prepared: PreparedDurableResume,
    ) -> DurableResumeExecutionResult {
        let activity_collision = match &prepared.recovered {
            PreparedDurableRecovery::Concurrent { recovered, .. } => {
                match reserve_recovered_concurrent_identities(
                    &self.inner.allocator,
                    recovered,
                    prepared.activity_id,
                ) {
                    Ok(activity_collision) => activity_collision,
                    Err(code) => {
                        return durable
                            .reject_prepared_resume(
                                prepared,
                                ResumeStartFailureCategory::Internal,
                                code,
                            )
                            .await;
                    }
                }
            }
            PreparedDurableRecovery::Serial(_) => {
                unreachable!("concurrent handoff receives concurrent recovery")
            }
        };
        if activity_collision {
            prepared.activity_id = match self.inner.allocator.allocate(
                self.inner.configuration.identity_source(),
                IdentityKind::Activity,
            ) {
                Ok(activity_id) => activity_id,
                Err(_) => {
                    return durable
                        .reject_prepared_resume(
                            prepared,
                            ResumeStartFailureCategory::IntegrationPreflight,
                            "identity-source-failure",
                        )
                        .await;
                }
            };
        }
        let (
            admission,
            program,
            operations,
            mut next_event_sequence,
            operation_recoveries,
            initial_delivery_pending,
            terminal,
            recovered_events,
        ) = match &prepared.recovered {
            PreparedDurableRecovery::Concurrent {
                execution_start,
                recovered,
                ..
            } => {
                let program = match execution_start.program() {
                    Ok(program) => Arc::new(program),
                    Err(_) => {
                        return durable
                            .reject_prepared_resume(
                                prepared,
                                ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                                "invalid-retained-program",
                            )
                            .await;
                    }
                };
                let checkpoint = match gantry_runtime::ConcurrentDurableCheckpointV4::capture(
                    recovered.execution().foreground(),
                    recovered.execution().scheduler(),
                    recovered.execution().sessions(),
                ) {
                    Ok(checkpoint) => checkpoint,
                    Err(_) => {
                        return durable
                            .reject_prepared_resume(
                                prepared,
                                ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                                "invalid-recovered-task-state",
                            )
                            .await;
                    }
                };
                let admission = match checkpoint
                    .recover(Arc::clone(&program))
                    .map_err(|_| ())
                    .and_then(|recovered| recovered.into_driver_admission().map_err(|_| ()))
                {
                    Ok(admission) => admission,
                    Err(()) => {
                        return durable
                            .reject_prepared_resume(
                                prepared,
                                ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                                "invalid-recovered-task-state",
                            )
                            .await;
                    }
                };
                let declared_value_shapes = prepared
                    .candidate_package_activity
                    .as_ref()
                    .and_then(|activity| activity.analysis.as_ref())
                    .and_then(|analysis| analysis.declared_value_shapes())
                    .cloned();
                let schemas = match decode_retained_schemas(
                    prepared.retained_artifacts.generated_schemas(),
                    self.inner
                        .configuration
                        .required()
                        .frontend_limits
                        .maximum_constructed_type_depth(),
                ) {
                    Ok(schemas) => schemas,
                    Err(code) => {
                        return durable
                            .reject_prepared_resume(
                                prepared,
                                ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                                code,
                            )
                            .await;
                    }
                };
                let next_event_sequence = match recovered_task_event_sequences(recovered.events()) {
                    Ok(sequences) => sequences,
                    Err(code) => {
                        return durable
                            .reject_prepared_resume(
                                prepared,
                                ResumeStartFailureCategory::JournalReadOrFormat,
                                code,
                            )
                            .await;
                    }
                };
                (
                    admission,
                    program,
                    DurableOperationContext {
                        execution_id: prepared.execution_id,
                        activity_id: prepared.activity_id,
                        mapping_revisions: prepared.mapping_revisions.clone(),
                        declared_value_shapes,
                        schemas,
                    },
                    next_event_sequence,
                    recovered.operation_recoveries().clone(),
                    recovered_events_have_pending_delivery(recovered.events()),
                    recovered.latest_cut() == DurableCommitCutV1::TerminalCompletion,
                    recovered.events().clone(),
                )
            }
            PreparedDurableRecovery::Serial(_) => {
                unreachable!("concurrent handoff receives concurrent recovery")
            }
        };
        if admission
            .coordinator()
            .publish_committed_events(recovered_events)
            .is_err()
        {
            return durable
                .reject_prepared_resume(
                    prepared,
                    ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                    "invalid-recovered-event-state",
                )
                .await;
        }
        let drivers = match recovered_concurrent_task_drivers(
            &admission,
            Arc::clone(&program),
            self.inner.configuration.machine_limits(),
        ) {
            Ok(drivers) => drivers,
            Err(code) => {
                return durable
                    .reject_prepared_resume(
                        prepared,
                        ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                        code,
                    )
                    .await;
            }
        };

        if terminal && drivers.is_empty() {
            if let Err(failure) = self
                .repair_prepared_lifecycle_events(
                    durable,
                    &mut prepared,
                    admission.coordinator(),
                    &operations,
                    &mut next_event_sequence,
                )
                .await
            {
                return durable.reject_prepared_resume_with(prepared, failure).await;
            }
            let initial_delivery_pending = match &prepared.recovered {
                PreparedDurableRecovery::Concurrent { recovered, .. } => {
                    admission
                        .coordinator()
                        .publish_committed_events(recovered.events().clone())
                        .unwrap_or_else(|_| {
                            unreachable!("unpublished recovery has no competing writer")
                        });
                    recovered_events_have_pending_delivery(recovered.events())
                }
                PreparedDurableRecovery::Serial(_) => unreachable!("concurrent recovery"),
            };
            if let Err(failure) = durable.commit_prepared_resume_revision(&mut prepared).await {
                return durable.reject_prepared_resume_with(prepared, failure).await;
            }
            let frontier = match &prepared.recovered {
                PreparedDurableRecovery::Concurrent {
                    latest_evidence_id,
                    latest_sequence,
                    ..
                } => (*latest_evidence_id, *latest_sequence),
                PreparedDurableRecovery::Serial(_) => {
                    unreachable!("concurrent handoff retains concurrent recovery")
                }
            };
            self.mark_durable_execution(prepared.execution_id);
            let accepted = match durable.publish_prepared_resume(prepared) {
                Ok(accepted) => accepted,
                Err(prepared) => {
                    self.abandon_durable_execution(prepared.execution_id);
                    unreachable!("reserved concurrent resume identity remains publishable")
                }
            };
            self.register_durable_execution(Arc::clone(&accepted.owned));
            let (coordinator, _, _, _) = admission.into_parts();
            accepted.owned.activate_graph_driver();
            if initial_delivery_pending {
                let owner = Arc::clone(&accepted.owned);
                let delivery_owner = Arc::clone(&owner);
                let delivery_coordinator = coordinator.clone();
                let delivery_program = Arc::clone(&program);
                let delivery_inner = Arc::clone(&self.inner);
                let delivery = self.inner.lifecycle.call_owned_event_delivery(async move {
                    let result = delivery_owner
                        .drain_graph_required_event_obligations_through(
                            delivery_program,
                            &delivery_coordinator,
                            frontier.1,
                            &delivery_inner.allocator,
                            delivery_inner.configuration.identity_source(),
                            delivery_inner.event_delivery_runtime.as_ref(),
                        )
                        .await
                        .and_then(|(_, barrier)| match barrier {
                            DurableEventBarrierV1::RequiredExhausted(failure) => delivery_owner
                                .record_graph_post_terminal_delivery_failure(
                                    &delivery_coordinator,
                                    failure,
                                ),
                            DurableEventBarrierV1::Delivered => Ok(()),
                            DurableEventBarrierV1::Pending { .. } => {
                                Err(DurableRunFailure::Internal)
                            }
                        });
                    match result {
                        Ok(()) => {
                            let _ = delivery_owner.finish_graph_driver().await;
                        }
                        Err(failure) => {
                            let _ = delivery_owner.finish_failed_graph_driver(failure).await;
                        }
                    }
                });
                if delivery.await.is_err() {
                    let _ = owner
                        .finish_failed_graph_driver(DurableRunFailure::Internal)
                        .await;
                }
            } else {
                let _ = accepted.owned.finish_graph_driver().await;
            }
            return DurableResumeExecutionResult::Accepted(Box::new(accepted));
        }

        let supervisor = self.inner.lifecycle.task_supervisor();
        let runnable_count = match u64::try_from(drivers.len()) {
            Ok(count) => count,
            Err(_) => {
                return durable
                    .reject_prepared_resume(
                        prepared,
                        ResumeStartFailureCategory::ImplementationResourceExhaustion,
                        "resume-runnable-task-capacity",
                    )
                    .await;
            }
        };
        let mut runnable_permits =
            match supervisor.try_reserve_many(AdmissionClass::ResumeRunnableTask, runnable_count) {
                Ok(permits) => permits,
                Err(_) => {
                    return durable
                        .reject_prepared_resume(
                            prepared,
                            ResumeStartFailureCategory::ImplementationResourceExhaustion,
                            "resume-runnable-task-capacity",
                        )
                        .await;
                }
            };
        let control_reservation = match supervisor.try_reserve_control_plane() {
            Ok(reservation) => reservation,
            Err(_) => {
                return durable
                    .reject_prepared_resume(
                        prepared,
                        ResumeStartFailureCategory::ImplementationResourceExhaustion,
                        "resume-control-plane-capacity",
                    )
                    .await;
            }
        };
        let recovered_submission_count = drivers
            .iter()
            .filter(|driver| driver.submission.is_some())
            .count();
        let recovered_submissions = drivers
            .iter()
            .filter_map(|driver| {
                driver
                    .submission
                    .as_ref()
                    .map(|submission| (submission.parent_task_id, driver.task_id))
            })
            .collect::<BTreeMap<_, _>>();
        if recovered_submissions.len() != recovered_submission_count {
            return durable
                .reject_prepared_resume(
                    prepared,
                    ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                    "invalid-recovered-submission-state",
                )
                .await;
        }

        let gate = Arc::new(RootStartGate::default());
        let runtime_slot = Arc::new(Mutex::new(None::<RecoveredDurableGraphRuntime>));
        let root_task_id = admission.coordinator().snapshot().state().root_task_id();
        let mut submitted_tasks = Vec::with_capacity(drivers.len());
        for driver in drivers {
            let task_id = driver.task_id;
            let workflow = driver.workflow;
            let abnormal_slot = Arc::clone(&runtime_slot);
            let abnormal_inner = Arc::clone(&self.inner);
            let abnormal: AbnormalCompletionHandler = Arc::new(move |completion| {
                if let Some(runtime) = lock_shutdown(&abnormal_slot).clone() {
                    if task_id == root_task_id {
                        runtime
                            .graph
                            .require_failure_finalization(DurableRunFailure::Internal);
                    } else if let Some(workflow) = &workflow {
                        TaskDriverFailureContext {
                            inner: Arc::clone(&abnormal_inner),
                            coordinator: runtime.coordinator.clone(),
                            task_id,
                            handle: runtime.owner.execution_handle(),
                            workflow: workflow.clone(),
                            execution_foreground: false,
                            durable_graph: Some(Arc::clone(&runtime.graph)),
                            durable_owner: Some(Arc::clone(&runtime.owner)),
                        }
                        .settle(&completion);
                    } else {
                        runtime
                            .graph
                            .require_failure_finalization(DurableRunFailure::Internal);
                    }
                }
            });
            let completion_coordinator = admission.coordinator().clone();
            let completion: PhysicalCompletionHandler = Arc::new(move |_| {
                let _ = completion_coordinator.mark_driver_physically_settled(task_id);
            });
            let registration = supervisor.prepare_owned_deferred_with_completion(
                SupervisedTaskDomain::Resume,
                prepared.execution_id,
                task_id,
                Some(abnormal),
                Some(completion),
            );
            let signal = registration.signal();
            let task_gate = Arc::clone(&gate);
            let task_slot = Arc::clone(&runtime_slot);
            let inner = Arc::clone(&self.inner);
            let create_request = driver.create_request;
            let model_session_occurrence = driver.model_session_occurrence;
            let submission = driver.submission;
            let task_signal = signal.clone();
            let task: OwnedTaskFuture = Box::pin(async move {
                if task_gate.wait().await {
                    let runtime = lock_shutdown(&task_slot)
                        .clone()
                        .unwrap_or_else(|| unreachable!("released recovery gate has a graph"));
                    let interpreter = Interpreter {
                        inner,
                        external_owner: false,
                    };
                    let result: Result<(), DurableRunFailure> = async {
                        if let Some(submission) = submission {
                            let mut lease = runtime
                                .graph
                                .acquire()
                                .await
                                .ok_or(DurableRunFailure::Internal)?;
                            let sequence = lease
                                .next_event_sequence
                                .get(&submission.parent_task_id)
                                .copied()
                                .unwrap_or(0);
                            let draft = concurrent_spawn_event(
                                runtime.operations.execution_id,
                                &submission.created.transition,
                                sequence,
                            )
                            .map_err(|_| DurableRunFailure::Internal)?;
                            let event = interpreter.complete_graph_event(
                                &runtime.operations,
                                submission.parent_task_id,
                                sequence,
                                draft.clone(),
                            );
                            let (frontier, repaired) = runtime
                                .owner
                                .repair_recovered_graph_event(
                                    Arc::clone(&runtime.program),
                                    &runtime.coordinator,
                                    |recovered| recovered.task_creation_cause(task_id),
                                    event,
                                    &draft.protected_payloads,
                                )
                                .await?;
                            lease.frontier = frontier;
                            if repaired {
                                lease.next_event_sequence.insert(
                                    submission.parent_task_id,
                                    sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
                                );
                            }
                            let cancelled = interpreter
                                .commit_durable_child_submission_resolution(
                                    &mut lease,
                                    &runtime.owner,
                                    &runtime.coordinator,
                                    &runtime.operations,
                                    submission.parent_task_id,
                                    &submission.created,
                                    &submission.suspension,
                                    Some(submission.machine),
                                )
                                .await?;
                            if !runtime
                                .graph
                                .finish_recovered_submission(submission.parent_task_id, task_id)
                            {
                                return Err(DurableRunFailure::Internal);
                            }
                            if cancelled {
                                return Ok(());
                            }
                        }
                        let hook = TaskHook::new(
                            &interpreter.inner.lifecycle,
                            interpreter.inner.hook_factory.as_ref(),
                            AdapterPoison::default(),
                            create_request,
                        )
                        .map_err(|_| DurableRunFailure::Internal)?;
                        interpreter
                            .drive_durable_graph_task(
                                Arc::clone(&runtime.graph),
                                Arc::clone(&runtime.owner),
                                runtime.coordinator.clone(),
                                Arc::clone(&runtime.program),
                                runtime.operations.clone(),
                                task_id,
                                Some(hook),
                                None,
                                model_session_occurrence,
                                true,
                            )
                            .await
                    }
                    .await;
                    if let Err(failure) = result {
                        runtime.graph.require_failure_finalization(failure);
                    }
                }
                let _ = task_signal.settle();
                OwnedTaskResult::new()
            });
            let permit = runnable_permits
                .pop()
                .unwrap_or_else(|| unreachable!("one permit exists per recovered driver"));
            match supervisor.submit(registration, task, permit) {
                Ok(task) => submitted_tasks.push((task_id, task, signal)),
                Err(_) => {
                    drop(runnable_permits);
                    drop(control_reservation);
                    rollback_submitted_recovered_graph(
                        submitted_tasks
                            .into_iter()
                            .map(|(_, task, signal)| (task, signal))
                            .collect(),
                        gate,
                        self.inner.configuration.executor(),
                        self.inner.configuration.post_cancellation_drain(),
                    )
                    .await;
                    return durable
                        .reject_prepared_resume(
                            prepared,
                            ResumeStartFailureCategory::Internal,
                            "resume-task-submission-failure",
                        )
                        .await;
                }
            }
        }

        let control_gate = Arc::clone(&gate);
        let control_slot = Arc::clone(&runtime_slot);
        let control_inner = Arc::clone(&self.inner);
        let fallback_slot = Arc::clone(&runtime_slot);
        let fallback_inner = Arc::clone(&self.inner);
        let control_abnormal: AbnormalCompletionHandler = Arc::new(move |_| {
            let Some(runtime) = lock_shutdown(&fallback_slot).clone() else {
                return;
            };
            runtime
                .graph
                .require_failure_finalization(DurableRunFailure::Internal);
            let fallback_inner = Arc::clone(&fallback_inner);
            DurableGraphControlFallback::start(Box::pin(async move {
                let interpreter = Interpreter {
                    inner: fallback_inner,
                    external_owner: false,
                };
                interpreter.drive_recovered_durable_graph(runtime).await;
            }));
        });
        let control_registration = supervisor.prepare_deferred_with_completion(
            SupervisedTaskDomain::ControlPlane,
            Some(control_abnormal),
            None,
        );
        let control_signal = control_registration.signal();
        let task_control_signal = control_signal.clone();
        let control_task: OwnedTaskFuture = Box::pin(async move {
            if control_gate.wait().await {
                let runtime = lock_shutdown(&control_slot)
                    .clone()
                    .unwrap_or_else(|| unreachable!("released control gate has a graph"));
                let interpreter = Interpreter {
                    inner: control_inner,
                    external_owner: false,
                };
                interpreter.drive_recovered_durable_graph(runtime).await;
            }
            let _ = task_control_signal.settle();
            OwnedTaskResult::new()
        });
        let control_task = match supervisor.submit(
            control_registration,
            control_task,
            control_reservation.transfer(),
        ) {
            Ok(task) => task,
            Err(_) => {
                rollback_submitted_recovered_graph(
                    submitted_tasks
                        .into_iter()
                        .map(|(_, task, signal)| (task, signal))
                        .collect(),
                    gate,
                    self.inner.configuration.executor(),
                    self.inner.configuration.post_cancellation_drain(),
                )
                .await;
                return durable
                    .reject_prepared_resume(
                        prepared,
                        ResumeStartFailureCategory::Internal,
                        "resume-control-submission-failure",
                    )
                    .await;
            }
        };

        if admission.register_submitted_drivers().is_err() {
            let mut submitted = submitted_tasks
                .into_iter()
                .map(|(_, task, signal)| (task, signal))
                .collect::<Vec<_>>();
            submitted.push((control_task, control_signal));
            rollback_submitted_recovered_graph(
                submitted,
                gate,
                self.inner.configuration.executor(),
                self.inner.configuration.post_cancellation_drain(),
            )
            .await;
            return durable
                .reject_prepared_resume(
                    prepared,
                    ResumeStartFailureCategory::Internal,
                    "resume-driver-registration-failure",
                )
                .await;
        }
        let repaired = self
            .repair_prepared_lifecycle_events(
                durable,
                &mut prepared,
                admission.coordinator(),
                &operations,
                &mut next_event_sequence,
            )
            .await;
        let prepared_commit = match repaired {
            Ok(()) => durable.commit_prepared_resume_revision(&mut prepared).await,
            Err(failure) => Err(failure),
        };
        if let Err(failure) = prepared_commit {
            let mut submitted = submitted_tasks
                .into_iter()
                .map(|(_, task, signal)| (task, signal))
                .collect::<Vec<_>>();
            submitted.push((control_task, control_signal));
            rollback_submitted_recovered_graph(
                submitted,
                gate,
                self.inner.configuration.executor(),
                self.inner.configuration.post_cancellation_drain(),
            )
            .await;
            return durable.reject_prepared_resume_with(prepared, failure).await;
        }
        let initial_delivery_pending = match &prepared.recovered {
            PreparedDurableRecovery::Concurrent { recovered, .. } => {
                initial_delivery_pending
                    || recovered_events_have_pending_delivery(recovered.events())
            }
            PreparedDurableRecovery::Serial(_) => unreachable!("concurrent recovery"),
        };
        let frontier = match &prepared.recovered {
            PreparedDurableRecovery::Concurrent {
                latest_evidence_id,
                latest_sequence,
                ..
            } => (*latest_evidence_id, *latest_sequence),
            PreparedDurableRecovery::Serial(_) => {
                unreachable!("concurrent handoff retains concurrent recovery")
            }
        };

        self.mark_durable_execution(prepared.execution_id);
        let accepted = match durable.publish_prepared_resume(prepared) {
            Ok(accepted) => accepted,
            Err(prepared) => {
                self.abandon_durable_execution(prepared.execution_id);
                unreachable!("reserved concurrent resume identity remains publishable")
            }
        };
        let (coordinator, foreground, children, unfinished_task_ids) = admission.into_parts();
        #[cfg(feature = "test-support")]
        {
            let gate = lock_shutdown(&self.inner.durable_handoff_test_gate).clone();
            if let Some(gate) = gate {
                gate.pause(accepted.handle().clone());
            }
        }
        let root_task_id = coordinator.snapshot().state().root_task_id();
        let drive_recovered_root = !terminal && !unfinished_task_ids.contains(&root_task_id);
        let mut task_signals = Vec::with_capacity(submitted_tasks.len());
        let task_handles = submitted_tasks
            .into_iter()
            .map(|(task_id, task, signal)| {
                task_signals.push(signal);
                (task_id, task)
            })
            .collect::<BTreeMap<_, _>>();
        debug_assert_eq!(task_handles.len(), unfinished_task_ids.len());
        let delivery_enabled = initial_delivery_pending
            || accepted
                .owned
                .graph_event_plan()
                .is_ok_and(|plan| !plan.obligations().is_empty());
        let graph = SharedDurableMachineGraph::new_recovered(
            DurableMachineGraph {
                foreground,
                children,
                frontier,
                next_event_sequence,
            },
            delivery_enabled,
            initial_delivery_pending,
            terminal,
            task_handles,
            recovered_submissions,
            operation_recoveries,
            &accepted.owned,
            Arc::clone(&program),
            operations.clone(),
        );
        if accepted.owned.begin_driver().is_some() {
            unreachable!("concurrent owner carries no serial recovered state");
        }
        accepted.owned.activate_graph_driver();
        *lock_shutdown(&runtime_slot) = Some(RecoveredDurableGraphRuntime {
            graph,
            owner: Arc::clone(&accepted.owned),
            coordinator,
            program,
            operations,
            drive_recovered_root,
        });
        for signal in task_signals {
            let _ = signal.arm_completion_observation();
        }
        let _ = control_signal.arm_completion_observation();
        control_task.relinquish();
        // Registry consumers must never observe an owner without its graph runtime.
        self.register_durable_execution(Arc::clone(&accepted.owned));
        gate.release();
        DurableResumeExecutionResult::Accepted(Box::new(accepted))
    }

    /// Repairs committed lifecycle causes before releasing replacement task gates.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn repair_prepared_lifecycle_events(
        &self,
        durable: &DurableStartExecutionCoordinator<'_>,
        prepared: &mut PreparedDurableResume,
        coordinator: &ExecutionCoordinator,
        operations: &DurableOperationContext,
        sequences: &mut BTreeMap<ProtocolIdentity, u64>,
    ) -> Result<(), crate::durable_start::ResumeRejection> {
        let failure = || {
            crate::durable_start::ResumeRejection::new(
                ResumeStartFailureCategory::Internal,
                "lifecycle-event-recovery-failure",
            )
        };
        let drafts = match &prepared.recovered {
            PreparedDurableRecovery::Concurrent { recovered, .. } => recovered
                .missing_lifecycle_events()
                .map_err(|_| failure())?,
            PreparedDurableRecovery::Serial(_) => return Err(failure()),
        };
        for (cause, task, draft) in drafts {
            let sequence = sequences.get(&task).copied().unwrap_or(0);
            let next = sequence.checked_add(1).ok_or_else(failure)?;
            let event = self.complete_graph_event(operations, task, sequence, draft.clone());
            durable
                .repair_prepared_event(prepared, cause, event, &draft.protected_payloads)
                .await?;
            sequences.insert(task, next);
        }
        durable.commit_prepared_resume_revision(prepared).await?;
        if let PreparedDurableRecovery::Concurrent { recovered, .. } = &prepared.recovered {
            coordinator
                .publish_committed_events(recovered.events().clone())
                .unwrap_or_else(|_| unreachable!("unpublished recovery has no competing writer"));
        }
        Ok(())
    }

    #[cfg(feature = "durable")]
    fn recovered_root_driver(
        &self,
        prepared: &PreparedDurableResume,
    ) -> Result<RecoveredRootDriver, &'static str> {
        let sessions = prepared
            .recovered
            .sessions()
            .cloned()
            .ok_or("missing-logical-sessions")?;
        let (root_session_id, provenance) = {
            let root = sessions
                .sessions()
                .find(|session| session.parent.is_none())
                .ok_or("missing-root-session")?;
            let provenance = match root.mode {
                SessionCreationModeV1::EmbedderRoot => RootSessionProvenanceV1::EmbedderSupplied,
                SessionCreationModeV1::GantryRoot => RootSessionProvenanceV1::GantryCreated,
                SessionCreationModeV1::New | SessionCreationModeV1::Fork => {
                    return Err("invalid-root-session");
                }
            };
            (root.id, provenance)
        };
        let task_id = root_task_identity(prepared.execution_id);
        let tasks = ConcurrentTaskStateV1::from_sequential_recovery(
            prepared.execution_id,
            task_id,
            self.inner.configuration.maximum_tasks_per_execution(),
            prepared.recovered.latest_cut(),
            prepared.recovered.machine().outcome().cloned(),
        )
        .map_err(|_| "invalid-recovered-task-state")?;
        #[cfg(feature = "concurrent")]
        let coordinator = ExecutionCoordinator::new_with_budget(
            tasks,
            sessions,
            prepared.recovered.machine().execution_budget(),
        )
        .map_err(|_| "invalid-recovered-task-state")?;
        #[cfg(not(feature = "concurrent"))]
        let coordinator = ExecutionCoordinator::new(tasks, sessions)
            .map_err(|_| "invalid-recovered-task-state")?;
        let create_request = TaskContextV1 {
            execution_id: prepared.execution_id,
            task_id,
            inherited_agent: prepared.recovered.machine().active_agent().map(Arc::from),
            session: TaskSessionContextV1::Root {
                root_session_id,
                provenance,
            },
        }
        .into_host_request()
        .map_err(|_| "invalid-recovered-hook-context")?;
        let declared_value_shapes = prepared
            .candidate_package_activity
            .as_ref()
            .and_then(|activity| activity.analysis.as_ref())
            .and_then(|analysis| analysis.declared_value_shapes())
            .cloned();
        let schemas = decode_retained_schemas(
            prepared.retained_artifacts.generated_schemas(),
            self.inner
                .configuration
                .required()
                .frontend_limits
                .maximum_constructed_type_depth(),
        )?;
        Ok(RecoveredRootDriver {
            coordinator,
            task_id,
            create_request,
            operations: DurableOperationContext {
                execution_id: prepared.execution_id,
                activity_id: prepared.activity_id,
                mapping_revisions: prepared.mapping_revisions.clone(),
                declared_value_shapes,
                schemas,
            },
            #[cfg(feature = "concurrent")]
            program: Arc::new(
                prepared
                    .recovered
                    .execution_start()
                    .ok_or("missing-execution-start")?
                    .program()
                    .map_err(|_| "invalid-retained-program")?,
            ),
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            root_supervision: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(feature = "durable")]
    fn start_owned_durable_submission_failure(
        &self,
        coordinator: ExecutionCoordinator,
        owner: Arc<crate::DurableOwnedExecution>,
        activity_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
    ) {
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve_control_plane() {
            Ok(reservation) => reservation,
            Err(_) => {
                if let Some(recovered) = owner.begin_driver() {
                    owner.fail_driver(recovered, DurableRunFailure::Internal);
                }
                return;
            }
        };
        let registration = supervisor.prepare(SupervisedTaskDomain::ControlPlane, None);
        let signal = registration.signal();
        let inner = Arc::clone(&self.inner);
        let fallback_owner = Arc::clone(&owner);
        let task: OwnedTaskFuture = Box::pin(async move {
            let interpreter = Interpreter {
                inner,
                external_owner: false,
            };
            interpreter
                .settle_durable_submission_failure(coordinator, owner, activity_id, task_id)
                .await;
            let _ = signal.settle();
            OwnedTaskResult::new()
        });
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => task.relinquish(),
            Err(_) => {
                if let Some(recovered) = fallback_owner.begin_driver() {
                    fallback_owner.fail_driver(recovered, DurableRunFailure::Internal);
                }
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    fn start_durable_graph_finalizer(
        &self,
        graph: Arc<SharedDurableMachineGraph>,
        owner: Arc<crate::DurableOwnedExecution>,
        coordinator: ExecutionCoordinator,
        program: Arc<gantry_ir::MachineProgram>,
        operations: DurableOperationContext,
    ) -> Result<(), DurableRunFailure> {
        let supervisor = self.inner.lifecycle.task_supervisor();
        let Some(reservation) = graph.begin_control()? else {
            return Ok(());
        };
        let registration = supervisor.prepare(SupervisedTaskDomain::ControlPlane, None);
        let signal = registration.signal();
        let inner = Arc::clone(&self.inner);
        let fallback_graph = Arc::clone(&graph);
        let fallback_owner = Arc::clone(&owner);
        let fallback_coordinator = coordinator.clone();
        let fallback_program = Arc::clone(&program);
        let fallback_operations = operations.clone();
        let fallback_inner = Arc::clone(&self.inner);
        let task: OwnedTaskFuture = Box::pin(async move {
            let interpreter = Interpreter {
                inner,
                external_owner: false,
            };
            interpreter
                .drive_durable_graph_control(graph, owner, coordinator, program, operations)
                .await;
            let _ = signal.settle();
            OwnedTaskResult::new()
        });
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => {
                task.relinquish();
                Ok(())
            }
            Err(_) => {
                fallback_graph.require_failure_finalization(DurableRunFailure::Internal);
                DurableGraphControlFallback::start(Box::pin(async move {
                    let interpreter = Interpreter {
                        inner: fallback_inner,
                        external_owner: false,
                    };
                    interpreter
                        .drive_durable_graph_control(
                            fallback_graph,
                            fallback_owner,
                            fallback_coordinator,
                            fallback_program,
                            fallback_operations,
                        )
                        .await;
                }));
                Err(DurableRunFailure::Internal)
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn drive_durable_graph_control(
        &self,
        graph: Arc<SharedDurableMachineGraph>,
        owner: Arc<crate::DurableOwnedExecution>,
        coordinator: ExecutionCoordinator,
        program: Arc<gantry_ir::MachineProgram>,
        operations: DurableOperationContext,
    ) {
        loop {
            let (command, reservation) = graph.next_control_command(&self.inner.lifecycle).await;
            match command {
                DurableGraphControlCommand::DeliverCommittedEvents => {
                    let Some(reservation) = reservation else {
                        graph.request_failure(DurableRunFailure::Internal);
                        continue;
                    };
                    let Some(lease) = graph.acquire().await else {
                        continue;
                    };
                    let occurrence_frontier = lease.frontier.1;
                    let delivery_graph = Arc::clone(&graph);
                    let delivery_owner = Arc::clone(&owner);
                    let delivery_coordinator = coordinator.clone();
                    let delivery_program = Arc::clone(&program);
                    let delivery_inner = Arc::clone(&self.inner);
                    self.inner.lifecycle.spawn_reserved_event_delivery(
                        reservation,
                        async move {
                            let mut lease = lease;
                            let (frontier, barrier) = delivery_owner
                                .drain_graph_required_event_obligations_through(
                                    delivery_program,
                                    &delivery_coordinator,
                                    occurrence_frontier,
                                    &delivery_inner.allocator,
                                    delivery_inner.configuration.identity_source(),
                                    delivery_inner.event_delivery_runtime.as_ref(),
                                )
                                .await?;
                            lease.frontier = frontier;
                            Ok::<_, DurableRunFailure>((lease, barrier))
                        },
                        move |result| {
                            delivery_graph.finish_live_delivery(match result {
                                Ok(result) => result,
                                Err(_) => Err(DurableRunFailure::Internal),
                            });
                        },
                    );
                }
                DurableGraphControlCommand::DeliverCommittedEventsFinished { result } => {
                    match *result {
                        Ok((mut lease, barrier)) => {
                            if let DurableEventBarrierV1::RequiredExhausted(failure) = barrier {
                                let result =
                                    if owner.graph_required_delivery_failure_recorded(&failure) {
                                        Ok(())
                                    } else if coordinator.terminal_outcome().is_some() {
                                        owner.record_graph_post_terminal_delivery_failure(
                                            &coordinator,
                                            failure,
                                        )
                                    } else {
                                        owner.exclude_graph_event_sink(failure.sink_id.clone());
                                        let reason =
                                            owner.request_graph_cancellation(CancellationReason {
                                                category: CancellationReasonCategory::Runtime,
                                                message: Some(Arc::from(
                                                    "required-event-delivery-failure",
                                                )),
                                                causal_identity: None,
                                            });
                                        self.commit_durable_graph_cancellation_with_lease(
                                            &mut lease,
                                            &owner,
                                            &coordinator,
                                            reason,
                                        )
                                        .await
                                        .and_then(|()| {
                                            owner.record_graph_required_delivery_failure(failure)
                                        })
                                    };
                                if let Err(failure) = result {
                                    drop(lease);
                                    graph.request_failure(failure);
                                    continue;
                                }
                            }
                            graph.complete_live_delivery(lease.frontier.1);
                        }
                        Err(failure) => graph.request_failure(failure),
                    }
                }
                DurableGraphControlCommand::SettleAbnormalChild { task_id, outcome } => {
                    if let Err(failure) = self
                        .settle_durable_abnormal_child(
                            &graph,
                            &owner,
                            &coordinator,
                            &operations,
                            task_id,
                            outcome,
                        )
                        .await
                    {
                        graph.request_failure(failure);
                    }
                }
                DurableGraphControlCommand::DrainCancellation { task_id } => {
                    if let Err(failure) = self
                        .drain_durable_graph_cancellation(&owner, &coordinator, task_id)
                        .await
                    {
                        owner.fail_live_graph(failure);
                    }
                }
                DurableGraphControlCommand::Complete => {
                    if let Err(failure) = owner.publish_graph_terminal(&coordinator) {
                        let _ = owner.finish_failed_graph_driver(failure).await;
                        return;
                    }
                    let tasks = graph.take_tasks();
                    let physically_settled = self.drain_durable_graph_tasks(tasks).await;
                    if physically_settled {
                        let _ = owner.finish_graph_driver().await;
                    } else {
                        let _ = owner
                            .finish_failed_graph_driver(DurableRunFailure::Internal)
                            .await;
                    }
                    return;
                }
                DurableGraphControlCommand::FinishRecoveredTerminal => {
                    let tasks = graph.take_tasks();
                    let physically_settled = self.drain_durable_graph_tasks(tasks).await;
                    if physically_settled {
                        let _ = owner.finish_graph_driver().await;
                    } else {
                        let _ = owner
                            .finish_failed_graph_driver(DurableRunFailure::Internal)
                            .await;
                    }
                    return;
                }
                DurableGraphControlCommand::Fail(failure) => {
                    if let Ok(cancellation) = owner.execution_handle().cancellation_signal() {
                        let _ = cancellation.cancel();
                    }
                    let tasks = graph.take_tasks();
                    let _ = self.drain_durable_graph_tasks(tasks).await;
                    let _ = owner.finish_failed_graph_driver(failure).await;
                    return;
                }
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn drain_durable_graph_tasks(&self, tasks: Vec<SupervisedTask>) -> bool {
        for task in &tasks {
            let _ = task.request_abort();
        }
        let completion = deadline_race(
            self.inner.configuration.executor(),
            Box::pin(async {
                for task in &tasks {
                    let _ = task.completion().await;
                }
            }),
            self.inner.configuration.post_cancellation_drain(),
            None,
        )
        .await;
        let physically_settled = matches!(completion, DeadlineOutcome::Completed(()));
        for task in tasks {
            task.relinquish();
        }
        physically_settled
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn drive_recovered_durable_graph(&self, runtime: RecoveredDurableGraphRuntime) {
        let RecoveredDurableGraphRuntime {
            graph,
            owner,
            coordinator,
            program,
            operations,
            drive_recovered_root,
        } = runtime;
        let mut control = Box::pin(self.drive_durable_graph_control(
            Arc::clone(&graph),
            Arc::clone(&owner),
            coordinator.clone(),
            Arc::clone(&program),
            operations.clone(),
        ));
        if !drive_recovered_root {
            control.await;
            return;
        }
        let root_task_id = coordinator.snapshot().state().root_task_id();
        let mut root = Some(Box::pin(self.drive_durable_graph_task(
            Arc::clone(&graph),
            Arc::clone(&owner),
            coordinator,
            program,
            operations,
            root_task_id,
            None,
            None,
            0,
            true,
        )));
        std::future::poll_fn(|context| {
            if let Some(future) = root.as_mut() {
                match future.as_mut().poll(context) {
                    Poll::Ready(Ok(())) => root = None,
                    Poll::Ready(Err(failure)) => {
                        graph.require_failure_finalization(failure);
                        root = None;
                    }
                    Poll::Pending => {}
                }
            }
            control.as_mut().poll(context)
        })
        .await;
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn drain_durable_graph_cancellation(
        &self,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
    ) -> Result<(), DurableRunFailure> {
        let settlement = coordinator
            .wait_for_task_settlement(task_id)
            .map_err(|_| DurableRunFailure::Internal)?;
        if matches!(
            deadline_race(
                self.inner.configuration.executor(),
                Box::pin(settlement),
                self.inner.configuration.post_cancellation_drain(),
                None,
            )
            .await,
            DeadlineOutcome::Completed(_)
        ) {
            return Ok(());
        }

        let tasks = self
            .inner
            .lifecycle
            .task_supervisor()
            .request_abort_owned_tasks(owner.execution_id(), &[task_id]);
        if tasks.is_empty() {
            return Ok(());
        }
        match deadline_race(
            self.inner.configuration.executor(),
            Box::pin(wait_for_abort_and_completion(&tasks)),
            self.inner.configuration.post_cancellation_drain(),
            None,
        )
        .await
        {
            DeadlineOutcome::Completed(Ok(())) => Ok(()),
            DeadlineOutcome::Completed(Err(error)) | DeadlineOutcome::Failed(error) => {
                Err(DurableRunFailure::Executor(error))
            }
            DeadlineOutcome::TimedOut | DeadlineOutcome::Cancelled => {
                Err(DurableRunFailure::Internal)
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn settle_durable_abnormal_child(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        operations: &DurableOperationContext,
        task_id: ProtocolIdentity,
        outcome: MachineOutcome,
    ) -> Result<(), DurableRunFailure> {
        let outcome = coordinator
            .snapshot()
            .state()
            .task_cancellation_reason(task_id)
            .map_or(outcome, |reason| {
                MachineOutcome::Cancelled(Arc::from(reason))
            });
        let mut lease = graph.acquire().await.ok_or(DurableRunFailure::Internal)?;
        let sequence = lease
            .next_event_sequence
            .get(&task_id)
            .copied()
            .unwrap_or(0);
        let draft = machine_lifecycle_event(
            &MachineLabel::TaskSettled(outcome.clone()),
            operations.execution_id,
            task_id,
        )
        .ok_or(DurableRunFailure::Internal)?;
        let event = self
            .complete_graph_event(operations, task_id, sequence, draft.clone())
            .await?;
        let predecessor = lease.frontier;
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut *lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        transaction
            .update(|_, children, tasks, _| {
                children.remove(&task_id);
                tasks.mark_driver_physically_settled(task_id)?;
                tasks.settle(task_id, outcome)
            })
            .map_err(|_| DurableRunFailure::Internal)?;
        transaction
            .set_event(
                event,
                owner.graph_event_plan()?,
                draft.protected_payloads.to_vec(),
            )
            .map_err(DurableRunFailure::Commit)?;
        lease.frontier = owner
            .commit_graph_transaction(
                coordinator,
                transaction,
                predecessor,
                DurableCommitCutV1::TaskSettlement,
                task_id,
            )
            .await?;
        lease.next_event_sequence.insert(
            task_id,
            sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
        );
        Ok(())
    }

    #[cfg(feature = "durable")]
    async fn settle_durable_submission_failure(
        &self,
        coordinator: ExecutionCoordinator,
        owner: Arc<crate::DurableOwnedExecution>,
        activity_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
    ) {
        let Some(mut recovered) = owner.begin_driver() else {
            return;
        };
        let mut last_committed = recovered.clone();
        let mut task_event_sequence = 0_u64;
        let _ = recovered.machine_mut().fail_root_submission();
        loop {
            match recovered.machine_mut().step() {
                MachineStep::Transition(MachineLabel::Failure(_)) => {}
                MachineStep::Transition(MachineLabel::TaskSettled(outcome)) => {
                    if let Err(failure) = owner
                        .commit_driver_cut(&mut recovered, DurableCommitCutV1::TaskSettlement, None)
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    last_committed = recovered.clone();
                    let event = machine_lifecycle_event(
                        &MachineLabel::TaskSettled(outcome.clone()),
                        owner.execution_id(),
                        task_id,
                    )
                    .unwrap_or_else(|| unreachable!("task settlement has one event draft"));
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                }
                MachineStep::Transition(MachineLabel::ForegroundCompletion(outcome)) => {
                    if let Err(failure) = owner
                        .commit_driver_cut(
                            &mut recovered,
                            DurableCommitCutV1::ForegroundCompletion,
                            None,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    last_committed = recovered.clone();
                    let event = machine_lifecycle_event(
                        &MachineLabel::ForegroundCompletion(outcome.clone()),
                        owner.execution_id(),
                        task_id,
                    )
                    .unwrap_or_else(|| unreachable!("foreground completion has one event draft"));
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                    if let Err(failure) = owner.publish_driver_progress(&recovered) {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                }
                MachineStep::Transition(MachineLabel::TerminalCompletion(outcome)) => {
                    if let Err(failure) = owner
                        .commit_driver_cut(
                            &mut recovered,
                            DurableCommitCutV1::TerminalCompletion,
                            None,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    last_committed = recovered.clone();
                    let event = machine_lifecycle_event(
                        &MachineLabel::TerminalCompletion(outcome),
                        owner.execution_id(),
                        task_id,
                    )
                    .unwrap_or_else(|| unreachable!("terminal completion has one event draft"));
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                }
                MachineStep::Complete(_) => {
                    let _ = owner
                        .finish_driver_terminal(
                            recovered,
                            &self.inner.allocator,
                            self.inner.configuration.identity_source(),
                            self.inner.event_delivery_runtime.as_ref(),
                        )
                        .await;
                    return;
                }
                _ => {
                    owner.fail_driver(last_committed, DurableRunFailure::Internal);
                    return;
                }
            }
        }
    }

    #[cfg(feature = "durable")]
    async fn drive_durable_execution(
        &self,
        accepted: StartExecutionAccepted,
        prepared: PreparedRootDriver,
        owner: Arc<crate::DurableOwnedExecution>,
    ) {
        let operations = DurableOperationContext::from_start(&accepted);
        let PreparedRootDriver {
            machine: _,
            coordinator,
            task_id,
            workflow: _,
            create_request,
            #[cfg(feature = "concurrent")]
            program,
            #[cfg(feature = "concurrent")]
            root_supervision,
            ..
        } = prepared;
        self.drive_recovered_durable_execution(
            RecoveredRootDriver {
                coordinator,
                task_id,
                create_request,
                operations,
                #[cfg(feature = "concurrent")]
                program,
                #[cfg(feature = "concurrent")]
                root_supervision,
            },
            owner,
        )
        .await;
    }

    #[cfg(feature = "durable")]
    async fn drive_recovered_durable_execution(
        &self,
        driver: RecoveredRootDriver,
        owner: Arc<crate::DurableOwnedExecution>,
    ) {
        let Some(mut recovered) = owner.begin_driver() else {
            return;
        };
        let mut last_committed = recovered.clone();
        if let Err(failure) = owner.reconcile_driver_required_delivery_failure(&mut recovered) {
            owner.fail_driver(last_committed, failure);
            return;
        }
        let RecoveredRootDriver {
            coordinator,
            task_id,
            create_request,
            operations,
            #[cfg(feature = "concurrent")]
            program,
            #[cfg(feature = "concurrent")]
            root_supervision,
        } = driver;
        let cancellation = owner
            .execution_handle()
            .cancellation_signal()
            .unwrap_or_else(|_| unreachable!("accepted durable execution retains cancellation"));
        let mut hook = TaskHook::new(
            &self.inner.lifecycle,
            self.inner.hook_factory.as_ref(),
            AdapterPoison::default(),
            create_request,
        )
        .unwrap_or_else(|_| unreachable!("committed durable start retains hook context"));
        let mut model_session_occurrence = 0_u64;
        let mut task_event_sequence = match recovered_task_event_sequences(recovered.events()) {
            Ok(sequences) => sequences.get(&task_id).copied().unwrap_or(0),
            Err(_) => {
                owner.fail_driver(last_committed, DurableRunFailure::Internal);
                return;
            }
        };
        if let DurableOperationRecoveryV1::ReuseResult {
            operation_id,
            result_type,
            result_bytes,
        } = recovered.operation_recovery().clone()
        {
            let cause = recovered.semantic_evidence_id();
            if recovered.events().event_for_cause(cause).is_none() {
                let value = match decode_logical_value(
                    &result_bytes,
                    &result_type,
                    self.inner.configuration.required().value_limits,
                    operations.declared_value_shapes.as_ref(),
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                };
                let (kind, normalized) = match result_type.kind() {
                    TypeKind::Unit => (OperationResultEventKindV1::Unit, None),
                    TypeKind::Decision => (OperationResultEventKindV1::Decision, Some(&value)),
                    _ => (OperationResultEventKindV1::Value, Some(&value)),
                };
                let event =
                    match operation_result_event(operation_id, &result_type, kind, normalized) {
                        Ok(event) => event,
                        Err(_) => {
                            owner.fail_driver(last_committed, DurableRunFailure::Internal);
                            return;
                        }
                    };
                if let Err(failure) = self
                    .commit_durable_event(
                        &owner,
                        &mut recovered,
                        operations.activity_id,
                        task_id,
                        &mut task_event_sequence,
                        event,
                        &mut last_committed,
                    )
                    .await
                {
                    owner.fail_driver(last_committed, failure);
                    return;
                }
            }
        }
        loop {
            if let Some(reason) = owner.take_driver_cancellation() {
                if let Err(failure) = owner
                    .commit_driver_cancellation(&mut recovered, reason)
                    .await
                {
                    owner.fail_driver(last_committed, failure);
                    return;
                }
                last_committed = recovered.clone();
            }
            match recovered.machine_mut().step() {
                MachineStep::Transition(MachineLabel::TaskSettled(outcome)) => {
                    if let Err(failure) = owner
                        .commit_driver_cut(&mut recovered, DurableCommitCutV1::TaskSettlement, None)
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    last_committed = recovered.clone();
                    let event = machine_lifecycle_event(
                        &MachineLabel::TaskSettled(outcome.clone()),
                        operations.execution_id,
                        task_id,
                    )
                    .unwrap_or_else(|| unreachable!("task settlement has one event draft"));
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            operations.activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                }
                MachineStep::Transition(MachineLabel::ForegroundCompletion(outcome)) => {
                    if let Err(failure) = owner
                        .commit_driver_cut(
                            &mut recovered,
                            DurableCommitCutV1::ForegroundCompletion,
                            None,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    last_committed = recovered.clone();
                    let event = machine_lifecycle_event(
                        &MachineLabel::ForegroundCompletion(outcome.clone()),
                        operations.execution_id,
                        task_id,
                    )
                    .unwrap_or_else(|| unreachable!("foreground completion has one event draft"));
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            operations.activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                    if let Err(failure) = owner.publish_driver_progress(&recovered) {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                }
                MachineStep::Transition(MachineLabel::TerminalCompletion(outcome)) => {
                    if let Err(failure) = owner
                        .commit_driver_cut(
                            &mut recovered,
                            DurableCommitCutV1::TerminalCompletion,
                            None,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    last_committed = recovered.clone();
                    let event = machine_lifecycle_event(
                        &MachineLabel::TerminalCompletion(outcome),
                        operations.execution_id,
                        task_id,
                    )
                    .unwrap_or_else(|| unreachable!("terminal completion has one event draft"));
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            operations.activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                }
                #[cfg(feature = "concurrent")]
                MachineStep::Transition(MachineLabel::Deterministic {
                    kind,
                    workflow: _,
                    site: _,
                }) if kind.as_ref() == "joinall-empty" => {
                    let event = concurrent_join_event(
                        operations.execution_id,
                        task_id,
                        TaskControlSiteKind::JoinAll,
                        &[],
                        "succeeded",
                        Some(&TypeDescriptor::UNIT),
                        None,
                        task_event_sequence,
                    )
                    .map_err(|_| DurableRunFailure::Internal);
                    let Ok(event) = event else {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    };
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            operations.activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                    if let Err(failure) = owner.publish_driver_progress(&recovered) {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                }
                #[cfg(feature = "concurrent")]
                MachineStep::Transition(label @ MachineLabel::TaskControlSuspended(_))
                | MachineStep::Transition(label @ MachineLabel::Deterministic { .. }) => {
                    let initial_spawn = match label {
                        MachineLabel::TaskControlSuspended(suspension) => Some(suspension),
                        MachineLabel::Deterministic { .. }
                            if recovered.machine_mut().pending_task_control().is_some() =>
                        {
                            None
                        }
                        MachineLabel::Deterministic { .. } => continue,
                        _ => unreachable!("matched one task-control handoff label"),
                    };
                    let root_supervision = lock_shutdown(&root_supervision)
                        .take()
                        .ok_or(DurableRunFailure::Internal);
                    let control_reservation = self
                        .inner
                        .lifecycle
                        .task_supervisor()
                        .try_reserve_control_plane()
                        .map_err(|_| DurableRunFailure::Internal);
                    let (root_supervision, control_reservation) =
                        match (root_supervision, control_reservation) {
                            (Ok(root_supervision), Ok(control_reservation)) => {
                                (root_supervision, control_reservation)
                            }
                            _ => {
                                owner.fail_driver(last_committed, DurableRunFailure::Internal);
                                return;
                            }
                        };
                    let graph = SharedDurableMachineGraph::new(
                        DurableMachineGraph {
                            foreground: recovered.into_machine(),
                            children: BTreeMap::new(),
                            frontier: (
                                last_committed.latest_evidence_id(),
                                last_committed.latest_sequence(),
                            ),
                            next_event_sequence: BTreeMap::from([(task_id, task_event_sequence)]),
                        },
                        !owner
                            .graph_event_plan()
                            .is_ok_and(|plan| plan.obligations().is_empty()),
                        task_id,
                        root_supervision,
                        control_reservation,
                        &owner,
                        Arc::clone(&program),
                        operations.clone(),
                    );
                    owner.activate_graph_driver();
                    if !owner
                        .graph_event_plan()
                        .is_ok_and(|plan| plan.obligations().is_empty())
                        && let Err(failure) = self.start_durable_graph_finalizer(
                            Arc::clone(&graph),
                            Arc::clone(&owner),
                            coordinator.clone(),
                            Arc::clone(&program),
                            operations.clone(),
                        )
                    {
                        graph.request_failure(failure);
                        return;
                    }
                    let result = self
                        .drive_durable_graph_task(
                            Arc::clone(&graph),
                            Arc::clone(&owner),
                            coordinator.clone(),
                            Arc::clone(&program),
                            operations.clone(),
                            task_id,
                            Some(hook),
                            initial_spawn,
                            model_session_occurrence,
                            false,
                        )
                        .await;
                    if let Err(failure) = result {
                        graph.request_failure(failure.clone());
                        let _ = self.start_durable_graph_finalizer(
                            Arc::clone(&graph),
                            Arc::clone(&owner),
                            coordinator.clone(),
                            Arc::clone(&program),
                            operations.clone(),
                        );
                    }
                    return;
                }
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => {
                    match owner
                        .poll_driver_future(
                            &mut recovered,
                            &mut last_committed,
                            self.inner.configuration.executor().yield_now(),
                        )
                        .await
                    {
                        Ok(crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(()))) => {
                            if !recovered.machine_mut().resume_after_yield() {
                                owner.fail_driver(last_committed, DurableRunFailure::Internal);
                                return;
                            }
                        }
                        Ok(crate::durable_lifecycle::DurableDriverPoll::CancellationSettled) => {}
                        Ok(crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_))) => {
                            owner.fail_driver(last_committed, DurableRunFailure::Internal);
                            return;
                        }
                        Err(failure) => {
                            owner.fail_driver(last_committed, failure);
                            return;
                        }
                    }
                }
                MachineStep::Complete(_) => {
                    let _ = owner
                        .finish_driver_terminal(
                            recovered,
                            &self.inner.allocator,
                            self.inner.configuration.identity_source(),
                            self.inner.event_delivery_runtime.as_ref(),
                        )
                        .await;
                    return;
                }
                MachineStep::WaitingSessionScope(scope) => {
                    if let Err(failure) = self
                        .drive_durable_session_scope(
                            operations.execution_id,
                            task_id,
                            &mut recovered,
                            &scope,
                            &owner,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                }
                MachineStep::WaitingOperation(operation) => {
                    let result = if operation
                        .metadata
                        .as_ref()
                        .is_some_and(|metadata| metadata.kind == OperationSiteKind::Action)
                    {
                        self.drive_durable_action_operation(
                            &operations,
                            &mut recovered,
                            &mut hook,
                            &cancellation,
                            &operation,
                            &owner,
                            &mut task_event_sequence,
                            &mut last_committed,
                        )
                        .await
                    } else {
                        let result = self
                            .drive_durable_model_operation(
                                &operations,
                                &mut recovered,
                                &mut hook,
                                &cancellation,
                                &operation,
                                &owner,
                                model_session_occurrence,
                                &mut task_event_sequence,
                                &mut last_committed,
                            )
                            .await;
                        model_session_occurrence = model_session_occurrence.saturating_add(1);
                        result
                    };
                    if let Err(failure) = result {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                }
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    fn drive_durable_graph_task<'a>(
        &'a self,
        graph: Arc<SharedDurableMachineGraph>,
        owner: Arc<crate::DurableOwnedExecution>,
        coordinator: ExecutionCoordinator,
        program: Arc<gantry_ir::MachineProgram>,
        operations: DurableOperationContext,
        task_id: ProtocolIdentity,
        mut hook: Option<TaskHook<'a>>,
        mut initial_spawn: Option<MachineSpawnSuspension>,
        mut model_session_occurrence: u64,
        replay_recovered_task_control: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(), DurableRunFailure>> + Send + 'a>> {
        Box::pin(async move {
            if replay_recovered_task_control
                && let Some(DurableOperationRecoveryV1::ReuseResult {
                    operation_id,
                    result_type,
                    result_bytes,
                }) = graph.operation_recovery(task_id)
            {
                let mut lease = graph.acquire().await.ok_or(DurableRunFailure::Internal)?;
                let value = decode_logical_value(
                    &result_bytes,
                    &result_type,
                    self.inner.configuration.required().value_limits,
                    operations.declared_value_shapes.as_ref(),
                )
                .map_err(|_| DurableRunFailure::Internal)?;
                let (kind, normalized) = match result_type.kind() {
                    TypeKind::Unit => (OperationResultEventKindV1::Unit, None),
                    TypeKind::Decision => (OperationResultEventKindV1::Decision, Some(&value)),
                    _ => (OperationResultEventKindV1::Value, Some(&value)),
                };
                let draft = operation_result_event(operation_id, &result_type, kind, normalized)
                    .map_err(|_| DurableRunFailure::Internal)?;
                let sequence = lease
                    .next_event_sequence
                    .get(&task_id)
                    .copied()
                    .unwrap_or(0);
                let event =
                    self.complete_graph_event(&operations, task_id, sequence, draft.clone());
                let (frontier, repaired) = owner
                    .repair_recovered_graph_event(
                        Arc::clone(&program),
                        &coordinator,
                        |recovered| recovered.operation_result_cause(operation_id),
                        event,
                        &draft.protected_payloads,
                    )
                    .await?;
                lease.frontier = frontier;
                if repaired {
                    lease.next_event_sequence.insert(
                        task_id,
                        sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
                    );
                }
            }
            let execution_cancellation = owner
                .execution_handle()
                .cancellation_signal()
                .map_err(DurableRunFailure::Lifecycle)?;
            let cancellation = DurableTaskCancellation {
                execution: execution_cancellation,
                coordinator: coordinator.clone(),
                task_id,
            };
            let (mut staged_join, mut staged_detach) = {
                let lease = graph.acquire().await.ok_or(DurableRunFailure::Internal)?;
                let pending = if task_id == lease.foreground.task_id() {
                    lease.foreground.pending_task_control()
                } else {
                    lease
                        .children
                        .get(&task_id)
                        .and_then(Machine::pending_task_control)
                };
                if replay_recovered_task_control {
                    pending.map_or(Ok((None, None)), |pending| {
                        coordinator.recovered_staged_task_control(task_id, pending)
                    })
                } else {
                    Ok((
                        pending
                            .and_then(|control| control.join())
                            .filter(|(join, all)| *all && join.handles.is_empty())
                            .map(|_| JoinStartV1::Empty),
                        None,
                    ))
                }
                .map_err(|_| DurableRunFailure::Internal)?
            };
            'graph_driver: loop {
                if let Some(suspension) = initial_spawn.take() {
                    self.submit_durable_source_child_boxed(
                        Arc::clone(&graph),
                        Arc::clone(&owner),
                        coordinator.clone(),
                        Arc::clone(&program),
                        operations.clone(),
                        task_id,
                        suspension,
                    )
                    .await?;
                    continue;
                }

                let mut lease = match self
                    .poll_durable_graph_future(&graph, &owner, &coordinator, graph.acquire())
                    .await?
                {
                    crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Some(lease)) => {
                        lease
                    }
                    crate::durable_lifecycle::DurableGraphDriverPoll::Completed(None) => {
                        return Ok(());
                    }
                    crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                        match graph.acquire().await {
                            Some(lease) => lease,
                            None => return Ok(()),
                        }
                    }
                };
                let task_control_pending = if task_id == lease.foreground.task_id() {
                    lease.foreground.pending_task_control().is_some()
                } else {
                    lease
                        .children
                        .get(&task_id)
                        .ok_or(DurableRunFailure::Internal)?
                        .pending_task_control()
                        .is_some()
                };
                if !task_control_pending {
                    let predecessor = lease.frontier;
                    let root_task = coordinator.snapshot().state().root_task_id();
                    let DurableMachineGraph {
                        foreground,
                        children,
                        ..
                    } = &mut *lease;
                    let mut transaction = coordinator
                        .stage_graph(foreground, children)
                        .map_err(|_| DurableRunFailure::Internal)?;
                    let staged = transaction
                        .update(
                            |foreground,
                             children,
                             tasks,
                             _|
                             -> Result<Option<DurableStagedTaskControl>, TaskStateError> {
                                let machine = if foreground.task_id() == task_id {
                                    foreground
                                } else {
                                    children
                                        .get_mut(&task_id)
                                        .ok_or(TaskStateError::UnknownTask)?
                                };
                                let MachineStep::Transition(MachineLabel::Deterministic { .. }) =
                                    machine.step()
                                else {
                                    return Ok(None);
                                };
                                if let Some((join, join_all)) = machine
                                    .pending_task_control()
                                    .and_then(|pending| pending.join())
                                {
                                    let kind = if join_all {
                                        TaskControlSiteKind::JoinAll
                                    } else {
                                        TaskControlSiteKind::Join
                                    };
                                    let handle_names = join
                                        .handles
                                        .iter()
                                        .map(|handle| Arc::from(handle.name()))
                                        .collect::<Vec<_>>();
                                    let handles = join
                                        .handles
                                        .iter()
                                        .map(|handle| handle.identity())
                                        .collect::<Vec<_>>();
                                    let started = tasks.begin_source_join(
                                        task_id,
                                        join.workflow.clone(),
                                        join.site.clone(),
                                        kind,
                                        &handle_names,
                                        &handles,
                                    )?;
                                    return Ok(Some((Some(started), None)));
                                }
                                if let Some(detach) = machine
                                    .pending_task_control()
                                    .and_then(|pending| pending.detach())
                                {
                                    let ownership = tasks.detach_source_handle(
                                        task_id,
                                        detach.workflow.clone(),
                                        detach.site.clone(),
                                        Arc::from(detach.handle.name()),
                                        detach.handle.identity(),
                                    )?;
                                    return Ok(Some((None, Some(ownership))));
                                }
                                Ok(None)
                            },
                        )
                        .map_err(|_| DurableRunFailure::Internal)?;
                    if let Some((join, detach)) = staged {
                        let (cut, affected_task) =
                            if let Some(JoinStartV1::Started(ownership)) = join.as_ref() {
                                (
                                    DurableCommitCutV1::TaskOwnership,
                                    ownership
                                        .members()
                                        .first()
                                        .map(|member| member.task_id())
                                        .ok_or(DurableRunFailure::Internal)?,
                                )
                            } else if let Some(ownership) = detach.as_ref() {
                                (
                                    DurableCommitCutV1::TaskOwnership,
                                    ownership
                                        .members()
                                        .first()
                                        .map(|member| member.task_id())
                                        .ok_or(DurableRunFailure::Internal)?,
                                )
                            } else {
                                (DurableCommitCutV1::Checkpoint, root_task)
                            };
                        lease.frontier = owner
                            .commit_graph_transaction(
                                &coordinator,
                                transaction,
                                predecessor,
                                cut,
                                affected_task,
                            )
                            .await?;
                        staged_join = join;
                        staged_detach = detach;
                        continue;
                    }
                    drop(transaction);
                }
                let step = if task_id == lease.foreground.task_id() {
                    lease.foreground.step()
                } else {
                    lease
                        .children
                        .get_mut(&task_id)
                        .ok_or(DurableRunFailure::Internal)?
                        .step()
                };
                match step {
                    MachineStep::Transition(MachineLabel::TaskControlSuspended(suspension)) => {
                        drop(lease);
                        if replay_recovered_task_control
                            && !graph.wait_for_recovered_submission(task_id).await
                        {
                            return Err(DurableRunFailure::Internal);
                        }
                        if replay_recovered_task_control {
                            let pending = {
                                let lease =
                                    graph.acquire().await.ok_or(DurableRunFailure::Internal)?;
                                if task_id == lease.foreground.task_id() {
                                    lease.foreground.pending_spawn().is_some()
                                } else {
                                    lease
                                        .children
                                        .get(&task_id)
                                        .and_then(Machine::pending_spawn)
                                        .is_some()
                                }
                            };
                            if !pending {
                                continue 'graph_driver;
                            }
                        }
                        self.submit_durable_source_child_boxed(
                            Arc::clone(&graph),
                            Arc::clone(&owner),
                            coordinator.clone(),
                            Arc::clone(&program),
                            operations.clone(),
                            task_id,
                            suspension,
                        )
                        .await?;
                    }
                    MachineStep::Transition(MachineLabel::Deterministic { kind, .. })
                        if kind.as_ref() == "joinall-empty" =>
                    {
                        let sequence = lease
                            .next_event_sequence
                            .get(&task_id)
                            .copied()
                            .unwrap_or(0);
                        let draft = concurrent_join_event(
                            operations.execution_id,
                            task_id,
                            TaskControlSiteKind::JoinAll,
                            &[],
                            "succeeded",
                            Some(&TypeDescriptor::UNIT),
                            None,
                            sequence,
                        )
                        .map_err(|_| DurableRunFailure::Internal)?;
                        let event = self
                            .complete_graph_event(&operations, task_id, sequence, draft.clone())
                            .await?;
                        let predecessor = lease.frontier;
                        let root_task = coordinator.snapshot().state().root_task_id();
                        let DurableMachineGraph {
                            foreground,
                            children,
                            ..
                        } = &mut *lease;
                        let mut transaction = coordinator
                            .stage_graph(foreground, children)
                            .map_err(|_| DurableRunFailure::Internal)?;
                        transaction
                            .set_event(
                                event,
                                owner.graph_event_plan()?,
                                draft.protected_payloads.to_vec(),
                            )
                            .map_err(DurableRunFailure::Commit)?;
                        lease.frontier = owner
                            .commit_graph_transaction(
                                &coordinator,
                                transaction,
                                predecessor,
                                DurableCommitCutV1::Checkpoint,
                                root_task,
                            )
                            .await?;
                        lease.next_event_sequence.insert(
                            task_id,
                            sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
                        );
                        continue 'graph_driver;
                    }
                    MachineStep::Transition(MachineLabel::Deterministic { .. }) => {
                        match self
                            .drive_durable_task_control(
                                &graph,
                                &owner,
                                &coordinator,
                                &operations,
                                task_id,
                                lease,
                                &mut staged_join,
                                &mut staged_detach,
                                replay_recovered_task_control,
                            )
                            .await?
                        {
                            DurableTaskControlOutcome::Continue => continue 'graph_driver,
                            DurableTaskControlOutcome::Finished => return Ok(()),
                        }
                    }
                    MachineStep::Transition(MachineLabel::TaskSettled(outcome)) => {
                        let execution_cancelled = owner
                            .execution_handle()
                            .cancellation_signal()
                            .is_ok_and(|signal| signal.is_cancelled());
                        if matches!(
                            outcome,
                            MachineOutcome::Failed(_) | MachineOutcome::Cancelled(_)
                        ) && !execution_cancelled
                            && let Some(descendants) = self
                                .commit_durable_descendant_cancellation(
                                    &mut lease,
                                    &owner,
                                    &coordinator,
                                    task_id,
                                    &outcome,
                                )
                                .await?
                        {
                            drop(lease);
                            self.drain_durable_cancelled_descendants(
                                operations.execution_id,
                                &coordinator,
                                &descendants,
                            )
                            .await?;
                            continue 'graph_driver;
                        }
                        let outcome = coordinator
                            .snapshot()
                            .state()
                            .task_record(task_id)
                            .and_then(|record| record.pending_outcome().cloned())
                            .unwrap_or(outcome);
                        let sequence = lease
                            .next_event_sequence
                            .get(&task_id)
                            .copied()
                            .unwrap_or(0);
                        let draft = machine_lifecycle_event(
                            &MachineLabel::TaskSettled(outcome.clone()),
                            operations.execution_id,
                            task_id,
                        )
                        .ok_or(DurableRunFailure::Internal)?;
                        let event = self
                            .complete_graph_event(&operations, task_id, sequence, draft.clone())
                            .await?;
                        let predecessor = lease.frontier;
                        let DurableMachineGraph {
                            foreground,
                            children,
                            ..
                        } = &mut *lease;
                        let mut transaction = coordinator
                            .stage_graph(foreground, children)
                            .map_err(|_| DurableRunFailure::Internal)?;
                        transaction
                            .update(|_, children, tasks, _| {
                                if task_id != tasks.root_task_id() {
                                    children.remove(&task_id);
                                }
                                if tasks
                                    .task_record(task_id)
                                    .is_some_and(|record| record.pending_outcome().is_some())
                                {
                                    tasks.settle_staged_task(task_id)
                                } else {
                                    tasks.settle(task_id, outcome)
                                }
                            })
                            .map_err(|_| DurableRunFailure::Internal)?;
                        transaction
                            .set_event(
                                event,
                                owner.graph_event_plan()?,
                                draft.protected_payloads.to_vec(),
                            )
                            .map_err(DurableRunFailure::Commit)?;
                        lease.frontier = owner
                            .commit_graph_transaction(
                                &coordinator,
                                transaction,
                                predecessor,
                                DurableCommitCutV1::TaskSettlement,
                                task_id,
                            )
                            .await?;
                        lease.next_event_sequence.insert(
                            task_id,
                            sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
                        );
                        if task_id != coordinator.snapshot().state().root_task_id() {
                            return Ok(());
                        }
                    }
                    MachineStep::Transition(MachineLabel::ForegroundCompletion(outcome)) => {
                        let attached = coordinator.shutdown_cohort().attached_tasks;
                        if !attached.is_empty() {
                            let machine = if task_id == lease.foreground.task_id() {
                                &mut lease.foreground
                            } else {
                                lease
                                    .children
                                    .get_mut(&task_id)
                                    .ok_or(DurableRunFailure::Internal)?
                            };
                            machine.defer_transition(MachineLabel::ForegroundCompletion(
                                outcome.clone(),
                            ));
                            drop(lease);
                            for child in attached {
                                let wait = coordinator
                                    .wait_for_task_settlement(child)
                                    .map_err(|_| DurableRunFailure::Internal)?;
                                if matches!(
                                    self
                                    .poll_durable_graph_future_with_retention(
                                        &graph,
                                        &owner,
                                        &coordinator,
                                        wait,
                                        true,
                                    )
                                    .await?,
                                    crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled
                                )
                                {
                                    continue 'graph_driver;
                                }
                            }
                            continue 'graph_driver;
                        }
                        self.commit_durable_graph_lifecycle(
                            &mut lease,
                            &owner,
                            &coordinator,
                            &operations,
                            task_id,
                            MachineLabel::ForegroundCompletion(outcome),
                            DurableCommitCutV1::ForegroundCompletion,
                        )
                        .await?;
                        let occurrence_frontier = lease.frontier.1;
                        drop(lease);
                        if !graph.wait_for_live_delivery(occurrence_frontier).await {
                            return Err(DurableRunFailure::Internal);
                        }
                        owner.publish_graph_foreground(&coordinator)?;
                    }
                    MachineStep::Transition(MachineLabel::TerminalCompletion(outcome)) => {
                        let detached = coordinator.shutdown_cohort().detached_tasks;
                        if !detached.is_empty() {
                            let machine = if task_id == lease.foreground.task_id() {
                                &mut lease.foreground
                            } else {
                                lease
                                    .children
                                    .get_mut(&task_id)
                                    .ok_or(DurableRunFailure::Internal)?
                            };
                            machine.defer_transition(MachineLabel::TerminalCompletion(
                                outcome.clone(),
                            ));
                            drop(lease);
                            for child in detached {
                                let wait = coordinator
                                    .wait_for_task_settlement(child)
                                    .map_err(|_| DurableRunFailure::Internal)?;
                                if matches!(
                                    self
                                    .poll_durable_graph_future_with_retention(
                                        &graph,
                                        &owner,
                                        &coordinator,
                                        wait,
                                        true,
                                    )
                                    .await?,
                                    crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled
                                )
                                {
                                    continue 'graph_driver;
                                }
                            }
                            continue 'graph_driver;
                        }
                        self.commit_durable_graph_lifecycle(
                            &mut lease,
                            &owner,
                            &coordinator,
                            &operations,
                            task_id,
                            MachineLabel::TerminalCompletion(outcome),
                            DurableCommitCutV1::TerminalCompletion,
                        )
                        .await?;
                        drop(lease);
                        graph.request_completion();
                        self.start_durable_graph_finalizer(
                            Arc::clone(&graph),
                            Arc::clone(&owner),
                            coordinator.clone(),
                            Arc::clone(&program),
                            operations.clone(),
                        )?;
                        return Ok(());
                    }
                    MachineStep::Transition(MachineLabel::OperationPrepared(_)) => {}
                    MachineStep::Transition(MachineLabel::OperationResult { operation }) => {
                        match graph.take_operation_recovery(task_id) {
                            Some(DurableOperationRecoveryV1::ReuseResult {
                                operation_id, ..
                            }) if operation_id == operation => {}
                            Some(_) => return Err(DurableRunFailure::Internal),
                            None => {}
                        }
                    }
                    MachineStep::Transition(_) => {}
                    MachineStep::YieldRequired => {
                        drop(lease);
                        match self
                            .poll_durable_graph_future(
                                &graph,
                                &owner,
                                &coordinator,
                                self.inner.configuration.executor().yield_now(),
                            )
                            .await?
                        {
                            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Ok(())) => {}
                            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Err(_)) => {
                                return Err(DurableRunFailure::Internal)
                            }
                            crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                                continue
                            }
                        }
                        let mut lease = match self
                            .poll_durable_graph_future(
                                &graph,
                                &owner,
                                &coordinator,
                                graph.acquire(),
                            )
                            .await?
                        {
                            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Some(
                                lease,
                            )) => lease,
                            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(None) => {
                                return Ok(())
                            }
                            crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                                continue
                            }
                        };
                        let machine = if task_id == lease.foreground.task_id() {
                            &mut lease.foreground
                        } else {
                            lease
                                .children
                                .get_mut(&task_id)
                                .ok_or(DurableRunFailure::Internal)?
                        };
                        if !machine.resume_after_yield() {
                            return Err(DurableRunFailure::Internal);
                        }
                    }
                    MachineStep::WaitingOperation(operation) => {
                        drop(lease);
                        let recovery = graph.take_operation_recovery(task_id);
                        if operation
                            .metadata
                            .as_ref()
                            .is_some_and(|metadata| metadata.kind == OperationSiteKind::Action)
                        {
                            self.drive_durable_graph_action_operation(
                                &graph,
                                &owner,
                                &coordinator,
                                &operations,
                                task_id,
                                hook.as_mut().ok_or(DurableRunFailure::Internal)?,
                                &cancellation,
                                &operation,
                                recovery,
                            )
                            .await?;
                        } else {
                            Box::pin(self.drive_durable_graph_model_operation(
                                &graph,
                                &owner,
                                &coordinator,
                                &operations,
                                task_id,
                                hook.as_mut().ok_or(DurableRunFailure::Internal)?,
                                &cancellation,
                                &operation,
                                model_session_occurrence,
                                recovery,
                            ))
                            .await?;
                            model_session_occurrence = model_session_occurrence.saturating_add(1);
                        }
                    }
                    MachineStep::WaitingSessionScope(_) => {
                        return Err(DurableRunFailure::Internal);
                    }
                    MachineStep::Complete(_) => return Ok(()),
                }
            }
        })
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    fn drive_durable_task_control<'a>(
        &'a self,
        graph: &'a Arc<SharedDurableMachineGraph>,
        owner: &'a Arc<crate::DurableOwnedExecution>,
        coordinator: &'a ExecutionCoordinator,
        operations: &'a DurableOperationContext,
        task_id: ProtocolIdentity,
        lease: DurableMachineGraphLease,
        staged_join: &'a mut Option<JoinStartV1>,
        staged_detach: &'a mut Option<TaskOwnershipChangedV1>,
        replay_recovered_task_control: bool,
    ) -> Pin<
        Box<dyn Future<Output = Result<DurableTaskControlOutcome, DurableRunFailure>> + Send + 'a>,
    > {
        Box::pin(async move {
            if let Some((suspension, join_all)) = if task_id == lease.foreground.task_id() {
                lease.foreground.pending_task_control()
            } else {
                lease
                    .children
                    .get(&task_id)
                    .and_then(Machine::pending_task_control)
            }
            .and_then(|pending| pending.join())
            .map(|(join, all)| (join.clone(), all))
            {
                let kind = if join_all {
                    TaskControlSiteKind::JoinAll
                } else {
                    TaskControlSiteKind::Join
                };
                let started = staged_join.take().ok_or(DurableRunFailure::Internal)?;
                let joined_task_ids = match &started {
                    JoinStartV1::Empty => Vec::new(),
                    JoinStartV1::Started(ownership) => ownership
                        .members()
                        .iter()
                        .map(|member| member.task_id())
                        .collect::<Vec<_>>(),
                };
                drop(lease);
                let resolution = match started {
                    JoinStartV1::Empty => JoinResolutionV1::Succeeded(LogicalValue::unit()),
                    JoinStartV1::Started(ownership) => {
                        let wait = coordinator
                            .wait_for_join(
                                ownership,
                                self.inner.configuration.required().value_limits,
                            )
                            .map_err(|_| DurableRunFailure::Internal)?;
                        match self
                            .poll_durable_graph_future(
                                graph,
                                owner,
                                coordinator,
                                wait,
                            )
                            .await?
                        {
                            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(
                                resolution,
                            ) => resolution.map_err(|_| DurableRunFailure::Internal)?,
                            crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                                return Ok(DurableTaskControlOutcome::Continue)
                            }
                        }
                    }
                };
                let (settlement_status, result_type, failure) = match &resolution {
                    JoinResolutionV1::Succeeded(_) => {
                        ("succeeded", Some(&suspension.expected_type), None)
                    }
                    JoinResolutionV1::Failed(failure) => ("failed", None, Some(failure)),
                    JoinResolutionV1::Pending(_) => {
                        return Err(DurableRunFailure::Internal);
                    }
                };
                let sequence = {
                    let lease = match self
                        .poll_durable_graph_future(graph, owner, coordinator, graph.acquire())
                        .await?
                    {
                        crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Some(
                            lease,
                        )) => lease,
                        crate::durable_lifecycle::DurableGraphDriverPoll::Completed(None) => {
                            return Ok(DurableTaskControlOutcome::Finished);
                        }
                        crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                            return Ok(DurableTaskControlOutcome::Continue);
                        }
                    };
                    let sequence = lease
                        .next_event_sequence
                        .get(&task_id)
                        .copied()
                        .unwrap_or(0);
                    drop(lease);
                    sequence
                };
                let draft = concurrent_join_event(
                    operations.execution_id,
                    task_id,
                    kind,
                    &joined_task_ids,
                    settlement_status,
                    result_type,
                    failure,
                    sequence,
                )
                .map_err(|_| DurableRunFailure::Internal)?;
                let event = self.complete_graph_event(operations, task_id, sequence, draft.clone());
                let mut lease = match self
                    .poll_durable_graph_future(graph, owner, coordinator, graph.acquire())
                    .await?
                {
                    crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Some(lease)) => {
                        lease
                    }
                    crate::durable_lifecycle::DurableGraphDriverPoll::Completed(None) => {
                        return Ok(DurableTaskControlOutcome::Finished);
                    }
                    crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                        return Ok(DurableTaskControlOutcome::Continue);
                    }
                };
                let root_task = coordinator.snapshot().state().root_task_id();
                self.commit_task_control_event(
                    graph,
                    owner,
                    coordinator,
                    &mut lease,
                    task_id,
                    sequence,
                    replay_recovered_task_control,
                    event,
                    &draft.protected_payloads,
                )
                .await?;

                let predecessor = lease.frontier;
                let DurableMachineGraph {
                    foreground,
                    children,
                    ..
                } = &mut *lease;
                let mut transaction = coordinator
                    .stage_graph(foreground, children)
                    .map_err(|_| DurableRunFailure::Internal)?;
                transaction.update(|foreground, children, _, _| {
                    let machine = if foreground.task_id() == task_id {
                        foreground
                    } else {
                        children
                            .get_mut(&task_id)
                            .ok_or(DurableRunFailure::Internal)?
                    };
                    machine
                        .complete_join(&suspension, resolution)
                        .map_err(|_| DurableRunFailure::Internal)?;
                    Ok::<_, DurableRunFailure>(())
                })?;
                lease.frontier = owner
                    .commit_graph_transaction(
                        coordinator,
                        transaction,
                        predecessor,
                        DurableCommitCutV1::Checkpoint,
                        root_task,
                    )
                    .await?;
            } else if let Some(suspension) = if task_id == lease.foreground.task_id() {
                lease.foreground.pending_task_control()
            } else {
                lease
                    .children
                    .get(&task_id)
                    .and_then(Machine::pending_task_control)
            }
            .and_then(|pending| pending.detach())
            .cloned()
            {
                let ownership = staged_detach.take().ok_or(DurableRunFailure::Internal)?;
                let sequence = lease
                    .next_event_sequence
                    .get(&task_id)
                    .copied()
                    .unwrap_or(0);
                let draft = concurrent_detach_event(operations.execution_id, &ownership, sequence)
                    .map_err(|_| DurableRunFailure::Internal)?;
                drop(lease);
                let event = self.complete_graph_event(operations, task_id, sequence, draft.clone());
                let mut lease = match self
                    .poll_durable_graph_future(graph, owner, coordinator, graph.acquire())
                    .await?
                {
                    crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Some(lease)) => {
                        lease
                    }
                    crate::durable_lifecycle::DurableGraphDriverPoll::Completed(None) => {
                        return Ok(DurableTaskControlOutcome::Finished);
                    }
                    crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                        return Ok(DurableTaskControlOutcome::Continue);
                    }
                };
                self.commit_task_control_event(
                    graph,
                    owner,
                    coordinator,
                    &mut lease,
                    task_id,
                    sequence,
                    replay_recovered_task_control,
                    event,
                    &draft.protected_payloads,
                )
                .await?;

                let predecessor = lease.frontier;
                let root_task = coordinator.snapshot().state().root_task_id();
                let DurableMachineGraph {
                    foreground,
                    children,
                    ..
                } = &mut *lease;
                let mut transaction = coordinator
                    .stage_graph(foreground, children)
                    .map_err(|_| DurableRunFailure::Internal)?;
                transaction.update(|foreground, children, _, _| {
                    let machine = if foreground.task_id() == task_id {
                        foreground
                    } else {
                        children
                            .get_mut(&task_id)
                            .ok_or(DurableRunFailure::Internal)?
                    };
                    machine
                        .complete_detach(&suspension)
                        .map_err(|_| DurableRunFailure::Internal)?;
                    Ok::<_, DurableRunFailure>(())
                })?;
                lease.frontier = owner
                    .commit_graph_transaction(
                        coordinator,
                        transaction,
                        predecessor,
                        DurableCommitCutV1::Checkpoint,
                        root_task,
                    )
                    .await?;
            }
            Ok(DurableTaskControlOutcome::Continue)
        })
    }

    /// Commits or repairs one task-control event without repeating its causal checkpoint.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn commit_task_control_event<F>(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        lease: &mut DurableMachineGraphLease,
        task_id: ProtocolIdentity,
        sequence: u64,
        replay_recovered_task_control: bool,
        event: F,
        payloads: &[gantry_host::event::ProtectedPayload],
    ) -> Result<(), DurableRunFailure>
    where
        F: Future<Output = Result<gantry_core::event::EventEnvelope, DurableRunFailure>>,
    {
        let recovered_cause = if replay_recovered_task_control {
            let machine = Self::durable_graph_machine_mut(lease, task_id)?;
            owner
                .recovered_task_control_event_cause(Arc::clone(&graph.program), machine)
                .await?
        } else {
            None
        };
        let created_event = if let Some(cause) = recovered_cause {
            let (frontier, repaired) = owner
                .repair_recovered_graph_event(
                    Arc::clone(&graph.program),
                    coordinator,
                    |_| Some(cause),
                    event,
                    payloads,
                )
                .await?;
            lease.frontier = frontier;
            repaired
        } else {
            let predecessor = lease.frontier;
            let root_task = coordinator.snapshot().state().root_task_id();
            let DurableMachineGraph {
                foreground,
                children,
                ..
            } = &mut **lease;
            let mut transaction = coordinator
                .stage_graph(foreground, children)
                .map_err(|_| DurableRunFailure::Internal)?;
            transaction
                .set_event(event.await?, owner.graph_event_plan()?, payloads.to_vec())
                .map_err(DurableRunFailure::Commit)?;
            lease.frontier = owner
                .commit_graph_transaction(
                    coordinator,
                    transaction,
                    predecessor,
                    DurableCommitCutV1::Checkpoint,
                    root_task,
                )
                .await?;
            true
        };
        if created_event {
            lease.next_event_sequence.insert(
                task_id,
                sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
            );
        }
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn poll_durable_graph_future<F>(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        future: F,
    ) -> Result<crate::durable_lifecycle::DurableGraphDriverPoll<F::Output>, DurableRunFailure>
    where
        F: Future,
    {
        self.poll_durable_graph_future_with_retention(graph, owner, coordinator, future, false)
            .await
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn poll_durable_graph_dispatch_future<F>(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        future: F,
    ) -> Result<crate::durable_lifecycle::DurableGraphDriverPoll<F::Output>, DurableRunFailure>
    where
        F: Future,
    {
        self.poll_durable_graph_future_with_cancellation_owner(
            graph,
            owner,
            coordinator,
            future,
            true,
            Some(task_id),
        )
        .await
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn poll_durable_graph_future_with_retention<F>(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        future: F,
        retain_to_settlement: bool,
    ) -> Result<crate::durable_lifecycle::DurableGraphDriverPoll<F::Output>, DurableRunFailure>
    where
        F: Future,
    {
        self.poll_durable_graph_future_with_cancellation_owner(
            graph,
            owner,
            coordinator,
            future,
            retain_to_settlement,
            None,
        )
        .await
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn poll_durable_graph_future_with_cancellation_owner<F>(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        future: F,
        retain_to_settlement: bool,
        cancellation_owner: Option<ProtocolIdentity>,
    ) -> Result<crate::durable_lifecycle::DurableGraphDriverPoll<F::Output>, DurableRunFailure>
    where
        F: Future,
    {
        let mut future = std::pin::pin!(future);
        let first = std::future::poll_fn(|context| match owner.poll_graph_cancellation(context) {
            crate::durable_lifecycle::DurableGraphCancellationPoll::Claimed(reason) => {
                Poll::Ready(Err(reason))
            }
            crate::durable_lifecycle::DurableGraphCancellationPoll::Waiting => Poll::Pending,
            crate::durable_lifecycle::DurableGraphCancellationPoll::Committed => {
                if let Some(task_id) = cancellation_owner {
                    graph.request_cancellation_drain(task_id);
                    if let Some(control_owner) = graph.owner.upgrade() {
                        let _ = self.start_durable_graph_finalizer(
                            Arc::clone(graph),
                            control_owner,
                            coordinator.clone(),
                            Arc::clone(&graph.program),
                            graph.operations.clone(),
                        );
                    } else {
                        graph.request_failure(DurableRunFailure::Internal);
                    }
                }
                if retain_to_settlement {
                    match future.as_mut().poll(context) {
                        Poll::Ready(_) => Poll::Ready(Ok(
                            crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled,
                        )),
                        Poll::Pending => Poll::Pending,
                    }
                } else {
                    Poll::Ready(Ok(
                        crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled,
                    ))
                }
            }
            crate::durable_lifecycle::DurableGraphCancellationPoll::Continue => {
                match future.as_mut().poll(context) {
                    Poll::Ready(output) => {
                        owner.clear_graph_driver_waker(context.waker());
                        Poll::Ready(Ok(
                            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(output),
                        ))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        })
        .await;
        match first {
            Ok(result) => Ok(result),
            Err(reason) => {
                let cancellation = self
                    .commit_durable_graph_cancellation(graph, owner, coordinator, reason)
                    .await;
                if cancellation.is_ok()
                    && let Some(task_id) = cancellation_owner
                {
                    graph.request_cancellation_drain(task_id);
                    let control_owner = graph.owner.upgrade().ok_or(DurableRunFailure::Internal)?;
                    self.start_durable_graph_finalizer(
                        Arc::clone(graph),
                        control_owner,
                        coordinator.clone(),
                        Arc::clone(&graph.program),
                        graph.operations.clone(),
                    )?;
                }
                if retain_to_settlement {
                    let _ = future.await;
                }
                cancellation?;
                Ok(crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled)
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn commit_durable_graph_cancellation(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        reason: CancellationReason,
    ) -> Result<(), DurableRunFailure> {
        let mut lease = graph.acquire().await.ok_or(DurableRunFailure::Internal)?;
        self.commit_durable_graph_cancellation_with_lease(&mut lease, owner, coordinator, reason)
            .await
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn commit_durable_graph_cancellation_with_lease(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        reason: CancellationReason,
    ) -> Result<(), DurableRunFailure> {
        let reason_text = reason
            .message
            .clone()
            .unwrap_or_else(|| Arc::from(reason.category.wire_name()));
        let predecessor = lease.frontier;
        let mut next_event_sequence = lease.next_event_sequence.clone();
        let operations = lease.shared.operations.clone();
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        let (affected, cancelled_tasks) = transaction
            .update(|foreground, children, tasks, _| {
                let affected = tasks.cancel_execution(Arc::clone(&reason_text))?;
                let mut cancelled_tasks = Vec::new();
                for task_id in &affected {
                    let label = if *task_id == foreground.task_id() {
                        foreground.cancel(Arc::clone(&reason_text))
                    } else if let Some(machine) = children.get_mut(task_id) {
                        machine.cancel(Arc::clone(&reason_text))
                    } else {
                        None
                    };
                    if label.is_some() {
                        cancelled_tasks.push(*task_id);
                    }
                }
                Ok::<_, TaskStateError>((affected, cancelled_tasks))
            })
            .map_err(|_| DurableRunFailure::Internal)?;
        let Some(affected_task) = affected.first().copied() else {
            lease.frontier = owner
                .commit_graph_transaction(
                    coordinator,
                    transaction,
                    predecessor,
                    DurableCommitCutV1::Cancellation,
                    coordinator.snapshot().state().root_task_id(),
                )
                .await?;
            owner.complete_graph_cancellation_without_cut();
            return Ok(());
        };
        let sequence = next_event_sequence
            .get(&affected_task)
            .copied()
            .unwrap_or(0);
        let draft = machine_lifecycle_event(
            &MachineLabel::Cancellation {
                reason: Arc::clone(&reason_text),
            },
            operations.execution_id,
            affected_task,
        )
        .ok_or(DurableRunFailure::Internal)?;
        let event = self
            .complete_graph_event(&operations, affected_task, sequence, draft.clone())
            .await?;
        transaction
            .set_event(
                event,
                owner.graph_event_plan()?,
                draft.protected_payloads.to_vec(),
            )
            .map_err(DurableRunFailure::Commit)?;
        next_event_sequence.insert(
            affected_task,
            sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
        );
        for task in cancelled_tasks {
            let sequence = next_event_sequence.get(&task).copied().unwrap_or(0);
            let draft = gantry_runtime::concurrent_task_cancellation_event(
                operations.execution_id,
                task,
                &reason_text,
                false,
                sequence,
            )
            .map_err(|_| DurableRunFailure::Internal)?;
            let event = self
                .complete_graph_event(&operations, task, sequence, draft)
                .await?;
            transaction
                .add_task_cancellation_event(event, owner.graph_event_plan()?)
                .map_err(DurableRunFailure::Commit)?;
            next_event_sequence.insert(
                task,
                sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
            );
        }
        lease.frontier = owner
            .commit_graph_transaction(
                coordinator,
                transaction,
                predecessor,
                DurableCommitCutV1::Cancellation,
                affected_task,
            )
            .await?;
        lease.next_event_sequence = next_event_sequence;
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn commit_durable_descendant_cancellation(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        outcome: &MachineOutcome,
    ) -> Result<Option<Vec<ProtocolIdentity>>, DurableRunFailure> {
        let reason: Arc<str> = match outcome {
            MachineOutcome::Failed(failure) => Arc::from(failure.code.wire_name()),
            MachineOutcome::Cancelled(reason) => Arc::clone(reason),
            MachineOutcome::Succeeded(_) => return Ok(None),
        };
        let already_cancelled = {
            let snapshot = coordinator.snapshot();
            let state = snapshot.state();
            let attached = state.shutdown_cohort().attached_tasks;
            attached.iter().all(|descendant| {
                state.task_cancellation_reason(*descendant).is_some()
                    || state
                        .task(*descendant)
                        .is_none_or(|task| task.parent_task_id() != task_id)
            })
        };
        if already_cancelled {
            let descendants = {
                let snapshot = coordinator.snapshot();
                let state = snapshot.state();
                let attached = state.shutdown_cohort().attached_tasks;
                let mut descendants = Vec::new();
                let mut frontier = vec![task_id];
                while let Some(parent_task_id) = frontier.pop() {
                    for child_task_id in &attached {
                        if descendants.contains(child_task_id) {
                            continue;
                        }
                        if state
                            .task(*child_task_id)
                            .is_some_and(|child| child.parent_task_id() == parent_task_id)
                        {
                            descendants.push(*child_task_id);
                            frontier.push(*child_task_id);
                        }
                    }
                }
                descendants
            };
            if descendants.is_empty() {
                return Ok(None);
            }
            let machine = Self::durable_graph_machine_mut(lease, task_id)?;
            machine.defer_transition(MachineLabel::TaskSettled(outcome.clone()));
            return Ok(Some(descendants));
        }
        let predecessor = lease.frontier;
        let operations = lease.shared.operations.clone();
        let mut next_event_sequence = lease.next_event_sequence.clone();
        let root_task = coordinator.snapshot().state().root_task_id();
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        let (descendants, affected, cancelled_tasks) = transaction
            .update(|foreground, children, tasks, _| {
                let attached = tasks.shutdown_cohort().attached_tasks;
                let mut descendants = Vec::new();
                let mut frontier = vec![task_id];
                while let Some(parent_task_id) = frontier.pop() {
                    for child_task_id in &attached {
                        if descendants.contains(child_task_id) {
                            continue;
                        }
                        if tasks
                            .task(*child_task_id)
                            .is_some_and(|child| child.parent_task_id() == parent_task_id)
                        {
                            descendants.push(*child_task_id);
                            frontier.push(*child_task_id);
                        }
                    }
                }
                if descendants.is_empty() {
                    return Ok((descendants, Vec::new(), Vec::new()));
                }

                match tasks
                    .task_record(task_id)
                    .and_then(|record| record.pending_outcome())
                {
                    Some(pending) if pending == outcome => {}
                    Some(_) => return Err(TaskStateError::InvalidTransition),
                    None => tasks.stage_task_outcome(task_id, outcome.clone())?,
                }
                let machine = if foreground.task_id() == task_id {
                    foreground
                } else {
                    children
                        .get_mut(&task_id)
                        .ok_or(TaskStateError::UnknownTask)?
                };
                machine.defer_transition(MachineLabel::TaskSettled(outcome.clone()));

                let direct_children = descendants
                    .iter()
                    .copied()
                    .filter(|child_task_id| {
                        tasks
                            .task(*child_task_id)
                            .is_some_and(|child| child.parent_task_id() == task_id)
                    })
                    .collect::<Vec<_>>();
                let mut affected = Vec::new();
                for child_task_id in direct_children {
                    affected.extend(tasks.cancel_task_tree(child_task_id, Arc::clone(&reason))?);
                }
                let mut cancelled_tasks = Vec::new();
                for affected_task_id in &affected {
                    if let Some(machine) = children.get_mut(affected_task_id)
                        && machine.cancel(Arc::clone(&reason)).is_some()
                    {
                        cancelled_tasks.push(*affected_task_id);
                    }
                }
                Ok::<_, TaskStateError>((descendants, affected, cancelled_tasks))
            })
            .map_err(|_| DurableRunFailure::Internal)?;
        if descendants.is_empty() {
            drop(transaction);
            return Ok(None);
        }

        for task in cancelled_tasks {
            let sequence = next_event_sequence.get(&task).copied().unwrap_or(0);
            let draft = gantry_runtime::concurrent_task_cancellation_event(
                operations.execution_id,
                task,
                &reason,
                false,
                sequence,
            )
            .map_err(|_| DurableRunFailure::Internal)?;
            let event = self
                .complete_graph_event(&operations, task, sequence, draft)
                .await?;
            transaction
                .add_task_cancellation_event(event, owner.graph_event_plan()?)
                .map_err(DurableRunFailure::Commit)?;
            next_event_sequence.insert(
                task,
                sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
            );
        }
        lease.frontier = if let Some(affected_task) = affected.first().copied() {
            owner
                .commit_graph_task_cancellation_transaction(
                    coordinator,
                    transaction,
                    predecessor,
                    affected_task,
                )
                .await?
        } else {
            owner
                .commit_graph_transaction(
                    coordinator,
                    transaction,
                    predecessor,
                    DurableCommitCutV1::Checkpoint,
                    root_task,
                )
                .await?
        };
        lease.next_event_sequence = next_event_sequence;
        Ok(Some(descendants))
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn drain_durable_cancelled_descendants(
        &self,
        execution_id: ProtocolIdentity,
        coordinator: &ExecutionCoordinator,
        descendants: &[ProtocolIdentity],
    ) -> Result<(), DurableRunFailure> {
        let selected = self
            .inner
            .lifecycle
            .task_supervisor()
            .owned_task_controls(execution_id, descendants);
        let waits = descendants
            .iter()
            .copied()
            .map(|task_id| coordinator.wait_for_task_settlement(task_id))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| DurableRunFailure::Internal)?;
        let graceful_controls = Arc::clone(&selected);
        let graceful = deadline_race(
            self.inner.configuration.executor(),
            Box::pin(async move {
                for wait in waits {
                    wait.await;
                }
                for task in graceful_controls.iter() {
                    let _ = task.completion().await;
                }
            }),
            self.inner.configuration.post_cancellation_drain(),
            None,
        )
        .await;
        if matches!(graceful, DeadlineOutcome::Completed(())) {
            return Ok(());
        }

        request_abort_for_active_controls(&selected);
        let physical = deadline_race(
            self.inner.configuration.executor(),
            Box::pin(wait_for_abort_and_completion(&selected)),
            self.inner.configuration.post_cancellation_drain(),
            None,
        )
        .await;
        if !matches!(physical, DeadlineOutcome::Completed(Ok(()))) {
            return Err(DurableRunFailure::Internal);
        }

        let waits = descendants
            .iter()
            .copied()
            .map(|task_id| coordinator.wait_for_task_settlement(task_id))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| DurableRunFailure::Internal)?;
        for wait in waits {
            wait.await;
        }
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn acquire_durable_graph_lease(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
    ) -> Result<Option<DurableMachineGraphLease>, DurableRunFailure> {
        match self
            .poll_durable_graph_future(graph, owner, coordinator, graph.acquire())
            .await?
        {
            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(lease) => Ok(lease),
            crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => Ok(None),
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn reconcile_durable_graph_cancellation(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        mut lease: DurableMachineGraphLease,
    ) -> Result<Option<DurableMachineGraphLease>, DurableRunFailure> {
        let cancellation = {
            let context = Context::from_waker(Waker::noop());
            owner.poll_graph_cancellation(&context)
        };
        match cancellation {
            crate::durable_lifecycle::DurableGraphCancellationPoll::Claimed(reason) => {
                self.commit_durable_graph_cancellation_with_lease(
                    &mut lease,
                    owner,
                    coordinator,
                    reason,
                )
                .await?;
                Ok(Some(lease))
            }
            crate::durable_lifecycle::DurableGraphCancellationPoll::Waiting => {
                drop(lease);
                self.acquire_durable_graph_lease(graph, owner, coordinator)
                    .await
            }
            crate::durable_lifecycle::DurableGraphCancellationPoll::Committed => Ok(Some(lease)),
            crate::durable_lifecycle::DurableGraphCancellationPoll::Continue => Ok(Some(lease)),
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    fn durable_graph_machine_mut(
        lease: &mut DurableMachineGraphLease,
        task_id: ProtocolIdentity,
    ) -> Result<&mut Machine, DurableRunFailure> {
        if task_id == lease.foreground.task_id() {
            Ok(&mut lease.foreground)
        } else {
            lease
                .children
                .get_mut(&task_id)
                .ok_or(DurableRunFailure::Internal)
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn fail_durable_graph_spawn(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        parent_task_id: ProtocolIdentity,
        suspension: &MachineSpawnSuspension,
        code: RuntimeCode,
    ) -> Result<(), DurableRunFailure> {
        Self::durable_graph_machine_mut(lease, parent_task_id)?
            .fail_spawn(suspension, code)
            .map_err(|_| DurableRunFailure::Internal)?;
        self.commit_durable_graph_checkpoint(lease, owner, coordinator)
            .await
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    fn submit_durable_source_child_boxed(
        &self,
        graph: Arc<SharedDurableMachineGraph>,
        owner: Arc<crate::DurableOwnedExecution>,
        coordinator: ExecutionCoordinator,
        program: Arc<gantry_ir::MachineProgram>,
        operations: DurableOperationContext,
        parent_task_id: ProtocolIdentity,
        suspension: MachineSpawnSuspension,
    ) -> Pin<Box<dyn Future<Output = Result<(), DurableRunFailure>> + Send + '_>> {
        Box::pin(self.submit_durable_source_child(
            graph,
            owner,
            coordinator,
            program,
            operations,
            parent_task_id,
            suspension,
        ))
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn submit_durable_source_child(
        &self,
        graph: Arc<SharedDurableMachineGraph>,
        owner: Arc<crate::DurableOwnedExecution>,
        coordinator: ExecutionCoordinator,
        program: Arc<gantry_ir::MachineProgram>,
        operations: DurableOperationContext,
        parent_task_id: ProtocolIdentity,
        suspension: MachineSpawnSuspension,
    ) -> Result<(), DurableRunFailure> {
        let task_limit_reached = |coordinator: &ExecutionCoordinator| {
            let snapshot = coordinator.snapshot();
            snapshot.state().created_task_count() >= snapshot.state().maximum_task_count()
        };
        let parent_is_cancelled = |coordinator: &ExecutionCoordinator| {
            coordinator
                .snapshot()
                .state()
                .task_cancellation_reason(parent_task_id)
                .is_some()
        };

        let Some(mut lease) = self
            .acquire_durable_graph_lease(&graph, &owner, &coordinator)
            .await?
        else {
            return Ok(());
        };
        if parent_is_cancelled(&coordinator)
            || Self::durable_graph_machine_mut(&mut lease, parent_task_id)?
                .outcome()
                .is_some()
        {
            return Ok(());
        }
        if task_limit_reached(&coordinator) {
            return self
                .fail_durable_graph_spawn(
                    &mut lease,
                    &owner,
                    &coordinator,
                    parent_task_id,
                    &suspension,
                    RuntimeCode::Deterministic(DeterministicEvaluationCode::TaskCountLimit),
                )
                .await;
        }
        let parent_session_id = suspension
            .parent_session
            .ok_or(DurableRunFailure::Internal)?;
        let parent_session = coordinator
            .session(parent_session_id)
            .ok_or(DurableRunFailure::Internal)?;
        drop(lease);
        let established = match self
            .poll_durable_graph_future(
                &graph,
                &owner,
                &coordinator,
                self.inner
                    .session_establisher
                    .establish(operations.execution_id, &parent_session),
            )
            .await?
        {
            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(established) => established,
            crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => return Ok(()),
        };
        let Some(mut lease) = self
            .acquire_durable_graph_lease(&graph, &owner, &coordinator)
            .await?
        else {
            return Ok(());
        };
        if parent_is_cancelled(&coordinator)
            || Self::durable_graph_machine_mut(&mut lease, parent_task_id)?
                .outcome()
                .is_some()
        {
            return Ok(());
        }
        if established.is_err() {
            return self
                .fail_durable_graph_spawn(
                    &mut lease,
                    &owner,
                    &coordinator,
                    parent_task_id,
                    &suspension,
                    RuntimeCode::Operation(RuntimeErrorCategory::LogicalSessionSetup),
                )
                .await;
        }
        if task_limit_reached(&coordinator) {
            return self
                .fail_durable_graph_spawn(
                    &mut lease,
                    &owner,
                    &coordinator,
                    parent_task_id,
                    &suspension,
                    RuntimeCode::Deterministic(DeterministicEvaluationCode::TaskCountLimit),
                )
                .await;
        }
        let sequence = lease
            .next_event_sequence
            .get(&parent_task_id)
            .copied()
            .unwrap_or(0);
        let captures = suspension
            .captures
            .iter()
            .map(|capture| capture.task_capture().clone())
            .collect::<Vec<_>>();
        let predecessor = lease.frontier;
        let root_task = coordinator.snapshot().state().root_task_id();
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut *lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        let created = match transaction.update(|_, _, tasks, sessions| {
            tasks.create_child(
                sessions,
                TaskCreationRequestV1 {
                    parent_task_id,
                    handle_name: Arc::from(suspension.handle.name()),
                    workflow: suspension.workflow.clone(),
                    spawn_site: suspension.site.clone(),
                    spawn_occurrence: suspension.occurrence,
                    result_type: suspension.handle.result_type().clone(),
                    captures: captures.clone(),
                    inherited_agent: suspension.inherited_agent.clone(),
                    parent_session_id,
                },
                self.inner.configuration.required().value_limits,
            )
        }) {
            Ok(created) => created,
            Err(TaskStateError::TaskCountLimit) => {
                transaction
                    .update(|foreground, children, _, _| {
                        let parent = if foreground.task_id() == parent_task_id {
                            foreground
                        } else {
                            children
                                .get_mut(&parent_task_id)
                                .ok_or(TaskStateError::UnknownTask)?
                        };
                        parent
                            .fail_spawn(
                                &suspension,
                                RuntimeCode::Deterministic(
                                    DeterministicEvaluationCode::TaskCountLimit,
                                ),
                            )
                            .map(|_| ())
                            .map_err(|_| TaskStateError::InvalidTransition)
                    })
                    .map_err(|_| DurableRunFailure::Internal)?;
                lease.frontier = owner
                    .commit_graph_transaction(
                        &coordinator,
                        transaction,
                        predecessor,
                        DurableCommitCutV1::Checkpoint,
                        root_task,
                    )
                    .await?;
                return Ok(());
            }
            Err(TaskStateError::TaskCancelled) => return Ok(()),
            Err(_) => return Err(DurableRunFailure::Internal),
        };
        let draft = concurrent_spawn_event(operations.execution_id, &created.transition, sequence)
            .map_err(|_| DurableRunFailure::Internal)?;
        let event = self
            .complete_graph_event(&operations, parent_task_id, sequence, draft.clone())
            .await?;
        transaction
            .set_event(
                event,
                owner.graph_event_plan()?,
                draft.protected_payloads.to_vec(),
            )
            .map_err(DurableRunFailure::Commit)?;
        lease.frontier = owner
            .commit_graph_transaction(
                &coordinator,
                transaction,
                predecessor,
                DurableCommitCutV1::TaskCreation,
                created.task_id,
            )
            .await?;
        lease.next_event_sequence.insert(
            parent_task_id,
            sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
        );

        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve(AdmissionClass::SourceChildTask) {
            Ok(reservation) => reservation,
            Err(_) => {
                self.commit_durable_child_submission_resolution(
                    &mut lease,
                    &owner,
                    &coordinator,
                    &operations,
                    parent_task_id,
                    &created,
                    &suspension,
                    None,
                )
                .await?;
                return Ok(());
            }
        };

        let snapshot = coordinator.snapshot();
        let child_record = snapshot
            .state()
            .task(created.task_id)
            .ok_or(DurableRunFailure::Internal)?;
        let child_session = coordinator
            .session(created.base_session_id)
            .ok_or(DurableRunFailure::Internal)?;
        let root_session = coordinator
            .session(child_session.root)
            .ok_or(DurableRunFailure::Internal)?;
        let root_provenance = match root_session.mode {
            SessionCreationModeV1::EmbedderRoot => RootSessionProvenanceV1::EmbedderSupplied,
            SessionCreationModeV1::GantryRoot => RootSessionProvenanceV1::GantryCreated,
            SessionCreationModeV1::New | SessionCreationModeV1::Fork => {
                return Err(DurableRunFailure::Internal);
            }
        };
        let child_machine = match Machine::new_concurrent_task_body_with_context(
            Arc::clone(&program),
            &suspension.body,
            &captures,
            operations.execution_id,
            created.task_id,
            Arc::from(child_record.task_path()),
            self.inner.configuration.machine_limits(),
            lease.foreground.execution_budget(),
            suspension.inherited_agent.clone(),
            Some(created.base_session_id),
        ) {
            Ok(machine) => machine,
            Err(_) => {
                drop(reservation);
                self.commit_durable_child_submission_resolution(
                    &mut lease,
                    &owner,
                    &coordinator,
                    &operations,
                    parent_task_id,
                    &created,
                    &suspension,
                    None,
                )
                .await?;
                return Ok(());
            }
        };
        let create_request = match (TaskContextV1 {
            execution_id: operations.execution_id,
            task_id: created.task_id,
            inherited_agent: suspension.inherited_agent.clone(),
            session: TaskSessionContextV1::Forked {
                base_session_id: created.base_session_id,
                parent_session_id,
                root_session_id: child_session.root,
                root_provenance,
            },
        })
        .into_host_request()
        {
            Ok(request) => request,
            Err(_) => {
                drop(reservation);
                self.commit_durable_child_submission_resolution(
                    &mut lease,
                    &owner,
                    &coordinator,
                    &operations,
                    parent_task_id,
                    &created,
                    &suspension,
                    None,
                )
                .await?;
                return Ok(());
            }
        };

        let child_task_id = created.task_id;
        let task_graph = Arc::clone(&graph);
        let task_owner = Arc::clone(&owner);
        let task_coordinator = coordinator.clone();
        let task_program = Arc::clone(&program);
        let task_operations = operations.clone();
        let task_inner = Arc::clone(&self.inner);
        let task_session = child_session.clone();
        let task_future = Box::pin(async move {
            let interpreter = Interpreter {
                inner: task_inner,
                external_owner: false,
            };
            let (established, cancellation_settled) = match interpreter
                .poll_durable_graph_future(
                    &task_graph,
                    &task_owner,
                    &task_coordinator,
                    interpreter
                        .inner
                        .session_establisher
                        .establish(task_operations.execution_id, &task_session),
                )
                .await
            {
                Ok(crate::durable_lifecycle::DurableGraphDriverPoll::Completed(established)) => {
                    #[cfg(feature = "test-support")]
                    let cancellation_after_establishment = {
                        lock_shutdown(
                            &interpreter
                                .inner
                                .durable_cancel_after_child_session_establishment,
                        )
                        .take()
                    };
                    match interpreter
                        .poll_durable_graph_future(
                            &task_graph,
                            &task_owner,
                            &task_coordinator,
                            std::future::ready(()),
                        )
                        .await
                    {
                        Ok(crate::durable_lifecycle::DurableGraphDriverPoll::Completed(())) => {
                            #[cfg(feature = "test-support")]
                            if let Some(reason) = cancellation_after_establishment {
                                task_owner.request_graph_cancellation(reason);
                            }
                            (established, false)
                        }
                        Ok(
                            crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled,
                        ) => (Ok(()), true),
                        Err(failure) => {
                            task_graph.request_failure(failure.clone());
                            let _ = interpreter.start_durable_graph_finalizer(
                                Arc::clone(&task_graph),
                                Arc::clone(&task_owner),
                                task_coordinator,
                                task_program,
                                task_operations,
                            );
                            return Ok(());
                        }
                    }
                }
                Ok(crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled) => {
                    (Ok(()), true)
                }
                Err(failure) => {
                    task_graph.request_failure(failure.clone());
                    let _ = interpreter.start_durable_graph_finalizer(
                        Arc::clone(&task_graph),
                        Arc::clone(&task_owner),
                        task_coordinator,
                        task_program,
                        task_operations,
                    );
                    return Ok(());
                }
            };
            let hook = if cancellation_settled {
                None
            } else if established.is_err() {
                if let Some(mut lease) = task_graph.acquire().await
                    && let Some(machine) = lease.children.get_mut(&child_task_id)
                {
                    let _ = machine.fail_execution(
                        RuntimeErrorCategory::LogicalSessionSetup,
                        gantry_runtime::ExecutionFailureProjection::Full,
                    );
                }
                None
            } else {
                let mut lease = match task_graph.acquire().await {
                    Some(lease) => lease,
                    None => return Ok(()),
                };
                let cancellation = {
                    let context = Context::from_waker(Waker::noop());
                    task_owner.poll_graph_cancellation(&context)
                };
                match cancellation {
                    crate::durable_lifecycle::DurableGraphCancellationPoll::Claimed(reason) => {
                        if let Err(failure) = interpreter
                            .commit_durable_graph_cancellation_with_lease(
                                &mut lease,
                                &task_owner,
                                &task_coordinator,
                                reason,
                            )
                            .await
                        {
                            task_graph.request_failure(failure);
                        }
                        None
                    }
                    crate::durable_lifecycle::DurableGraphCancellationPoll::Waiting
                    | crate::durable_lifecycle::DurableGraphCancellationPoll::Committed => None,
                    crate::durable_lifecycle::DurableGraphCancellationPoll::Continue => {
                        let hook = TaskHook::new(
                            &interpreter.inner.lifecycle,
                            interpreter.inner.hook_factory.as_ref(),
                            AdapterPoison::default(),
                            create_request,
                        )
                        .map_err(|_| DurableRunFailure::Internal);
                        drop(lease);
                        Some(hook)
                    }
                }
            };
            let result = match hook.transpose() {
                Ok(hook) => {
                    interpreter
                        .drive_durable_graph_task(
                            Arc::clone(&task_graph),
                            Arc::clone(&task_owner),
                            task_coordinator.clone(),
                            Arc::clone(&task_program),
                            task_operations.clone(),
                            child_task_id,
                            hook,
                            None,
                            0,
                            false,
                        )
                        .await
                }
                Err(failure) => Err(failure),
            };
            if let Err(failure) = result {
                task_graph.request_failure(failure.clone());
                let _ = interpreter.start_durable_graph_finalizer(
                    Arc::clone(&task_graph),
                    Arc::clone(&task_owner),
                    task_coordinator,
                    task_program,
                    task_operations,
                );
            }
            Ok(())
        });
        let driver = TaskDriver::from_durable_graph_child(
            Arc::clone(&self.inner),
            coordinator.clone(),
            child_task_id,
            suspension.workflow.clone(),
            Arc::clone(&graph),
            Arc::clone(&owner),
            task_future,
        );
        let abnormal = driver.abnormal_completion_handler();
        let completion = driver.physical_completion_handler();
        let registration = supervisor.prepare_owned_deferred_with_completion(
            SupervisedTaskDomain::SourceChild,
            operations.execution_id,
            created.task_id,
            Some(abnormal),
            Some(completion),
        );
        let signal = registration.signal();
        let gate = Arc::new(RootStartGate::default());
        let task = driver.into_gated_owned_task(signal.clone(), Arc::clone(&gate));

        #[cfg(feature = "test-support")]
        if let Some(reason) = lock_shutdown(&self.inner.durable_cancel_before_child_submit).take() {
            owner.request_graph_cancellation(reason);
        }
        let Some(reconciled) = self
            .reconcile_durable_graph_cancellation(&graph, &owner, &coordinator, lease)
            .await?
        else {
            gate.cancel();
            drop(task);
            drop(reservation);
            return Ok(());
        };
        lease = reconciled;
        if parent_is_cancelled(&coordinator) {
            gate.cancel();
            drop(task);
            drop(reservation);
            self.settle_durable_cancelled_unsubmitted_child(
                &mut lease,
                &owner,
                &coordinator,
                parent_task_id,
                created.task_id,
                &suspension,
            )
            .await?;
            return Ok(());
        }

        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => {
                #[cfg(feature = "test-support")]
                if let Some(reason) =
                    lock_shutdown(&self.inner.durable_cancel_after_child_submit).take()
                {
                    owner.request_graph_cancellation(reason);
                }
                let reconciled = self
                    .reconcile_durable_graph_cancellation(&graph, &owner, &coordinator, lease)
                    .await;
                lease = match reconciled {
                    Ok(Some(lease)) => lease,
                    Ok(None) => {
                        self.rollback_submitted_source_child(task, &signal, &gate)
                            .await
                            .map_err(|_| DurableRunFailure::Internal)?;
                        return Ok(());
                    }
                    Err(failure) => {
                        self.rollback_submitted_source_child(task, &signal, &gate)
                            .await
                            .map_err(|_| DurableRunFailure::Internal)?;
                        return Err(failure);
                    }
                };
                if parent_is_cancelled(&coordinator) {
                    self.rollback_submitted_source_child(task, &signal, &gate)
                        .await
                        .map_err(|_| DurableRunFailure::Internal)?;
                    self.settle_durable_cancelled_unsubmitted_child(
                        &mut lease,
                        &owner,
                        &coordinator,
                        parent_task_id,
                        created.task_id,
                        &suspension,
                    )
                    .await?;
                    return Ok(());
                }
                let disposition = self
                    .commit_durable_child_submission_resolution(
                        &mut lease,
                        &owner,
                        &coordinator,
                        &operations,
                        parent_task_id,
                        &created,
                        &suspension,
                        Some(child_machine),
                    )
                    .await;
                match disposition {
                    Ok(false) => {
                        graph.register_task(child_task_id, task);
                        let _ = signal.arm_completion_observation();
                        gate.release();
                    }
                    Ok(true) => {
                        self.rollback_submitted_source_child(task, &signal, &gate)
                            .await
                            .map_err(|_| DurableRunFailure::Internal)?;
                    }
                    Err(failure) => {
                        self.rollback_submitted_source_child(task, &signal, &gate)
                            .await
                            .map_err(|_| DurableRunFailure::Internal)?;
                        return Err(failure);
                    }
                }
            }
            Err(_) => {
                self.commit_durable_child_submission_resolution(
                    &mut lease,
                    &owner,
                    &coordinator,
                    &operations,
                    parent_task_id,
                    &created,
                    &suspension,
                    None,
                )
                .await?;
            }
        }
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn settle_durable_cancelled_unsubmitted_child(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        parent_task_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        suspension: &MachineSpawnSuspension,
    ) -> Result<(), DurableRunFailure> {
        let predecessor = lease.frontier;
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        transaction
            .update(|foreground, children, tasks, _| {
                let parent = if foreground.task_id() == parent_task_id {
                    foreground
                } else {
                    children
                        .get_mut(&parent_task_id)
                        .ok_or(TaskStateError::UnknownTask)?
                };
                let handle = tasks
                    .task(task_id)
                    .ok_or(TaskStateError::UnknownTask)?
                    .handle_id();
                parent
                    .complete_cancelled_spawn(suspension, handle)
                    .map_err(|_| TaskStateError::InvalidTransition)?;
                tasks.resolve_submission(task_id, Ok(()))?;
                tasks.mark_driver_physically_settled(task_id)?;
                Ok::<_, TaskStateError>(())
            })
            .map_err(|_| DurableRunFailure::Internal)?;
        lease.frontier = owner
            .commit_graph_transaction(
                coordinator,
                transaction,
                predecessor,
                DurableCommitCutV1::TaskSettlement,
                task_id,
            )
            .await?;
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn commit_durable_child_submission_resolution(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        operations: &DurableOperationContext,
        parent_task_id: ProtocolIdentity,
        created: &gantry_runtime::TaskCreationV1,
        suspension: &MachineSpawnSuspension,
        child_machine: Option<Machine>,
    ) -> Result<bool, DurableRunFailure> {
        let completed_event = if child_machine.is_none() {
            let sequence = lease
                .next_event_sequence
                .get(&created.task_id)
                .copied()
                .unwrap_or(0);
            let outcome = MachineOutcome::Failed(MachineFailure {
                code: RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure),
                workflow: suspension.workflow.clone(),
                site: suspension.site.clone(),
                #[cfg(feature = "concurrent")]
                join_failure: None,
            });
            let draft = machine_lifecycle_event(
                &MachineLabel::TaskSettled(outcome),
                operations.execution_id,
                created.task_id,
            )
            .ok_or(DurableRunFailure::Internal)?;
            let event = self
                .complete_graph_event(operations, created.task_id, sequence, draft.clone())
                .await?;
            Some((sequence, event, draft))
        } else {
            None
        };
        let predecessor = lease.frontier;
        let root_task = coordinator.snapshot().state().root_task_id();
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        let submitted = child_machine.is_some();
        let disposition = transaction
            .update(|foreground, children, tasks, _| {
                let parent = if foreground.task_id() == parent_task_id {
                    foreground
                } else {
                    children
                        .get_mut(&parent_task_id)
                        .ok_or(TaskStateError::UnknownTask)?
                };
                parent
                    .complete_spawn(suspension, created.handle_id)
                    .map_err(|_| TaskStateError::InvalidTransition)?;
                tasks.resolve_submission(
                    created.task_id,
                    if submitted {
                        Ok(())
                    } else {
                        Err(HostError {
                            code: Arc::from("task-submission-failure"),
                            protected_diagnostic: None,
                        })
                    },
                )
            })
            .map_err(|_| DurableRunFailure::Internal)?;
        if disposition != gantry_core::portable::TaskStatusKind::Cancelled
            && let Some(machine) = child_machine
        {
            transaction
                .install_child_machine(created.task_id, machine)
                .map_err(|_| DurableRunFailure::Internal)?;
        }
        if disposition == gantry_core::portable::TaskStatusKind::Failed
            && let Some((_, event, draft)) = &completed_event
        {
            transaction
                .set_event(
                    event.clone(),
                    owner.graph_event_plan()?,
                    draft.protected_payloads.to_vec(),
                )
                .map_err(DurableRunFailure::Commit)?;
        }
        let (cut, affected_task) =
            if submitted && disposition != gantry_core::portable::TaskStatusKind::Cancelled {
                (DurableCommitCutV1::Checkpoint, root_task)
            } else {
                (DurableCommitCutV1::TaskSettlement, created.task_id)
            };
        lease.frontier = owner
            .commit_graph_transaction(coordinator, transaction, predecessor, cut, affected_task)
            .await?;
        if disposition == gantry_core::portable::TaskStatusKind::Failed
            && let Some((sequence, _, _)) = completed_event
        {
            lease.next_event_sequence.insert(
                created.task_id,
                sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
            );
        }
        Ok(disposition == gantry_core::portable::TaskStatusKind::Cancelled)
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn drive_durable_graph_action_operation(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        context: &DurableOperationContext,
        task_id: ProtocolIdentity,
        hook: &mut TaskHook<'_>,
        cancellation: &dyn CancellationToken,
        occurrence: &gantry_runtime::OperationOccurrence,
        recovery: Option<DurableOperationRecoveryV1>,
    ) -> Result<(), DurableRunFailure> {
        let metadata = occurrence
            .metadata
            .as_ref()
            .ok_or(DurableRunFailure::Internal)?;
        let action = metadata
            .action
            .as_ref()
            .ok_or(DurableRunFailure::Internal)?;
        if metadata.kind != OperationSiteKind::Action
            || action.parameters.len() != occurrence.inputs.len()
        {
            return Err(DurableRunFailure::Internal);
        }
        let expected_schema = context
            .schema(&metadata.result_type)
            .ok_or(DurableRunFailure::Internal)?;
        let mapping_revision = context
            .mapping_revisions
            .action
            .clone()
            .ok_or(DurableRunFailure::Internal)?;
        let captured = CapturedOperationRequestV1::Action {
            header: OperationRequestHeaderV1 {
                execution_id: context.execution_id,
                task_id,
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self
                    .inner
                    .configuration
                    .required()
                    .maximum_hook_output_bytes,
                value_limits: self.inner.configuration.required().value_limits,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: ActionOperationRequestV1 {
                path: action.path.clone(),
                signature: action.signature.clone(),
                recovery: action.recovery,
                mapping_revision,
                arguments: action
                    .parameters
                    .iter()
                    .zip(occurrence.inputs.iter())
                    .map(|(parameter, value)| TypedActionArgumentV1 {
                        name: Arc::from(parameter.name()),
                        ty: parameter.ty().clone(),
                        value: value.canonical_json(),
                    })
                    .collect(),
            },
        };
        let mut operation =
            OperationLifecycle::new(captured).map_err(|_| DurableRunFailure::Internal)?;
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            self.inner.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        let recovery = recovery.unwrap_or(DurableOperationRecoveryV1::None);
        let mut reused_outcome_request = match &recovery {
            DurableOperationRecoveryV1::ReuseOutcome { request_bytes, .. } => {
                Some(Arc::clone(request_bytes))
            }
            _ => None,
        };
        operation
            .recover(
                &recovery,
                policy,
                &self.inner.allocator,
                self.inner.configuration.identity_source(),
            )
            .map_err(|_| DurableRunFailure::Internal)?;
        Box::pin(self.repair_recovered_operation_dispatch(
            graph,
            owner,
            coordinator,
            context,
            task_id,
            &operation,
            &recovery,
        ))
        .await?;
        if matches!(recovery, DurableOperationRecoveryV1::UnknownOutcome { .. }) {
            let Some(mut lease) = self
                .acquire_durable_graph_lease(graph, owner, coordinator)
                .await?
            else {
                return Ok(());
            };
            let machine = Self::durable_graph_machine_mut(&mut lease, task_id)?;
            if metadata.attempted {
                operation
                    .accept_attempt_failure(machine)
                    .map_err(|_| DurableRunFailure::Internal)?;
            } else {
                let failure = operation
                    .lifecycle_failure()
                    .and_then(|failure| match failure {
                        OperationLifecycleFailureV1::Operation(failure) => Some(failure),
                        _ => None,
                    })
                    .ok_or(DurableRunFailure::Internal)?;
                machine
                    .fail_operation(occurrence.identity, failure.runtime_category())
                    .map_err(|_| DurableRunFailure::Internal)?;
            }
            self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                .await?;
            return Ok(());
        }
        if matches!(recovery, DurableOperationRecoveryV1::RetryDelay { .. }) {
            let prepared = match self
                .poll_durable_graph_future(
                    graph,
                    owner,
                    coordinator,
                    operation.prepare_after_retry_wait(
                        self.inner.configuration.executor(),
                        cancellation,
                        &self.inner.allocator,
                        self.inner.configuration.identity_source(),
                    ),
                )
                .await?
            {
                crate::durable_lifecycle::DurableGraphDriverPoll::Completed(result) => {
                    result.map_err(|_| DurableRunFailure::Internal)?
                }
                crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                    return Ok(());
                }
            };
            if prepared.is_none() {
                let Some(mut lease) = self
                    .acquire_durable_graph_lease(graph, owner, coordinator)
                    .await?
                else {
                    return Ok(());
                };
                Self::settle_retry_terminal(
                    Self::durable_graph_machine_mut(&mut lease, task_id)?,
                    occurrence,
                    &operation,
                )
                .map_err(|_| DurableRunFailure::Internal)?;
                self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                    .await?;
                return Ok(());
            }
        }
        let mut retries_left = operation.retries_left();

        loop {
            let action_recovery = Some(action.recovery);
            let (dispatch_id, request_bytes, validation_attempt, recovery_dispatch, outcome) =
                if let Some(request_bytes) = reused_outcome_request.take() {
                    self.repair_recovered_operation_completion(
                        graph,
                        owner,
                        coordinator,
                        context,
                        task_id,
                        &operation,
                    )
                    .await?;
                    let (dispatch_id, outcome, validation_attempt, recovery_dispatch) = operation
                        .outcome_context()
                        .ok_or(DurableRunFailure::Internal)?;
                    (
                        dispatch_id,
                        request_bytes,
                        validation_attempt,
                        recovery_dispatch,
                        outcome.clone(),
                    )
                } else {
                    let (prepared, validation_attempt, recovery_dispatch) = operation
                        .prepared_dispatch()
                        .ok_or(DurableRunFailure::Internal)?;
                    let dispatch_id = prepared.dispatch_id;
                    let request_bytes: Arc<[u8]> = Arc::from(prepared.request.canonical_bytes());
                    let dispatch_event = operation_dispatch_event(
                        operation.captured(),
                        prepared,
                        validation_attempt,
                        recovery_dispatch,
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    self.commit_durable_graph_operation_cut(
                        &mut lease,
                        owner,
                        coordinator,
                        context,
                        task_id,
                        DurableCommitCutV1::OperationPrepared,
                        DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: Some(dispatch_id),
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: None,
                            retries_left,
                            action_recovery,
                            request_bytes: Some(Arc::clone(&request_bytes)),
                            outcome: None,
                            retry_errors: Arc::from([]),
                            result_type: None,
                            result_bytes: None,
                        },
                        Some(dispatch_event),
                    )
                    .await?;
                    drop(lease);
                    let dispatch = match self
                        .poll_durable_graph_dispatch_future(
                            graph,
                            owner,
                            coordinator,
                            task_id,
                            operation.dispatch(hook, cancellation),
                        )
                        .await?
                    {
                        crate::durable_lifecycle::DurableGraphDriverPoll::Completed(result) => {
                            result
                        }
                        crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                            return Ok(());
                        }
                    };
                    if dispatch.is_err() {
                        let Some(mut lease) = self
                            .acquire_durable_graph_lease(graph, owner, coordinator)
                            .await?
                        else {
                            return Ok(());
                        };
                        let machine = Self::durable_graph_machine_mut(&mut lease, task_id)?;
                        let category = if hook.is_ready() {
                            RuntimeErrorCategory::HookFailure
                        } else {
                            RuntimeErrorCategory::HookCreation
                        };
                        machine
                            .fail_operation(occurrence.identity, category)
                            .map_err(|_| DurableRunFailure::Internal)?;
                        self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                            .await?;
                        return Ok(());
                    }
                    let (_, outcome, validation_attempt, recovery_dispatch) = operation
                        .outcome_context()
                        .ok_or(DurableRunFailure::Internal)?;
                    let outcome = outcome.clone();
                    let completion_event = operation_completion_event(
                        operation.captured(),
                        dispatch_id,
                        validation_attempt,
                        recovery_dispatch,
                        &outcome,
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    self.commit_durable_graph_operation_cut(
                        &mut lease,
                        owner,
                        coordinator,
                        context,
                        task_id,
                        DurableCommitCutV1::OperationOutcome,
                        DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: Some(dispatch_id),
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: None,
                            retries_left,
                            action_recovery,
                            request_bytes: Some(Arc::clone(&request_bytes)),
                            outcome: Some(outcome.clone()),
                            retry_errors: Arc::from([]),
                            result_type: None,
                            result_bytes: None,
                        },
                        Some(completion_event),
                    )
                    .await?;
                    drop(lease);
                    (
                        dispatch_id,
                        request_bytes,
                        validation_attempt,
                        recovery_dispatch,
                        outcome,
                    )
                };
            match operation
                .process_outcome(policy, self.inner.configuration.executor(), cancellation)
                .map_err(|_| DurableRunFailure::Internal)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let result_bytes: Arc<[u8]> = Arc::from(output.canonical_json().bytes());
                    let value = decode_logical_value(
                        &result_bytes,
                        &metadata.result_type,
                        self.inner.configuration.required().value_limits,
                        context.declared_value_shapes.as_ref(),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let (result_kind, result_value) = match metadata.result_type.kind() {
                        TypeKind::Unit => (OperationResultEventKindV1::Unit, None),
                        TypeKind::Decision => (OperationResultEventKindV1::Decision, Some(&value)),
                        _ => (OperationResultEventKindV1::Value, Some(&value)),
                    };
                    let result_event = operation_result_event(
                        occurrence.identity,
                        &metadata.result_type,
                        result_kind,
                        result_value,
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    let machine = Self::durable_graph_machine_mut(&mut lease, task_id)?;
                    if metadata.attempted {
                        operation.accept_attempt(machine, value)
                    } else {
                        operation.accept(machine, value)
                    }
                    .map_err(|_| DurableRunFailure::Internal)?;
                    self.commit_durable_graph_operation_cut(
                        &mut lease,
                        owner,
                        coordinator,
                        context,
                        task_id,
                        DurableCommitCutV1::OperationResult,
                        DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: None,
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: None,
                            retries_left,
                            action_recovery,
                            request_bytes: None,
                            outcome: None,
                            retry_errors: Arc::from([]),
                            result_type: Some(metadata.result_type.clone()),
                            result_bytes: Some(result_bytes),
                        },
                        Some(result_event),
                    )
                    .await?;
                    return Ok(());
                }
                ProcessedHookOutcomeV1::Retry(wait) => {
                    retries_left = Some(wait.retries_left);
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    self.commit_durable_graph_operation_cut(
                        &mut lease,
                        owner,
                        coordinator,
                        context,
                        task_id,
                        DurableCommitCutV1::RetryWaiting,
                        DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: Some(dispatch_id),
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: Some(wait.delay.get()),
                            retries_left,
                            action_recovery,
                            request_bytes: Some(request_bytes),
                            outcome: Some(outcome),
                            retry_errors: Arc::clone(&wait.errors),
                            result_type: None,
                            result_bytes: None,
                        },
                        None,
                    )
                    .await?;
                    drop(lease);
                    let prepared = match self
                        .poll_durable_graph_future(
                            graph,
                            owner,
                            coordinator,
                            operation.prepare_after_retry_wait(
                                self.inner.configuration.executor(),
                                cancellation,
                                &self.inner.allocator,
                                self.inner.configuration.identity_source(),
                            ),
                        )
                        .await?
                    {
                        crate::durable_lifecycle::DurableGraphDriverPoll::Completed(result) => {
                            result.map_err(|_| DurableRunFailure::Internal)?
                        }
                        crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                            return Ok(());
                        }
                    };
                    if prepared.is_none() {
                        let Some(mut lease) = self
                            .acquire_durable_graph_lease(graph, owner, coordinator)
                            .await?
                        else {
                            return Ok(());
                        };
                        let machine = if task_id == lease.foreground.task_id() {
                            &mut lease.foreground
                        } else {
                            lease
                                .children
                                .get_mut(&task_id)
                                .ok_or(DurableRunFailure::Internal)?
                        };
                        Self::settle_retry_terminal(machine, occurrence, &operation)
                            .map_err(|_| DurableRunFailure::Internal)?;
                        self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                            .await?;
                        return Ok(());
                    }
                }
                ProcessedHookOutcomeV1::Failed(failure) => {
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    let machine = Self::durable_graph_machine_mut(&mut lease, task_id)?;
                    if metadata.attempted
                        && matches!(
                            operation.lifecycle_failure(),
                            Some(OperationLifecycleFailureV1::Operation(_))
                        )
                    {
                        operation
                            .accept_attempt_failure(machine)
                            .map_err(|_| DurableRunFailure::Internal)?;
                    } else {
                        machine
                            .fail_operation(occurrence.identity, failure.runtime_category())
                            .map_err(|_| DurableRunFailure::Internal)?;
                    }
                    self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                        .await?;
                    return Ok(());
                }
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn drive_durable_graph_model_operation(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        context: &DurableOperationContext,
        task_id: ProtocolIdentity,
        hook: &mut TaskHook<'_>,
        cancellation: &dyn CancellationToken,
        occurrence: &gantry_runtime::OperationOccurrence,
        session_occurrence: u64,
        recovery: Option<DurableOperationRecoveryV1>,
    ) -> Result<(), DurableRunFailure> {
        let metadata = occurrence
            .metadata
            .as_ref()
            .ok_or(DurableRunFailure::Internal)?;
        let interpolation_count = metadata.interpolation_types.len();
        if !matches!(
            metadata.kind,
            OperationSiteKind::Prompt | OperationSiteKind::Decide
        ) || metadata.named_input_names.len() != metadata.named_input_types.len()
            || occurrence.inputs.len()
                != interpolation_count.saturating_add(metadata.named_input_types.len())
        {
            return Err(DurableRunFailure::Internal);
        }
        let expected_schema = context
            .schema(&metadata.result_type)
            .ok_or(DurableRunFailure::Internal)?;
        let selected_agent = occurrence
            .active_agent
            .clone()
            .ok_or(DurableRunFailure::Internal)?;
        let mapping_revision = context
            .mapping_revisions
            .agent
            .clone()
            .ok_or(DurableRunFailure::Internal)?;
        let parent_session_id = occurrence
            .active_session
            .ok_or(DurableRunFailure::Internal)?;
        let retained_session_id = recovery
            .as_ref()
            .map(OperationLifecycle::retained_model_session_id)
            .transpose()
            .map_err(|_| DurableRunFailure::Internal)?
            .flatten();
        let active_session_id = if let Some(session_id) = retained_session_id {
            let session = coordinator
                .session(session_id)
                .ok_or(DurableRunFailure::Internal)?;
            let valid = match metadata.session_mode.as_deref() {
                Some(mode @ ("fork" | "new")) => {
                    session.creator_task == Some(task_id)
                        && session.parent == Some(parent_session_id)
                        && session.creation_site.as_ref() == Some(&occurrence.site)
                        && session.establishment == SessionEstablishmentV1::OperationRequest
                        && session.mode
                            == if mode == "fork" {
                                SessionCreationModeV1::Fork
                            } else {
                                SessionCreationModeV1::New
                            }
                }
                None => session_id == parent_session_id,
                _ => false,
            };
            if !valid {
                return Err(DurableRunFailure::Internal);
            }
            session_id
        } else if let Some(mode) = metadata.session_mode.as_deref() {
            let mode = match mode {
                "fork" => SessionCreationModeV1::Fork,
                "new" => SessionCreationModeV1::New,
                _ => return Err(DurableRunFailure::Internal),
            };
            let Some(mut lease) = self
                .acquire_durable_graph_lease(graph, owner, coordinator)
                .await?
            else {
                return Ok(());
            };
            let predecessor = lease.frontier;
            let root_task = coordinator.snapshot().state().root_task_id();
            let DurableMachineGraph {
                foreground,
                children,
                ..
            } = &mut *lease;
            let mut transaction = coordinator
                .stage_graph(foreground, children)
                .map_err(|_| DurableRunFailure::Internal)?;
            let session_id = transaction
                .update(|_, _, _, sessions| {
                    sessions
                        .create(
                            parent_session_id,
                            task_id,
                            occurrence.site.clone(),
                            session_occurrence,
                            mode,
                            SessionEstablishmentV1::OperationRequest,
                        )
                        .map(|session| session.id)
                })
                .map_err(|_| DurableRunFailure::Internal)?;
            lease.frontier = owner
                .commit_graph_transaction(
                    coordinator,
                    transaction,
                    predecessor,
                    DurableCommitCutV1::Checkpoint,
                    root_task,
                )
                .await?;
            session_id
        } else {
            parent_session_id
        };
        let session = coordinator
            .session(active_session_id)
            .ok_or(DurableRunFailure::Internal)?;
        let interpolation_inputs = metadata
            .interpolation_types
            .iter()
            .zip(occurrence.inputs.iter().take(interpolation_count))
            .enumerate()
            .map(|(position, (ty, value))| {
                Ok(InterpolationInputV1 {
                    position: u64::try_from(position).map_err(|_| DurableRunFailure::Internal)?,
                    ty: ty.clone(),
                    value: value.canonical_json(),
                })
            })
            .collect::<Result<Vec<_>, DurableRunFailure>>()?;
        let named_inputs = metadata
            .named_input_names
            .iter()
            .zip(&metadata.named_input_types)
            .zip(occurrence.inputs.iter().skip(interpolation_count))
            .map(|((name, ty), value)| NamedInputV1 {
                name: Arc::clone(name),
                ty: ty.clone(),
                value: value.canonical_json(),
            })
            .collect::<Vec<_>>();
        let rendered_prompt = match render_prompt(
            &metadata.template_segments,
            occurrence.inputs.iter().take(interpolation_count),
            self.inner
                .configuration
                .required()
                .value_limits
                .maximum_string_scalars(),
        ) {
            Ok(prompt) => prompt,
            Err(RenderPromptError::Limit) => {
                let Some(mut lease) = self
                    .acquire_durable_graph_lease(graph, owner, coordinator)
                    .await?
                else {
                    return Ok(());
                };
                Self::durable_graph_machine_mut(&mut lease, task_id)?
                    .fail_operation_with_code(
                        occurrence.identity,
                        RuntimeCode::Deterministic(DeterministicEvaluationCode::StringSizeLimit),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                    .await?;
                return Ok(());
            }
            Err(RenderPromptError::Shape) => return Err(DurableRunFailure::Internal),
        };
        let session_use = if let Some(mode) = metadata.session_mode.as_ref() {
            ModelSessionUseV1::Create {
                mode: Arc::clone(mode),
                session_id: session.id,
                parent_session_id,
                root_session_id: session.root,
                provenance: Arc::from("operation-request"),
            }
        } else {
            ModelSessionUseV1::Inline
        };
        let captured = CapturedOperationRequestV1::Model {
            header: OperationRequestHeaderV1 {
                execution_id: context.execution_id,
                task_id,
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self
                    .inner
                    .configuration
                    .required()
                    .maximum_hook_output_bytes,
                value_limits: self.inner.configuration.required().value_limits,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: Box::new(ModelOperationRequestV1 {
                selected_agent: Arc::clone(&selected_agent),
                mapping_revision,
                template_segments: metadata.template_segments.clone(),
                rendered_prompt: Arc::clone(&rendered_prompt),
                interpolation_inputs: interpolation_inputs.clone(),
                named_inputs: named_inputs.clone(),
                transcript: session.transcript.clone(),
                active_session_id: session.id,
                parent_session_id: session.parent,
                root_session_id: session.root,
                session_use,
            }),
        };
        let mut operation =
            OperationLifecycle::new(captured).map_err(|_| DurableRunFailure::Internal)?;
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            self.inner.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        let recovery = recovery.unwrap_or(DurableOperationRecoveryV1::None);
        let mut reused_outcome_request = match &recovery {
            DurableOperationRecoveryV1::ReuseOutcome { request_bytes, .. } => {
                Some(Arc::clone(request_bytes))
            }
            _ => None,
        };
        operation
            .recover(
                &recovery,
                policy,
                &self.inner.allocator,
                self.inner.configuration.identity_source(),
            )
            .map_err(|_| DurableRunFailure::Internal)?;
        Box::pin(self.repair_recovered_operation_dispatch(
            graph,
            owner,
            coordinator,
            context,
            task_id,
            &operation,
            &recovery,
        ))
        .await?;
        if matches!(recovery, DurableOperationRecoveryV1::RetryDelay { .. }) {
            let prepared = match self
                .poll_durable_graph_future(
                    graph,
                    owner,
                    coordinator,
                    operation.prepare_after_retry_wait(
                        self.inner.configuration.executor(),
                        cancellation,
                        &self.inner.allocator,
                        self.inner.configuration.identity_source(),
                    ),
                )
                .await?
            {
                crate::durable_lifecycle::DurableGraphDriverPoll::Completed(result) => {
                    result.map_err(|_| DurableRunFailure::Internal)?
                }
                crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                    return Ok(());
                }
            };
            if prepared.is_none() {
                let Some(mut lease) = self
                    .acquire_durable_graph_lease(graph, owner, coordinator)
                    .await?
                else {
                    return Ok(());
                };
                Self::settle_retry_terminal(
                    Self::durable_graph_machine_mut(&mut lease, task_id)?,
                    occurrence,
                    &operation,
                )
                .map_err(|_| DurableRunFailure::Internal)?;
                self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                    .await?;
                return Ok(());
            }
        }
        let mut retries_left = operation.retries_left();

        loop {
            let (dispatch_id, request_bytes, validation_attempt, recovery_dispatch, outcome) =
                if let Some(request_bytes) = reused_outcome_request.take() {
                    Box::pin(self.repair_recovered_operation_completion(
                        graph,
                        owner,
                        coordinator,
                        context,
                        task_id,
                        &operation,
                    ))
                    .await?;
                    let (dispatch_id, outcome, validation_attempt, recovery_dispatch) = operation
                        .outcome_context()
                        .ok_or(DurableRunFailure::Internal)?;
                    (
                        dispatch_id,
                        request_bytes,
                        validation_attempt,
                        recovery_dispatch,
                        outcome.clone(),
                    )
                } else {
                    let (prepared, validation_attempt, recovery_dispatch) = operation
                        .prepared_dispatch()
                        .ok_or(DurableRunFailure::Internal)?;
                    let dispatch_id = prepared.dispatch_id;
                    let request_bytes: Arc<[u8]> = Arc::from(prepared.request.canonical_bytes());
                    let dispatch_event = operation_dispatch_event(
                        operation.captured(),
                        prepared,
                        validation_attempt,
                        recovery_dispatch,
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    self.commit_durable_graph_operation_cut(
                        &mut lease,
                        owner,
                        coordinator,
                        context,
                        task_id,
                        DurableCommitCutV1::OperationPrepared,
                        DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: Some(dispatch_id),
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: None,
                            retries_left,
                            action_recovery: None,
                            request_bytes: Some(Arc::clone(&request_bytes)),
                            outcome: None,
                            retry_errors: Arc::from([]),
                            result_type: None,
                            result_bytes: None,
                        },
                        Some(dispatch_event),
                    )
                    .await?;
                    drop(lease);

                    let dispatch = match self
                        .poll_durable_graph_dispatch_future(
                            graph,
                            owner,
                            coordinator,
                            task_id,
                            operation.dispatch_model(
                                hook,
                                cancellation,
                                &self.inner.session_establisher,
                                context.execution_id,
                                &session,
                            ),
                        )
                        .await?
                    {
                        crate::durable_lifecycle::DurableGraphDriverPoll::Completed(result) => {
                            result
                        }
                        crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                            return Ok(());
                        }
                    };
                    if let Err(error) = dispatch {
                        let category = match error {
                            OperationLifecycleError::Cancelled => {
                                RuntimeErrorCategory::Cancellation
                            }
                            OperationLifecycleError::Session(_) => {
                                RuntimeErrorCategory::LogicalSessionSetup
                            }
                            OperationLifecycleError::Hook(_) if hook.is_ready() => {
                                RuntimeErrorCategory::HookFailure
                            }
                            OperationLifecycleError::Hook(_) => RuntimeErrorCategory::HookCreation,
                            _ => return Err(DurableRunFailure::Internal),
                        };
                        let Some(mut lease) = self
                            .acquire_durable_graph_lease(graph, owner, coordinator)
                            .await?
                        else {
                            return Ok(());
                        };
                        Self::durable_graph_machine_mut(&mut lease, task_id)?
                            .fail_operation(occurrence.identity, category)
                            .map_err(|_| DurableRunFailure::Internal)?;
                        self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                            .await?;
                        return Ok(());
                    }

                    let (_, outcome, validation_attempt, recovery_dispatch) = operation
                        .outcome_context()
                        .ok_or(DurableRunFailure::Internal)?;
                    let outcome = outcome.clone();
                    let completion_event = operation_completion_event(
                        operation.captured(),
                        dispatch_id,
                        validation_attempt,
                        recovery_dispatch,
                        &outcome,
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    self.commit_durable_graph_operation_cut(
                        &mut lease,
                        owner,
                        coordinator,
                        context,
                        task_id,
                        DurableCommitCutV1::OperationOutcome,
                        DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: Some(dispatch_id),
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: None,
                            retries_left,
                            action_recovery: None,
                            request_bytes: Some(Arc::clone(&request_bytes)),
                            outcome: Some(outcome.clone()),
                            retry_errors: Arc::from([]),
                            result_type: None,
                            result_bytes: None,
                        },
                        Some(completion_event),
                    )
                    .await?;
                    drop(lease);

                    (
                        dispatch_id,
                        request_bytes,
                        validation_attempt,
                        recovery_dispatch,
                        outcome,
                    )
                };
            match operation
                .process_outcome(policy, self.inner.configuration.executor(), cancellation)
                .map_err(|_| DurableRunFailure::Internal)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let result_bytes: Arc<[u8]> = Arc::from(output.canonical_json().bytes());
                    let value = decode_logical_value(
                        &result_bytes,
                        &metadata.result_type,
                        self.inner.configuration.required().value_limits,
                        context.declared_value_shapes.as_ref(),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let turn = TranscriptTurnV1 {
                        operation_kind: metadata.kind,
                        template_representation: metadata.template_segments.clone(),
                        rendered_prompt: Arc::clone(&rendered_prompt),
                        interpolation_inputs: interpolation_inputs.clone(),
                        using_inputs: named_inputs.clone(),
                        selected_agent: Arc::clone(&selected_agent),
                        accepted_result: AcceptedTranscriptResultV1 {
                            kind: transcript_result_kind(&metadata.result_type),
                            ty: metadata.result_type.clone(),
                            value: value.canonical_json(),
                        },
                    };
                    let (result_kind, result_value) = match metadata.result_type.kind() {
                        TypeKind::Unit => (OperationResultEventKindV1::Unit, None),
                        TypeKind::Decision => (OperationResultEventKindV1::Decision, Some(&value)),
                        _ => (OperationResultEventKindV1::Value, Some(&value)),
                    };
                    let result_event = operation_result_event(
                        occurrence.identity,
                        &metadata.result_type,
                        result_kind,
                        result_value,
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    let sequence = lease
                        .next_event_sequence
                        .get(&task_id)
                        .copied()
                        .unwrap_or(0);
                    let completed_event = self
                        .complete_graph_event(context, task_id, sequence, result_event.clone())
                        .await?;
                    let predecessor = lease.frontier;
                    let DurableMachineGraph {
                        foreground,
                        children,
                        ..
                    } = &mut *lease;
                    let mut transaction = coordinator
                        .stage_graph(foreground, children)
                        .map_err(|_| DurableRunFailure::Internal)?;
                    let accepted = transaction.update(|foreground, children, _, sessions| {
                        let machine = if foreground.task_id() == task_id {
                            foreground
                        } else {
                            children
                                .get_mut(&task_id)
                                .ok_or(OperationLifecycleError::InvalidAcceptedValue)?
                        };
                        let session = sessions
                            .get_mut(active_session_id)
                            .ok_or(OperationLifecycleError::InvalidAcceptedValue)?;
                        if metadata.attempted {
                            operation.accept_model_attempt(
                                machine,
                                session,
                                &turn,
                                self.inner.configuration.required().value_limits,
                                value,
                            )
                        } else {
                            operation.accept_model(
                                machine,
                                session,
                                &turn,
                                self.inner.configuration.required().value_limits,
                                value,
                            )
                        }
                    });
                    match accepted {
                        Ok(_) => {}
                        Err(OperationLifecycleError::Transcript(
                            gantry_runtime::TranscriptError::Limit,
                        )) => {
                            drop(transaction);
                            Self::durable_graph_machine_mut(&mut lease, task_id)?
                                .fail_operation(
                                    occurrence.identity,
                                    RuntimeErrorCategory::LogicalSessionTranscriptLimit,
                                )
                                .map_err(|_| DurableRunFailure::Internal)?;
                            self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                                .await?;
                            return Ok(());
                        }
                        Err(_) => return Err(DurableRunFailure::Internal),
                    }
                    transaction
                        .set_operation(DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: None,
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: None,
                            retries_left,
                            action_recovery: None,
                            request_bytes: None,
                            outcome: None,
                            retry_errors: Arc::from([]),
                            result_type: Some(metadata.result_type.clone()),
                            result_bytes: Some(result_bytes),
                        })
                        .map_err(DurableRunFailure::Commit)?;
                    transaction
                        .set_event(
                            completed_event,
                            owner.graph_event_plan()?,
                            result_event.protected_payloads.to_vec(),
                        )
                        .map_err(DurableRunFailure::Commit)?;
                    lease.frontier = owner
                        .commit_graph_transaction(
                            coordinator,
                            transaction,
                            predecessor,
                            DurableCommitCutV1::OperationResult,
                            task_id,
                        )
                        .await?;
                    lease.next_event_sequence.insert(
                        task_id,
                        sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
                    );
                    return Ok(());
                }
                ProcessedHookOutcomeV1::Retry(wait) => {
                    retries_left = Some(wait.retries_left);
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    self.commit_durable_graph_operation_cut(
                        &mut lease,
                        owner,
                        coordinator,
                        context,
                        task_id,
                        DurableCommitCutV1::RetryWaiting,
                        DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: Some(dispatch_id),
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: Some(wait.delay.get()),
                            retries_left,
                            action_recovery: None,
                            request_bytes: Some(request_bytes),
                            outcome: Some(outcome),
                            retry_errors: Arc::clone(&wait.errors),
                            result_type: None,
                            result_bytes: None,
                        },
                        None,
                    )
                    .await?;
                    drop(lease);
                    let prepared = match self
                        .poll_durable_graph_future(
                            graph,
                            owner,
                            coordinator,
                            operation.prepare_after_retry_wait(
                                self.inner.configuration.executor(),
                                cancellation,
                                &self.inner.allocator,
                                self.inner.configuration.identity_source(),
                            ),
                        )
                        .await?
                    {
                        crate::durable_lifecycle::DurableGraphDriverPoll::Completed(result) => {
                            result.map_err(|_| DurableRunFailure::Internal)?
                        }
                        crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                            return Ok(());
                        }
                    };
                    if prepared.is_none() {
                        let Some(mut lease) = self
                            .acquire_durable_graph_lease(graph, owner, coordinator)
                            .await?
                        else {
                            return Ok(());
                        };
                        Self::settle_retry_terminal(
                            Self::durable_graph_machine_mut(&mut lease, task_id)?,
                            occurrence,
                            &operation,
                        )
                        .map_err(|_| DurableRunFailure::Internal)?;
                        self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                            .await?;
                        return Ok(());
                    }
                }
                ProcessedHookOutcomeV1::Failed(failure) => {
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    let machine = Self::durable_graph_machine_mut(&mut lease, task_id)?;
                    if metadata.attempted
                        && matches!(
                            operation.lifecycle_failure(),
                            Some(OperationLifecycleFailureV1::Operation(_))
                        )
                    {
                        operation
                            .accept_attempt_failure(machine)
                            .map_err(|_| DurableRunFailure::Internal)?;
                    } else {
                        machine
                            .fail_operation(occurrence.identity, failure.runtime_category())
                            .map_err(|_| DurableRunFailure::Internal)?;
                    }
                    self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                        .await?;
                    return Ok(());
                }
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn repair_recovered_operation_dispatch(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        context: &DurableOperationContext,
        task_id: ProtocolIdentity,
        operation: &OperationLifecycle,
        recovery: &DurableOperationRecoveryV1,
    ) -> Result<(), DurableRunFailure> {
        let Some((dispatch, draft)) = operation
            .recovered_dispatch_event(recovery)
            .map_err(|_| DurableRunFailure::Internal)?
        else {
            return Ok(());
        };
        let mut lease = graph.acquire().await.ok_or(DurableRunFailure::Internal)?;
        let sequence = lease
            .next_event_sequence
            .get(&task_id)
            .copied()
            .unwrap_or(0);
        let event = self.complete_graph_event(context, task_id, sequence, draft.clone());
        let (frontier, repaired) = owner
            .repair_recovered_graph_event(
                Arc::clone(&graph.program),
                coordinator,
                |recovered| recovered.operation_dispatch_cause(dispatch),
                event,
                &draft.protected_payloads,
            )
            .await?;
        lease.frontier = frontier;
        if repaired {
            lease.next_event_sequence.insert(
                task_id,
                sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
            );
        }
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn repair_recovered_operation_completion(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        context: &DurableOperationContext,
        task_id: ProtocolIdentity,
        operation: &OperationLifecycle,
    ) -> Result<(), DurableRunFailure> {
        let (dispatch, outcome, validation_attempt, recovery_dispatch) = operation
            .outcome_context()
            .ok_or(DurableRunFailure::Internal)?;
        let draft = operation_completion_event(
            operation.captured(),
            dispatch,
            validation_attempt,
            recovery_dispatch,
            outcome,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        let mut lease = graph.acquire().await.ok_or(DurableRunFailure::Internal)?;
        let sequence = lease
            .next_event_sequence
            .get(&task_id)
            .copied()
            .unwrap_or(0);
        let event = self.complete_graph_event(context, task_id, sequence, draft.clone());
        let (frontier, repaired) = owner
            .repair_recovered_graph_event(
                Arc::clone(&graph.program),
                coordinator,
                |recovered| recovered.operation_outcome_cause(dispatch),
                event,
                &draft.protected_payloads,
            )
            .await?;
        lease.frontier = frontier;
        if repaired {
            lease.next_event_sequence.insert(
                task_id,
                sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
            );
        }
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn commit_durable_graph_operation_cut(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        context: &DurableOperationContext,
        task_id: ProtocolIdentity,
        cut: DurableCommitCutV1,
        operation: DurableOperationEvidenceV1,
        event: Option<ExecutionEventDraftV1>,
    ) -> Result<(), DurableRunFailure> {
        let completed_event = if let Some(event) = event {
            let sequence = lease
                .next_event_sequence
                .get(&task_id)
                .copied()
                .unwrap_or(0);
            Some((
                sequence,
                self.complete_graph_event(context, task_id, sequence, event.clone())
                    .await?,
                event,
            ))
        } else {
            None
        };
        let predecessor = lease.frontier;
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        transaction
            .set_operation(operation)
            .map_err(DurableRunFailure::Commit)?;
        if let Some((_, completed, draft)) = &completed_event {
            transaction
                .set_event(
                    completed.clone(),
                    owner.graph_event_plan()?,
                    draft.protected_payloads.to_vec(),
                )
                .map_err(DurableRunFailure::Commit)?;
        }
        lease.frontier = owner
            .commit_graph_transaction(coordinator, transaction, predecessor, cut, task_id)
            .await?;
        if let Some((sequence, _, _)) = completed_event {
            lease.next_event_sequence.insert(
                task_id,
                sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
            );
        }
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn commit_durable_graph_checkpoint(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
    ) -> Result<(), DurableRunFailure> {
        let predecessor = lease.frontier;
        let root_task = coordinator.snapshot().state().root_task_id();
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        lease.frontier = owner
            .commit_graph_transaction(
                coordinator,
                transaction,
                predecessor,
                DurableCommitCutV1::Checkpoint,
                root_task,
            )
            .await?;
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn complete_graph_event(
        &self,
        operations: &DurableOperationContext,
        task_id: ProtocolIdentity,
        sequence: u64,
        event: ExecutionEventDraftV1,
    ) -> Result<gantry_core::event::EventEnvelope, DurableRunFailure> {
        let draft = event
            .draft
            .with_execution_id(operations.execution_id)
            .and_then(|draft| draft.with_task(task_id, sequence))
            .map_err(|_| DurableRunFailure::Internal)?;
        EventCompleter::new(
            &self.inner.allocator,
            self.inner.configuration.identity_source(),
            self.inner.clock.as_ref(),
        )
        .complete(operations.activity_id, draft)
        .await
        .map_err(|_| DurableRunFailure::Internal)
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn commit_durable_graph_lifecycle(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        operations: &DurableOperationContext,
        task_id: ProtocolIdentity,
        label: MachineLabel,
        cut: DurableCommitCutV1,
    ) -> Result<(), DurableRunFailure> {
        let sequence = lease
            .next_event_sequence
            .get(&task_id)
            .copied()
            .unwrap_or(0);
        let outcome = match &label {
            MachineLabel::ForegroundCompletion(outcome)
            | MachineLabel::TerminalCompletion(outcome) => outcome.clone(),
            _ => return Err(DurableRunFailure::Internal),
        };
        let predecessor = lease.frontier;
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        let terminal = transaction
            .update(|_, _, tasks, _| match cut {
                DurableCommitCutV1::ForegroundCompletion => {
                    tasks.complete_foreground(outcome).map(|()| None)
                }
                DurableCommitCutV1::TerminalCompletion => tasks
                    .complete_terminal()
                    .map(|terminal| Some(terminal.clone())),
                _ => Err(TaskStateError::InvalidTransition),
            })
            .map_err(|_| DurableRunFailure::Internal)?;
        let draft = if let Some(terminal) = terminal {
            concurrent_terminal_event(operations.execution_id, task_id, &terminal)
                .map_err(|_| DurableRunFailure::Internal)?
        } else {
            machine_lifecycle_event(&label, operations.execution_id, task_id)
                .ok_or(DurableRunFailure::Internal)?
        };
        let event = self
            .complete_graph_event(operations, task_id, sequence, draft.clone())
            .await?;
        transaction
            .set_event(
                event,
                owner.graph_event_plan()?,
                draft.protected_payloads.to_vec(),
            )
            .map_err(DurableRunFailure::Commit)?;
        lease.frontier = owner
            .commit_graph_transaction(coordinator, transaction, predecessor, cut, task_id)
            .await?;
        lease.next_event_sequence.insert(
            task_id,
            sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
        );
        Ok(())
    }

    #[cfg(feature = "durable")]
    #[allow(clippy::too_many_arguments)]
    async fn commit_durable_event(
        &self,
        owner: &crate::DurableOwnedExecution,
        recovered: &mut gantry_runtime::RecoveredDurableStateV1,
        activity_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        task_sequence: &mut u64,
        event: ExecutionEventDraftV1,
        last_committed: &mut gantry_runtime::RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        let protected_payloads = Arc::clone(&event.protected_payloads);
        let draft = event
            .draft
            .with_execution_id(recovered.machine().execution_id())
            .and_then(|draft| draft.with_task(task_id, *task_sequence))
            .map_err(|_| DurableRunFailure::Internal)?;
        let event = EventCompleter::new(
            &self.inner.allocator,
            self.inner.configuration.identity_source(),
            self.inner.clock.as_ref(),
        )
        .complete(activity_id, draft)
        .await
        .map_err(|_| DurableRunFailure::Internal)?;
        let frontier = owner
            .commit_driver_event(recovered, event, &protected_payloads)
            .await?;
        *task_sequence = task_sequence
            .checked_add(1)
            .ok_or(DurableRunFailure::Internal)?;
        *last_committed = recovered.clone();
        if recovered.latest_cut() == DurableCommitCutV1::ForegroundCompletion {
            let barrier = owner
                .drain_driver_required_event_obligations_through(
                    recovered,
                    frontier,
                    &self.inner.allocator,
                    self.inner.configuration.identity_source(),
                    self.inner.event_delivery_runtime.as_ref(),
                )
                .await?;
            *last_committed = recovered.clone();
            if let DurableEventBarrierV1::RequiredExhausted(failure) = barrier {
                owner.project_driver_required_delivery_failure(recovered, failure)?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "durable")]
    async fn drive_durable_session_scope(
        &self,
        execution_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        recovered: &mut gantry_runtime::RecoveredDurableStateV1,
        scope: &gantry_runtime::SessionScopeOccurrence,
        owner: &crate::DurableOwnedExecution,
        last_committed: &mut gantry_runtime::RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        let parent = recovered
            .sessions()
            .and_then(|sessions| sessions.get(scope.parent_session_id))
            .cloned()
            .ok_or(DurableRunFailure::Internal)?;
        match owner
            .poll_driver_future(
                recovered,
                last_committed,
                self.inner
                    .session_establisher
                    .establish(execution_id, &parent),
            )
            .await?
        {
            crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(_)) => {}
            crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_)) => {
                recovered
                    .machine_mut()
                    .fail_session_scope(
                        scope,
                        RuntimeCode::Operation(RuntimeErrorCategory::LogicalSessionSetup),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                return Ok(());
            }
            crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => return Ok(()),
        }
        let mut staged = recovered.clone();
        let child = staged
            .sessions_mut()
            .ok_or(DurableRunFailure::Internal)?
            .create(
                scope.parent_session_id,
                task_id,
                scope.site.clone(),
                scope.occurrence,
                scope.mode,
                SessionEstablishmentV1::Separate,
            )
            .map_err(|_| DurableRunFailure::Internal)?
            .clone();
        owner
            .commit_driver_cut(&mut staged, DurableCommitCutV1::Checkpoint, None)
            .await?;
        *recovered = staged;
        *last_committed = recovered.clone();
        match owner
            .poll_driver_future(
                recovered,
                last_committed,
                self.inner
                    .session_establisher
                    .establish(execution_id, &child),
            )
            .await?
        {
            crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(_)) => {}
            crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_)) => {
                let mut staged = recovered.clone();
                staged
                    .machine_mut()
                    .fail_session_scope(
                        scope,
                        RuntimeCode::Operation(RuntimeErrorCategory::LogicalSessionSetup),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                owner
                    .commit_driver_cut(&mut staged, DurableCommitCutV1::Checkpoint, None)
                    .await?;
                *recovered = staged;
                *last_committed = recovered.clone();
                return Ok(());
            }
            crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => return Ok(()),
        }
        let mut staged = recovered.clone();
        staged
            .machine_mut()
            .complete_session_scope(scope, child.id)
            .map_err(|_| DurableRunFailure::Internal)?;
        owner
            .commit_driver_cut(&mut staged, DurableCommitCutV1::Checkpoint, None)
            .await?;
        *recovered = staged;
        *last_committed = recovered.clone();
        Ok(())
    }

    #[cfg(feature = "durable")]
    #[allow(clippy::too_many_arguments)]
    async fn drive_durable_action_operation(
        &self,
        context: &DurableOperationContext,
        recovered: &mut gantry_runtime::RecoveredDurableStateV1,
        hook: &mut TaskHook<'_>,
        cancellation: &CancellationSignal,
        occurrence: &gantry_runtime::OperationOccurrence,
        owner: &crate::DurableOwnedExecution,
        task_event_sequence: &mut u64,
        last_committed: &mut gantry_runtime::RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        let metadata = occurrence
            .metadata
            .as_ref()
            .ok_or(DurableRunFailure::Internal)?;
        let action = metadata
            .action
            .as_ref()
            .ok_or(DurableRunFailure::Internal)?;
        if metadata.kind != OperationSiteKind::Action
            || action.parameters.len() != occurrence.inputs.len()
        {
            return Err(DurableRunFailure::Internal);
        }
        let expected_schema = context
            .schema(&metadata.result_type)
            .ok_or(DurableRunFailure::Internal)?;
        let mapping_revision = context
            .mapping_revisions
            .action
            .clone()
            .ok_or(DurableRunFailure::Internal)?;
        let captured = CapturedOperationRequestV1::Action {
            header: OperationRequestHeaderV1 {
                execution_id: context.execution_id,
                task_id: occurrence.task_id,
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self
                    .inner
                    .configuration
                    .required()
                    .maximum_hook_output_bytes,
                value_limits: self.inner.configuration.required().value_limits,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: ActionOperationRequestV1 {
                path: action.path.clone(),
                signature: action.signature.clone(),
                recovery: action.recovery,
                mapping_revision,
                arguments: action
                    .parameters
                    .iter()
                    .zip(occurrence.inputs.iter())
                    .map(|(parameter, value)| TypedActionArgumentV1 {
                        name: Arc::from(parameter.name()),
                        ty: parameter.ty().clone(),
                        value: value.canonical_json(),
                    })
                    .collect(),
            },
        };
        let mut operation =
            OperationLifecycle::new(captured).map_err(|_| DurableRunFailure::Internal)?;
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            self.inner.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        let recovery = recovered.operation_recovery().clone();
        let mut reused_outcome_request = match &recovery {
            DurableOperationRecoveryV1::ReuseOutcome {
                operation_id,
                request_bytes,
                ..
            } if *operation_id == occurrence.identity => Some(Arc::clone(request_bytes)),
            _ => None,
        };
        if matches!(recovery, DurableOperationRecoveryV1::None) {
            operation
                .prepare(
                    &self.inner.allocator,
                    self.inner.configuration.identity_source(),
                    0,
                    0,
                    &[],
                )
                .map_err(|_| DurableRunFailure::Internal)?;
        } else {
            operation
                .recover(
                    &recovery,
                    policy,
                    &self.inner.allocator,
                    self.inner.configuration.identity_source(),
                )
                .map_err(|_| DurableRunFailure::Internal)?;
        }
        if let Some((_, dispatch_event)) = operation
            .recovered_dispatch_event(&recovery)
            .map_err(|_| DurableRunFailure::Internal)?
            && recovered
                .events()
                .event_for_cause(recovered.semantic_evidence_id())
                .is_none()
        {
            self.commit_durable_event(
                owner,
                recovered,
                context.activity_id,
                root_task_identity(context.execution_id),
                task_event_sequence,
                dispatch_event,
                last_committed,
            )
            .await?;
        }
        if matches!(recovery, DurableOperationRecoveryV1::UnknownOutcome { .. }) {
            if metadata.attempted {
                operation
                    .accept_attempt_failure(recovered.machine_mut())
                    .map_err(|_| DurableRunFailure::Internal)?;
            } else {
                let failure = operation
                    .lifecycle_failure()
                    .and_then(|failure| match failure {
                        OperationLifecycleFailureV1::Operation(failure) => Some(failure),
                        _ => None,
                    })
                    .ok_or(DurableRunFailure::Internal)?;
                recovered
                    .machine_mut()
                    .fail_operation(occurrence.identity, failure.runtime_category())
                    .map_err(|_| DurableRunFailure::Internal)?;
            }
            owner
                .commit_driver_cut(recovered, DurableCommitCutV1::Checkpoint, None)
                .await?;
            *last_committed = recovered.clone();
            return Ok(());
        }
        if matches!(recovery, DurableOperationRecoveryV1::RetryDelay { .. }) {
            match owner
                .poll_driver_future(
                    recovered,
                    last_committed,
                    operation.prepare_after_retry_wait(
                        self.inner.configuration.executor(),
                        cancellation,
                        &self.inner.allocator,
                        self.inner.configuration.identity_source(),
                    ),
                )
                .await?
            {
                crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(Some(_))) => {}
                crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(None)) => {
                    Self::settle_retry_terminal(recovered.machine_mut(), occurrence, &operation)
                        .map_err(|_| DurableRunFailure::Internal)?;
                    owner
                        .commit_driver_cut(recovered, DurableCommitCutV1::Checkpoint, None)
                        .await?;
                    *last_committed = recovered.clone();
                    return Ok(());
                }
                crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_)) => {
                    return Err(DurableRunFailure::Internal);
                }
                crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => return Ok(()),
            }
        }
        let mut retries_left = operation.retries_left();
        loop {
            let reused_request = reused_outcome_request.take();
            let reusing_outcome = reused_request.is_some();
            let (dispatch_id, request_bytes, validation_attempt, recovery_dispatch) =
                if let Some(request) = reused_request {
                    let (dispatch, _, validation, recovery) = operation
                        .outcome_context()
                        .ok_or(DurableRunFailure::Internal)?;
                    (dispatch, request, validation, recovery)
                } else {
                    let (prepared, validation, recovery) = operation
                        .prepared_dispatch()
                        .ok_or(DurableRunFailure::Internal)?;
                    (
                        prepared.dispatch_id,
                        Arc::from(prepared.request.canonical_bytes()),
                        validation,
                        recovery,
                    )
                };
            let action_recovery = Some(action.recovery);
            if !reusing_outcome {
                let (prepared, _, _) = operation
                    .prepared_dispatch()
                    .ok_or(DurableRunFailure::Internal)?;
                let dispatch_event = operation_dispatch_event(
                    operation.captured(),
                    prepared,
                    validation_attempt,
                    recovery_dispatch,
                )
                .map_err(|_| DurableRunFailure::Internal)?;
                owner
                    .commit_driver_cut(
                        recovered,
                        DurableCommitCutV1::OperationPrepared,
                        Some(DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: Some(dispatch_id),
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: None,
                            retries_left,
                            action_recovery,
                            request_bytes: Some(Arc::clone(&request_bytes)),
                            outcome: None,
                            retry_errors: Arc::from([]),
                            result_type: None,
                            result_bytes: None,
                        }),
                    )
                    .await?;
                *last_committed = recovered.clone();
                self.commit_durable_event(
                    owner,
                    recovered,
                    context.activity_id,
                    root_task_identity(context.execution_id),
                    task_event_sequence,
                    dispatch_event,
                    last_committed,
                )
                .await?;
                if recovered.machine().outcome().is_some() {
                    return Ok(());
                }
                match owner
                    .poll_driver_future(
                        recovered,
                        last_committed,
                        operation.dispatch(hook, cancellation),
                    )
                    .await?
                {
                    crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(_)) => {}
                    crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_)) => {
                        recovered
                            .machine_mut()
                            .fail_operation(occurrence.identity, RuntimeErrorCategory::HookFailure)
                            .map_err(|_| DurableRunFailure::Internal)?;
                        return Ok(());
                    }
                    crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => {
                        return Ok(());
                    }
                }
            }
            let (_, outcome, validation_attempt, recovery_dispatch) =
                operation
                    .outcome_context()
                    .ok_or(DurableRunFailure::Internal)?;
            let outcome = outcome.clone();
            if !reusing_outcome {
                owner
                    .commit_driver_cut(
                        recovered,
                        DurableCommitCutV1::OperationOutcome,
                        Some(DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: Some(dispatch_id),
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: None,
                            retries_left,
                            action_recovery,
                            request_bytes: Some(Arc::clone(&request_bytes)),
                            outcome: Some(outcome.clone()),
                            retry_errors: Arc::from([]),
                            result_type: None,
                            result_bytes: None,
                        }),
                    )
                    .await?;
                *last_committed = recovered.clone();
            }
            let completion_exists = reusing_outcome
                && recovered.events().events().values().any(|event| {
                    let event = event.occurrence().event();
                    event.kind() == gantry_core::portable::EventKind::OperationCompletion
                        && event.operation_id() == Some(occurrence.identity)
                        && event.causal_ids() == [dispatch_id]
                });
            if !completion_exists {
                let completion_event = operation_completion_event(
                    operation.captured(),
                    dispatch_id,
                    validation_attempt,
                    recovery_dispatch,
                    &outcome,
                )
                .map_err(|_| DurableRunFailure::Internal)?;
                self.commit_durable_event(
                    owner,
                    recovered,
                    context.activity_id,
                    root_task_identity(context.execution_id),
                    task_event_sequence,
                    completion_event,
                    last_committed,
                )
                .await?;
            }
            if recovered.machine().outcome().is_some() {
                return Ok(());
            }
            match operation
                .process_outcome(policy, self.inner.configuration.executor(), cancellation)
                .map_err(|_| DurableRunFailure::Internal)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let result_bytes: Arc<[u8]> = Arc::from(output.canonical_json().bytes());
                    let value = decode_logical_value(
                        &result_bytes,
                        &metadata.result_type,
                        self.inner.configuration.required().value_limits,
                        context.declared_value_shapes.as_ref(),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let (result_kind, result_value) = match metadata.result_type.kind() {
                        TypeKind::Unit => (OperationResultEventKindV1::Unit, None),
                        TypeKind::Decision => (OperationResultEventKindV1::Decision, Some(&value)),
                        _ => (OperationResultEventKindV1::Value, Some(&value)),
                    };
                    let result_event = operation_result_event(
                        occurrence.identity,
                        &metadata.result_type,
                        result_kind,
                        result_value,
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let mut staged = recovered.clone();
                    if metadata.attempted {
                        operation.accept_attempt(staged.machine_mut(), value)
                    } else {
                        operation.accept(staged.machine_mut(), value)
                    }
                    .map_err(|_| DurableRunFailure::Internal)?;
                    owner
                        .commit_driver_cut(
                            &mut staged,
                            DurableCommitCutV1::OperationResult,
                            Some(DurableOperationEvidenceV1 {
                                operation_id: occurrence.identity,
                                dispatch_id: None,
                                validation_attempt,
                                recovery_dispatch,
                                retry_delay_us: None,
                                retries_left,
                                action_recovery,
                                request_bytes: None,
                                outcome: None,
                                retry_errors: Arc::from([]),
                                result_type: Some(metadata.result_type.clone()),
                                result_bytes: Some(result_bytes),
                            }),
                        )
                        .await?;
                    *recovered = staged;
                    *last_committed = recovered.clone();
                    self.commit_durable_event(
                        owner,
                        recovered,
                        context.activity_id,
                        root_task_identity(context.execution_id),
                        task_event_sequence,
                        result_event,
                        last_committed,
                    )
                    .await?;
                    return Ok(());
                }
                ProcessedHookOutcomeV1::Retry(wait) => {
                    retries_left = Some(wait.retries_left);
                    owner
                        .commit_driver_cut(
                            recovered,
                            DurableCommitCutV1::RetryWaiting,
                            Some(DurableOperationEvidenceV1 {
                                operation_id: occurrence.identity,
                                dispatch_id: Some(dispatch_id),
                                validation_attempt,
                                recovery_dispatch,
                                retry_delay_us: Some(wait.delay.get()),
                                retries_left,
                                action_recovery,
                                request_bytes: Some(request_bytes),
                                outcome: Some(outcome),
                                retry_errors: Arc::clone(&wait.errors),
                                result_type: None,
                                result_bytes: None,
                            }),
                        )
                        .await?;
                    *last_committed = recovered.clone();
                    match owner
                        .poll_driver_future(
                            recovered,
                            last_committed,
                            operation.prepare_after_retry_wait(
                                self.inner.configuration.executor(),
                                cancellation,
                                &self.inner.allocator,
                                self.inner.configuration.identity_source(),
                            ),
                        )
                        .await?
                    {
                        crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(Some(_))) => {}
                        crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(None)) => {
                            Self::settle_retry_terminal(
                                recovered.machine_mut(),
                                occurrence,
                                &operation,
                            )
                            .map_err(|_| DurableRunFailure::Internal)?;
                            return Ok(());
                        }
                        crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_)) => {
                            return Err(DurableRunFailure::Internal);
                        }
                        crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => {
                            return Ok(());
                        }
                    }
                }
                ProcessedHookOutcomeV1::Failed(failure) => {
                    if metadata.attempted
                        && matches!(
                            operation.lifecycle_failure(),
                            Some(OperationLifecycleFailureV1::Operation(_))
                        )
                    {
                        operation
                            .accept_attempt_failure(recovered.machine_mut())
                            .map_err(|_| DurableRunFailure::Internal)?;
                    } else {
                        recovered
                            .machine_mut()
                            .fail_operation(occurrence.identity, failure.runtime_category())
                            .map_err(|_| DurableRunFailure::Internal)?;
                    }
                    return Ok(());
                }
            }
        }
    }

    #[cfg(feature = "durable")]
    #[allow(clippy::too_many_arguments)]
    async fn drive_durable_model_operation(
        &self,
        context: &DurableOperationContext,
        recovered: &mut gantry_runtime::RecoveredDurableStateV1,
        hook: &mut TaskHook<'_>,
        cancellation: &CancellationSignal,
        occurrence: &gantry_runtime::OperationOccurrence,
        owner: &crate::DurableOwnedExecution,
        session_occurrence: u64,
        task_event_sequence: &mut u64,
        last_committed: &mut gantry_runtime::RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        let metadata = occurrence
            .metadata
            .as_ref()
            .ok_or(DurableRunFailure::Internal)?;
        let interpolation_count = metadata.interpolation_types.len();
        if !matches!(
            metadata.kind,
            OperationSiteKind::Prompt | OperationSiteKind::Decide
        ) || metadata.named_input_names.len() != metadata.named_input_types.len()
            || occurrence.inputs.len()
                != interpolation_count.saturating_add(metadata.named_input_types.len())
        {
            return Err(DurableRunFailure::Internal);
        }
        let expected_schema = context
            .schema(&metadata.result_type)
            .ok_or(DurableRunFailure::Internal)?;
        let selected_agent = occurrence
            .active_agent
            .clone()
            .ok_or(DurableRunFailure::Internal)?;
        let mapping_revision = context
            .mapping_revisions
            .agent
            .clone()
            .ok_or(DurableRunFailure::Internal)?;
        let parent_session_id = occurrence
            .active_session
            .ok_or(DurableRunFailure::Internal)?;
        let task_id = occurrence.task_id;
        let retained_session = match recovered.operation_recovery() {
            recovery @ DurableOperationRecoveryV1::ReuseOutcome { operation_id, .. }
                if *operation_id == occurrence.identity =>
            {
                OperationLifecycle::retained_model_session_id(recovery)
                    .map_err(|_| DurableRunFailure::Internal)?
            }
            _ => None,
        };
        let active_session_id = if let Some(session_id) = retained_session {
            let session = recovered
                .sessions()
                .and_then(|sessions| sessions.get(session_id))
                .ok_or(DurableRunFailure::Internal)?;
            let valid = match metadata.session_mode.as_deref() {
                Some(mode @ ("fork" | "new")) => {
                    session.creator_task == Some(task_id)
                        && session.parent == Some(parent_session_id)
                        && session.creation_site.as_ref() == Some(&occurrence.site)
                        && session.establishment == SessionEstablishmentV1::OperationRequest
                        && session.mode
                            == if mode == "fork" {
                                SessionCreationModeV1::Fork
                            } else {
                                SessionCreationModeV1::New
                            }
                }
                None => session_id == parent_session_id,
                _ => false,
            };
            if !valid {
                return Err(DurableRunFailure::Internal);
            }
            session_id
        } else if let Some(mode) = metadata.session_mode.as_deref() {
            let mode = match mode {
                "fork" => SessionCreationModeV1::Fork,
                "new" => SessionCreationModeV1::New,
                _ => return Err(DurableRunFailure::Internal),
            };
            let mut staged = recovered.clone();
            let session_id = staged
                .sessions_mut()
                .ok_or(DurableRunFailure::Internal)?
                .create(
                    parent_session_id,
                    task_id,
                    occurrence.site.clone(),
                    session_occurrence,
                    mode,
                    SessionEstablishmentV1::OperationRequest,
                )
                .map_err(|_| DurableRunFailure::Internal)?
                .id;
            owner
                .commit_driver_cut(&mut staged, DurableCommitCutV1::Checkpoint, None)
                .await?;
            *recovered = staged;
            *last_committed = recovered.clone();
            session_id
        } else {
            parent_session_id
        };
        let session = recovered
            .sessions()
            .and_then(|sessions| sessions.get(active_session_id))
            .cloned()
            .ok_or(DurableRunFailure::Internal)?;
        let interpolation_inputs = metadata
            .interpolation_types
            .iter()
            .zip(occurrence.inputs.iter().take(interpolation_count))
            .enumerate()
            .map(|(position, (ty, value))| {
                Ok(InterpolationInputV1 {
                    position: u64::try_from(position).map_err(|_| DurableRunFailure::Internal)?,
                    ty: ty.clone(),
                    value: value.canonical_json(),
                })
            })
            .collect::<Result<Vec<_>, DurableRunFailure>>()?;
        let named_inputs = metadata
            .named_input_names
            .iter()
            .zip(&metadata.named_input_types)
            .zip(occurrence.inputs.iter().skip(interpolation_count))
            .map(|((name, ty), value)| NamedInputV1 {
                name: Arc::clone(name),
                ty: ty.clone(),
                value: value.canonical_json(),
            })
            .collect::<Vec<_>>();
        let rendered_prompt = match render_prompt(
            &metadata.template_segments,
            occurrence.inputs.iter().take(interpolation_count),
            self.inner
                .configuration
                .required()
                .value_limits
                .maximum_string_scalars(),
        ) {
            Ok(prompt) => prompt,
            Err(RenderPromptError::Limit) => {
                recovered
                    .machine_mut()
                    .fail_operation_with_code(
                        occurrence.identity,
                        RuntimeCode::Deterministic(DeterministicEvaluationCode::StringSizeLimit),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                return Ok(());
            }
            Err(RenderPromptError::Shape) => return Err(DurableRunFailure::Internal),
        };
        let session_use = if let Some(mode) = metadata.session_mode.as_ref() {
            ModelSessionUseV1::Create {
                mode: Arc::clone(mode),
                session_id: session.id,
                parent_session_id,
                root_session_id: session.root,
                provenance: Arc::from("operation-request"),
            }
        } else {
            ModelSessionUseV1::Inline
        };
        let captured = CapturedOperationRequestV1::Model {
            header: OperationRequestHeaderV1 {
                execution_id: context.execution_id,
                task_id,
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self
                    .inner
                    .configuration
                    .required()
                    .maximum_hook_output_bytes,
                value_limits: self.inner.configuration.required().value_limits,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: Box::new(ModelOperationRequestV1 {
                selected_agent: Arc::clone(&selected_agent),
                mapping_revision,
                template_segments: metadata.template_segments.clone(),
                rendered_prompt: Arc::clone(&rendered_prompt),
                interpolation_inputs: interpolation_inputs.clone(),
                named_inputs: named_inputs.clone(),
                transcript: session.transcript.clone(),
                active_session_id: session.id,
                parent_session_id: session.parent,
                root_session_id: session.root,
                session_use,
            }),
        };
        let mut operation =
            OperationLifecycle::new(captured).map_err(|_| DurableRunFailure::Internal)?;
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            self.inner.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        let mut reused_outcome_request = match recovered.operation_recovery() {
            DurableOperationRecoveryV1::ReuseOutcome {
                operation_id,
                request_bytes,
                ..
            } if *operation_id == occurrence.identity => Some(Arc::clone(request_bytes)),
            _ => None,
        };
        if reused_outcome_request.is_some() {
            operation
                .recover(
                    recovered.operation_recovery(),
                    policy,
                    &self.inner.allocator,
                    self.inner.configuration.identity_source(),
                )
                .map_err(|_| DurableRunFailure::Internal)?;
        } else {
            operation
                .prepare(
                    &self.inner.allocator,
                    self.inner.configuration.identity_source(),
                    0,
                    0,
                    &[],
                )
                .map_err(|_| DurableRunFailure::Internal)?;
        }
        let mut retries_left = operation.retries_left();
        loop {
            let reused_request = reused_outcome_request.take();
            let reusing_outcome = reused_request.is_some();
            let (dispatch_id, request_bytes, validation_attempt, recovery_dispatch) =
                if let Some(request) = reused_request {
                    let (dispatch, _, validation, recovery) = operation
                        .outcome_context()
                        .ok_or(DurableRunFailure::Internal)?;
                    (dispatch, request, validation, recovery)
                } else {
                    let (prepared, validation, recovery) = operation
                        .prepared_dispatch()
                        .ok_or(DurableRunFailure::Internal)?;
                    (
                        prepared.dispatch_id,
                        Arc::from(prepared.request.canonical_bytes()),
                        validation,
                        recovery,
                    )
                };
            if !reusing_outcome {
                let (prepared, _, _) = operation
                    .prepared_dispatch()
                    .ok_or(DurableRunFailure::Internal)?;
                let dispatch_event = operation_dispatch_event(
                    operation.captured(),
                    prepared,
                    validation_attempt,
                    recovery_dispatch,
                )
                .map_err(|_| DurableRunFailure::Internal)?;
                owner
                    .commit_driver_cut(
                        recovered,
                        DurableCommitCutV1::OperationPrepared,
                        Some(DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: Some(dispatch_id),
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: None,
                            retries_left,
                            action_recovery: None,
                            request_bytes: Some(Arc::clone(&request_bytes)),
                            outcome: None,
                            retry_errors: Arc::from([]),
                            result_type: None,
                            result_bytes: None,
                        }),
                    )
                    .await?;
                *last_committed = recovered.clone();
                self.commit_durable_event(
                    owner,
                    recovered,
                    context.activity_id,
                    root_task_identity(context.execution_id),
                    task_event_sequence,
                    dispatch_event,
                    last_committed,
                )
                .await?;
                if recovered.machine().outcome().is_some() {
                    return Ok(());
                }
                match owner
                    .poll_driver_future(
                        recovered,
                        last_committed,
                        operation.dispatch_model(
                            hook,
                            cancellation,
                            &self.inner.session_establisher,
                            context.execution_id,
                            &session,
                        ),
                    )
                    .await?
                {
                    crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(_)) => {}
                    crate::durable_lifecycle::DurableDriverPoll::Completed(Err(error)) => {
                        let category = match error {
                            OperationLifecycleError::Cancelled => {
                                RuntimeErrorCategory::Cancellation
                            }
                            OperationLifecycleError::Session(_) => {
                                RuntimeErrorCategory::LogicalSessionSetup
                            }
                            OperationLifecycleError::Hook(_) if hook.is_ready() => {
                                RuntimeErrorCategory::HookFailure
                            }
                            OperationLifecycleError::Hook(_) => RuntimeErrorCategory::HookCreation,
                            _ => return Err(DurableRunFailure::Internal),
                        };
                        recovered
                            .machine_mut()
                            .fail_operation(occurrence.identity, category)
                            .map_err(|_| DurableRunFailure::Internal)?;
                        return Ok(());
                    }
                    crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => {
                        return Ok(());
                    }
                }
            }
            let (_, outcome, validation_attempt, recovery_dispatch) =
                operation
                    .outcome_context()
                    .ok_or(DurableRunFailure::Internal)?;
            let outcome = outcome.clone();
            if !reusing_outcome {
                owner
                    .commit_driver_cut(
                        recovered,
                        DurableCommitCutV1::OperationOutcome,
                        Some(DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: Some(dispatch_id),
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: None,
                            retries_left,
                            action_recovery: None,
                            request_bytes: Some(Arc::clone(&request_bytes)),
                            outcome: Some(outcome.clone()),
                            retry_errors: Arc::from([]),
                            result_type: None,
                            result_bytes: None,
                        }),
                    )
                    .await?;
                *last_committed = recovered.clone();
            }
            let completion_exists = reusing_outcome
                && recovered.events().events().values().any(|event| {
                    let event = event.occurrence().event();
                    event.kind() == gantry_core::portable::EventKind::OperationCompletion
                        && event.operation_id() == Some(occurrence.identity)
                        && event.causal_ids() == [dispatch_id]
                });
            if !completion_exists {
                let completion_event = operation_completion_event(
                    operation.captured(),
                    dispatch_id,
                    validation_attempt,
                    recovery_dispatch,
                    &outcome,
                )
                .map_err(|_| DurableRunFailure::Internal)?;
                self.commit_durable_event(
                    owner,
                    recovered,
                    context.activity_id,
                    root_task_identity(context.execution_id),
                    task_event_sequence,
                    completion_event,
                    last_committed,
                )
                .await?;
            }
            if recovered.machine().outcome().is_some() {
                return Ok(());
            }
            match operation
                .process_outcome(policy, self.inner.configuration.executor(), cancellation)
                .map_err(|_| DurableRunFailure::Internal)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let result_bytes: Arc<[u8]> = Arc::from(output.canonical_json().bytes());
                    let value = decode_logical_value(
                        &result_bytes,
                        &metadata.result_type,
                        self.inner.configuration.required().value_limits,
                        context.declared_value_shapes.as_ref(),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let turn = TranscriptTurnV1 {
                        operation_kind: metadata.kind,
                        template_representation: metadata.template_segments.clone(),
                        rendered_prompt: Arc::clone(&rendered_prompt),
                        interpolation_inputs: interpolation_inputs.clone(),
                        using_inputs: named_inputs.clone(),
                        selected_agent: Arc::clone(&selected_agent),
                        accepted_result: AcceptedTranscriptResultV1 {
                            kind: transcript_result_kind(&metadata.result_type),
                            ty: metadata.result_type.clone(),
                            value: value.canonical_json(),
                        },
                    };
                    let (result_kind, result_value) = match metadata.result_type.kind() {
                        TypeKind::Unit => (OperationResultEventKindV1::Unit, None),
                        TypeKind::Decision => (OperationResultEventKindV1::Decision, Some(&value)),
                        _ => (OperationResultEventKindV1::Value, Some(&value)),
                    };
                    let result_event = operation_result_event(
                        occurrence.identity,
                        &metadata.result_type,
                        result_kind,
                        result_value,
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let mut staged = recovered.clone();
                    let accepted_result = {
                        let (machine, sessions) = staged.state_mut();
                        let session = sessions
                            .and_then(|sessions| sessions.get_mut(active_session_id))
                            .ok_or(DurableRunFailure::Internal)?;
                        if metadata.attempted {
                            operation.accept_model_attempt(
                                machine,
                                session,
                                &turn,
                                self.inner.configuration.required().value_limits,
                                value,
                            )
                        } else {
                            operation.accept_model(
                                machine,
                                session,
                                &turn,
                                self.inner.configuration.required().value_limits,
                                value,
                            )
                        }
                    };
                    match accepted_result {
                        Ok(_) => {}
                        Err(OperationLifecycleError::Transcript(
                            gantry_runtime::TranscriptError::Limit,
                        )) => {
                            staged
                                .machine_mut()
                                .fail_operation(
                                    occurrence.identity,
                                    RuntimeErrorCategory::LogicalSessionTranscriptLimit,
                                )
                                .map_err(|_| DurableRunFailure::Internal)?;
                            *recovered = staged;
                            return Ok(());
                        }
                        Err(_) => return Err(DurableRunFailure::Internal),
                    }
                    owner
                        .commit_driver_cut(
                            &mut staged,
                            DurableCommitCutV1::OperationResult,
                            Some(DurableOperationEvidenceV1 {
                                operation_id: occurrence.identity,
                                dispatch_id: None,
                                validation_attempt,
                                recovery_dispatch,
                                retry_delay_us: None,
                                retries_left,
                                action_recovery: None,
                                request_bytes: None,
                                outcome: None,
                                retry_errors: Arc::from([]),
                                result_type: Some(metadata.result_type.clone()),
                                result_bytes: Some(result_bytes),
                            }),
                        )
                        .await?;
                    *recovered = staged;
                    *last_committed = recovered.clone();
                    self.commit_durable_event(
                        owner,
                        recovered,
                        context.activity_id,
                        root_task_identity(context.execution_id),
                        task_event_sequence,
                        result_event,
                        last_committed,
                    )
                    .await?;
                    return Ok(());
                }
                ProcessedHookOutcomeV1::Retry(wait) => {
                    retries_left = Some(wait.retries_left);
                    owner
                        .commit_driver_cut(
                            recovered,
                            DurableCommitCutV1::RetryWaiting,
                            Some(DurableOperationEvidenceV1 {
                                operation_id: occurrence.identity,
                                dispatch_id: Some(dispatch_id),
                                validation_attempt,
                                recovery_dispatch,
                                retry_delay_us: Some(wait.delay.get()),
                                retries_left,
                                action_recovery: None,
                                request_bytes: Some(request_bytes),
                                outcome: Some(outcome),
                                retry_errors: Arc::clone(&wait.errors),
                                result_type: None,
                                result_bytes: None,
                            }),
                        )
                        .await?;
                    *last_committed = recovered.clone();
                    match owner
                        .poll_driver_future(
                            recovered,
                            last_committed,
                            operation.prepare_after_retry_wait(
                                self.inner.configuration.executor(),
                                cancellation,
                                &self.inner.allocator,
                                self.inner.configuration.identity_source(),
                            ),
                        )
                        .await?
                    {
                        crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(Some(_))) => {}
                        crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(None)) => {
                            Self::settle_retry_terminal(
                                recovered.machine_mut(),
                                occurrence,
                                &operation,
                            )
                            .map_err(|_| DurableRunFailure::Internal)?;
                            return Ok(());
                        }
                        crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_)) => {
                            return Err(DurableRunFailure::Internal);
                        }
                        crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => {
                            return Ok(());
                        }
                    }
                }
                ProcessedHookOutcomeV1::Failed(failure) => {
                    if metadata.attempted
                        && matches!(
                            operation.lifecycle_failure(),
                            Some(OperationLifecycleFailureV1::Operation(_))
                        )
                    {
                        operation
                            .accept_attempt_failure(recovered.machine_mut())
                            .map_err(|_| DurableRunFailure::Internal)?;
                    } else {
                        recovered
                            .machine_mut()
                            .fail_operation(occurrence.identity, failure.runtime_category())
                            .map_err(|_| DurableRunFailure::Internal)?;
                    }
                    return Ok(());
                }
            }
        }
    }

    async fn drive_execution(
        &self,
        accepted: StartExecutionAccepted,
        prepared: PreparedRootDriver,
    ) -> Result<ExecutionSnapshot, RunExecutionError> {
        self.drive_task(accepted, prepared.into(), true)
            .await?
            .ok_or(RunExecutionError::ExecutionNotFound)
    }

    async fn drive_task(
        &self,
        accepted: StartExecutionAccepted,
        prepared: PreparedTaskDriver,
        execution_foreground: bool,
    ) -> Result<Option<ExecutionSnapshot>, RunExecutionError> {
        let analysis = accepted
            .package_activity
            .analysis
            .as_ref()
            .ok_or(RunExecutionError::MissingAnalysis)?;
        let PreparedTaskDriver {
            mut machine,
            coordinator,
            task_id,
            workflow,
            create_request,
            base_session,
            #[cfg(feature = "concurrent")]
            program,
            #[cfg(feature = "concurrent")]
            execution_budget,
        } = prepared;
        let execution_cancellation = accepted
            .handle
            .cancellation_signal()
            .map_err(|_| RunExecutionError::LifecycleTransition)?;
        let cancellation = NondurableTaskCancellation {
            execution: execution_cancellation.clone(),
            coordinator: coordinator.clone(),
            task_id,
        };
        let session_establisher = self.inner.session_establisher.clone();
        let mut events = ExecutionEventPipeline::new(
            &accepted.handle,
            &coordinator,
            accepted.package_activity.activity_id,
            task_id,
            &self.inner.allocator,
            self.inner.configuration.identity_source(),
            self.inner.clock.as_ref(),
            self.inner.event_delivery_runtime.as_ref(),
            accepted.event_delivery.clone(),
        )
        .map_err(RunExecutionError::Event)?;
        self.apply_task_cancellation(&accepted, &coordinator, task_id, &mut machine, &mut events)
            .await?;
        let setup_succeeded = if cancellation.is_cancelled() || machine.outcome().is_some() {
            false
        } else if let Some(base_session) = base_session {
            let session = coordinator
                .session(base_session)
                .ok_or(RunExecutionError::MissingLogicalSession)?;
            self.apply_task_cancellation(
                &accepted,
                &coordinator,
                task_id,
                &mut machine,
                &mut events,
            )
            .await?;
            if cancellation.is_cancelled() || machine.outcome().is_some() {
                false
            } else {
                let established = session_establisher
                    .establish(accepted.execution_id, &session)
                    .await;
                self.apply_task_cancellation(
                    &accepted,
                    &coordinator,
                    task_id,
                    &mut machine,
                    &mut events,
                )
                .await?;
                if established.is_err() && machine.outcome().is_none() {
                    let _ = machine.fail_execution(
                        RuntimeErrorCategory::LogicalSessionSetup,
                        gantry_runtime::ExecutionFailureProjection::Full,
                    );
                }
                established.is_ok() && !cancellation.is_cancelled() && machine.outcome().is_none()
            }
        } else {
            true
        };
        let mut hook = setup_succeeded
            .then(|| {
                TaskHook::new(
                    &self.inner.lifecycle,
                    self.inner.hook_factory.as_ref(),
                    AdapterPoison::default(),
                    create_request,
                )
            })
            .transpose()
            .map_err(RunExecutionError::TaskHook)?;
        let mut model_session_occurrence = 0_u64;
        let mut foreground_fixed = false;
        let mut terminal_fixed = false;

        loop {
            self.apply_task_cancellation(
                &accepted,
                &coordinator,
                task_id,
                &mut machine,
                &mut events,
            )
            .await?;
            match machine.step() {
                MachineStep::Transition(label) => {
                    let defer_execution_completion_event =
                        should_defer_execution_completion_event(&label, execution_foreground);
                    let defer_task_settlement_event = matches!(label, MachineLabel::TaskSettled(_));
                    if !defer_execution_completion_event
                        && !defer_task_settlement_event
                        && let Some(event) =
                            machine_lifecycle_event(&label, accepted.execution_id, task_id)
                    {
                        self.complete_and_enqueue_nondurable_event(
                            &coordinator,
                            &accepted.handle,
                            &accepted.event_delivery,
                            events.complete_task_draft(event),
                        )
                        .await?;
                    }
                    match label {
                        MachineLabel::TaskSettled(outcome) => {
                            coordinator
                                .stage_task_outcome(task_id, outcome.clone())
                                .map_err(RunExecutionError::TaskState)?;
                            #[cfg(feature = "concurrent")]
                            if matches!(
                                outcome,
                                MachineOutcome::Failed(_) | MachineOutcome::Cancelled(_)
                            ) {
                                self.cancel_and_drain_nondurable_descendants(
                                    accepted.execution_id,
                                    &coordinator,
                                    task_id,
                                    &outcome,
                                )
                                .await?;
                            }
                            let draft = machine_lifecycle_event(
                                &MachineLabel::TaskSettled(outcome),
                                accepted.execution_id,
                                task_id,
                            )
                            .ok_or(RunExecutionError::LifecycleTransition)?;
                            self.complete_and_enqueue_nondurable_event(
                                &coordinator,
                                &accepted.handle,
                                &accepted.event_delivery,
                                events.complete_task_draft(draft),
                            )
                            .await?;
                            coordinator
                                .settle_staged_task(task_id)
                                .map_err(RunExecutionError::TaskState)?;
                        }
                        MachineLabel::ForegroundCompletion(outcome) if execution_foreground => {
                            if !foreground_fixed {
                                self.wait_for_nondurable_attached_tasks(&coordinator)
                                    .await?;
                                coordinator.wait_for_required_event_delivery().await;
                                let selected_outcome = if coordinator
                                    .event_delivery_executor_failed()
                                {
                                    MachineOutcome::Failed(MachineFailure {
                                        code: RuntimeCode::Operation(
                                            RuntimeErrorCategory::ExecutorFailure,
                                        ),
                                        workflow: workflow.clone(),
                                        site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
                                            .map_err(|_| RunExecutionError::LifecycleTransition)?,
                                        #[cfg(feature = "concurrent")]
                                        join_failure: None,
                                    })
                                } else if coordinator.required_event_delivery_failed() {
                                    MachineOutcome::Failed(MachineFailure {
                                        code: RuntimeCode::Operation(
                                            RuntimeErrorCategory::RequiredEventDeliveryFailure,
                                        ),
                                        workflow: workflow.clone(),
                                        site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
                                            .map_err(|_| RunExecutionError::LifecycleTransition)?,
                                        #[cfg(feature = "concurrent")]
                                        join_failure: None,
                                    })
                                } else {
                                    outcome
                                };
                                coordinator
                                    .complete_foreground_with_outcome(selected_outcome.clone())
                                    .map_err(RunExecutionError::TaskState)?;
                                let draft = machine_lifecycle_event(
                                    &MachineLabel::ForegroundCompletion(selected_outcome.clone()),
                                    accepted.execution_id,
                                    task_id,
                                )
                                .ok_or(RunExecutionError::LifecycleTransition)?;
                                self.complete_and_enqueue_nondurable_event(
                                    &coordinator,
                                    &accepted.handle,
                                    &accepted.event_delivery,
                                    events.complete_task_draft(draft),
                                )
                                .await?;
                                coordinator.wait_for_required_event_delivery().await;
                                self.inner
                                    .lifecycle
                                    .complete_foreground(&accepted.handle, selected_outcome.clone())
                                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                                foreground_fixed = true;
                            }
                        }
                        MachineLabel::TerminalCompletion(_outcome)
                            if execution_foreground && !terminal_fixed =>
                        {
                            #[cfg(feature = "concurrent")]
                            {
                                let terminal = loop {
                                    match coordinator.complete_terminal() {
                                        Ok(terminal) => break terminal,
                                        Err(TaskStateError::DetachedTasksPending) => {
                                            let detached =
                                                coordinator.shutdown_cohort().detached_tasks;
                                            if detached.is_empty() {
                                                return Err(RunExecutionError::LifecycleTransition);
                                            }
                                            for child in detached {
                                                coordinator
                                                    .wait_for_task_settlement(child)
                                                    .map_err(RunExecutionError::TaskState)?
                                                    .await;
                                            }
                                        }
                                        Err(error) => {
                                            return Err(RunExecutionError::TaskState(error));
                                        }
                                    }
                                };
                                self.complete_and_enqueue_nondurable_event(
                                    &coordinator,
                                    &accepted.handle,
                                    &accepted.event_delivery,
                                    async {
                                        if terminal.detached_failures.is_empty() {
                                            let draft = machine_lifecycle_event(
                                                &MachineLabel::TerminalCompletion(
                                                    terminal.foreground.clone(),
                                                ),
                                                accepted.execution_id,
                                                task_id,
                                            )
                                            .ok_or(ExecutionEventError::IdentityKind)?;
                                            events.complete_task_draft(draft).await
                                        } else {
                                            let draft = concurrent_terminal_event(
                                                accepted.execution_id,
                                                task_id,
                                                &terminal,
                                            )
                                            .map_err(|_| ExecutionEventError::IdentityKind)?;
                                            events.complete_execution_draft(draft).await
                                        }
                                    },
                                )
                                .await?;
                                coordinator.wait_for_required_event_delivery().await;
                                self.inner
                                    .lifecycle
                                    .complete_terminal(&accepted.handle, terminal)
                                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                            }
                            #[cfg(not(feature = "concurrent"))]
                            {
                                let terminal = coordinator
                                    .complete_terminal()
                                    .map_err(RunExecutionError::TaskState)?;
                                let draft = machine_lifecycle_event(
                                    &MachineLabel::TerminalCompletion(terminal.foreground.clone()),
                                    accepted.execution_id,
                                    task_id,
                                )
                                .ok_or(RunExecutionError::LifecycleTransition)?;
                                self.complete_and_enqueue_nondurable_event(
                                    &coordinator,
                                    &accepted.handle,
                                    &accepted.event_delivery,
                                    events.complete_task_draft(draft),
                                )
                                .await?;
                                coordinator.wait_for_required_event_delivery().await;
                                self.inner
                                    .lifecycle
                                    .complete_terminal(&accepted.handle, terminal)
                                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                            }
                            terminal_fixed = true;
                        }
                        #[cfg(feature = "concurrent")]
                        MachineLabel::TaskControlSuspended(suspension) => {
                            self.submit_source_child(
                                &accepted,
                                &mut machine,
                                &coordinator,
                                task_id,
                                &program,
                                &execution_budget,
                                &session_establisher,
                                &cancellation,
                                &mut events,
                                execution_foreground,
                                suspension,
                            )
                            .await?;
                        }
                        #[cfg(feature = "concurrent")]
                        MachineLabel::Deterministic { ref kind, .. }
                            if kind.as_ref() == "joinall-empty" =>
                        {
                            let draft = concurrent_join_event(
                                accepted.execution_id,
                                task_id,
                                TaskControlSiteKind::JoinAll,
                                &[],
                                "succeeded",
                                Some(&TypeDescriptor::UNIT),
                                None,
                                0,
                            )
                            .map_err(|_| RunExecutionError::LifecycleTransition)?;
                            self.complete_and_enqueue_nondurable_event(
                                &coordinator,
                                &accepted.handle,
                                &accepted.event_delivery,
                                events.complete_task_draft(draft),
                            )
                            .await?;
                            continue;
                        }
                        #[cfg(feature = "concurrent")]
                        MachineLabel::Deterministic { .. } => {
                            if let Some((suspension, join_all)) = machine
                                .pending_task_control()
                                .and_then(|pending| pending.join())
                                .map(|(join, all)| (join.clone(), all))
                            {
                                let handle_names = suspension
                                    .handles
                                    .iter()
                                    .map(|handle| Arc::from(handle.name()))
                                    .collect::<Vec<_>>();
                                let handles = suspension
                                    .handles
                                    .iter()
                                    .map(|handle| handle.identity())
                                    .collect::<Vec<_>>();
                                let kind = if join_all {
                                    TaskControlSiteKind::JoinAll
                                } else {
                                    TaskControlSiteKind::Join
                                };
                                let started = coordinator
                                    .begin_source_join(
                                        task_id,
                                        suspension.workflow.clone(),
                                        suspension.site.clone(),
                                        kind,
                                        &handle_names,
                                        &handles,
                                    )
                                    .map_err(RunExecutionError::TaskState)?;
                                let (joined_task_ids, resolution) = match started {
                                    JoinStartV1::Empty => (
                                        Vec::new(),
                                        Some(JoinResolutionV1::Succeeded(LogicalValue::unit())),
                                    ),
                                    JoinStartV1::Started(ownership) => {
                                        let joined_task_ids = ownership
                                            .members()
                                            .iter()
                                            .map(|member| member.task_id())
                                            .collect::<Vec<_>>();
                                        let mut wait = std::pin::pin!(
                                            coordinator
                                                .wait_for_join(
                                                    ownership,
                                                    self.inner
                                                        .configuration
                                                        .required()
                                                        .value_limits,
                                                )
                                                .map_err(RunExecutionError::TaskState)?
                                        );
                                        let cancellation_wait = execution_cancellation.cancelled();
                                        let mut cancellation_wait =
                                            std::pin::pin!(cancellation_wait);
                                        let resolution = std::future::poll_fn(|context| {
                                            if cancellation_wait.as_mut().poll(context).is_ready() {
                                                return Poll::Ready(None);
                                            }
                                            wait.as_mut().poll(context).map(Some)
                                        })
                                        .await
                                        .transpose()
                                        .map_err(RunExecutionError::TaskState)?;
                                        (joined_task_ids, resolution)
                                    }
                                };
                                self.apply_task_cancellation(
                                    &accepted,
                                    &coordinator,
                                    task_id,
                                    &mut machine,
                                    &mut events,
                                )
                                .await?;
                                let Some(resolution) = resolution else {
                                    continue;
                                };
                                if cancellation.is_cancelled() || machine.outcome().is_some() {
                                    continue;
                                }
                                let (settlement_status, result_type, failure) = match &resolution {
                                    JoinResolutionV1::Succeeded(_) => {
                                        ("succeeded", Some(&suspension.expected_type), None)
                                    }
                                    JoinResolutionV1::Failed(failure) => {
                                        ("failed", None, Some(failure))
                                    }
                                    JoinResolutionV1::Pending(_) => {
                                        return Err(RunExecutionError::LifecycleTransition);
                                    }
                                };
                                let draft = concurrent_join_event(
                                    accepted.execution_id,
                                    task_id,
                                    kind,
                                    &joined_task_ids,
                                    settlement_status,
                                    result_type,
                                    failure,
                                    0,
                                )
                                .map_err(|_| RunExecutionError::LifecycleTransition)?;
                                self.complete_and_enqueue_nondurable_event(
                                    &coordinator,
                                    &accepted.handle,
                                    &accepted.event_delivery,
                                    events.complete_task_draft(draft),
                                )
                                .await?;
                                self.apply_task_cancellation(
                                    &accepted,
                                    &coordinator,
                                    task_id,
                                    &mut machine,
                                    &mut events,
                                )
                                .await?;
                                if !cancellation.is_cancelled() && machine.outcome().is_none() {
                                    machine
                                        .complete_join(&suspension, resolution)
                                        .map_err(|_| RunExecutionError::LifecycleTransition)?;
                                }
                            } else if let Some(suspension) = machine
                                .pending_task_control()
                                .and_then(|pending| pending.detach())
                                .cloned()
                            {
                                let ownership = coordinator
                                    .detach_source_handle(
                                        task_id,
                                        suspension.workflow.clone(),
                                        suspension.site.clone(),
                                        Arc::from(suspension.handle.name()),
                                        suspension.handle.identity(),
                                    )
                                    .map_err(RunExecutionError::TaskState)?;
                                let draft =
                                    concurrent_detach_event(accepted.execution_id, &ownership, 0)
                                        .map_err(|_| RunExecutionError::LifecycleTransition)?;
                                self.complete_and_enqueue_nondurable_event(
                                    &coordinator,
                                    &accepted.handle,
                                    &accepted.event_delivery,
                                    events.complete_task_draft(draft),
                                )
                                .await?;
                                self.apply_task_cancellation(
                                    &accepted,
                                    &coordinator,
                                    task_id,
                                    &mut machine,
                                    &mut events,
                                )
                                .await?;
                                if !cancellation.is_cancelled() && machine.outcome().is_none() {
                                    machine
                                        .complete_detach(&suspension)
                                        .map_err(|_| RunExecutionError::LifecycleTransition)?;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                MachineStep::WaitingSessionScope(scope) => {
                    let parent = coordinator
                        .session(scope.parent_session_id)
                        .ok_or(RunExecutionError::MissingLogicalSession)?;
                    if session_establisher
                        .establish(accepted.execution_id, &parent)
                        .await
                        .is_err()
                    {
                        machine
                            .fail_session_scope(
                                &scope,
                                RuntimeCode::Operation(RuntimeErrorCategory::LogicalSessionSetup),
                            )
                            .map_err(|_| RunExecutionError::LifecycleTransition)?;
                        continue;
                    }
                    if cancellation.is_cancelled() {
                        continue;
                    }
                    let child = coordinator
                        .create_session(
                            scope.parent_session_id,
                            task_id,
                            scope.site.clone(),
                            scope.occurrence,
                            scope.mode,
                            SessionEstablishmentV1::Separate,
                        )
                        .map_err(RunExecutionError::Session)?;
                    if session_establisher
                        .establish(accepted.execution_id, &child)
                        .await
                        .is_err()
                    {
                        machine
                            .fail_session_scope(
                                &scope,
                                RuntimeCode::Operation(RuntimeErrorCategory::LogicalSessionSetup),
                            )
                            .map_err(|_| RunExecutionError::LifecycleTransition)?;
                        continue;
                    }
                    if cancellation.is_cancelled() {
                        continue;
                    }
                    machine
                        .complete_session_scope(&scope, child.id)
                        .map_err(|_| RunExecutionError::LifecycleTransition)?;
                }
                MachineStep::YieldRequired => {
                    if cancellation.is_cancelled() {
                        continue;
                    }
                    if self
                        .inner
                        .configuration
                        .executor()
                        .yield_now()
                        .await
                        .is_err()
                    {
                        if !execution_foreground {
                            let _ = machine.fail_execution(
                                RuntimeErrorCategory::ExecutorFailure,
                                gantry_runtime::ExecutionFailureProjection::Full,
                            );
                            continue;
                        }
                        let failure = MachineFailure {
                            code: RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure),
                            workflow: workflow.clone(),
                            site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
                                .map_err(|_| RunExecutionError::LifecycleTransition)?,
                            #[cfg(feature = "concurrent")]
                            join_failure: None,
                        };
                        let outcome = MachineOutcome::Failed(failure.clone());
                        coordinator
                            .settle_task(task_id, outcome.clone())
                            .map_err(RunExecutionError::TaskState)?;
                        let coordinated = coordinator
                            .complete_foreground()
                            .map_err(RunExecutionError::TaskState)?;
                        if coordinated != outcome {
                            return Err(RunExecutionError::LifecycleTransition);
                        }
                        coordinator
                            .complete_terminal()
                            .map_err(RunExecutionError::TaskState)?;
                        self.fix_failed_execution(&accepted, failure)?;
                        return Err(RunExecutionError::ExecutorFailure);
                    }
                    if cancellation.is_cancelled() {
                        continue;
                    }
                    if !machine.resume_after_yield() {
                        return Err(RunExecutionError::LifecycleTransition);
                    }
                }
                MachineStep::WaitingOperation(operation) => {
                    let Some(metadata) = operation.metadata.as_ref() else {
                        if !execution_foreground {
                            let _ = machine.fail_execution(
                                RuntimeErrorCategory::InternalInvariantFailure,
                                gantry_runtime::ExecutionFailureProjection::Full,
                            );
                            continue;
                        }
                        let failure = MachineFailure {
                            code: RuntimeCode::InternalInvariant,
                            workflow: operation.workflow,
                            site: operation.site,
                            #[cfg(feature = "concurrent")]
                            join_failure: None,
                        };
                        self.fix_failed_execution(&accepted, failure)?;
                        return Err(RunExecutionError::MissingOperationMetadata);
                    };
                    match metadata.kind {
                        OperationSiteKind::Action => {
                            self.drive_action_operation(
                                &accepted,
                                analysis,
                                &mut machine,
                                hook.as_mut()
                                    .ok_or(RunExecutionError::LifecycleTransition)?,
                                &cancellation,
                                &operation,
                            )
                            .await?;
                        }
                        OperationSiteKind::Prompt | OperationSiteKind::Decide => {
                            self.drive_model_operation(
                                &accepted,
                                analysis,
                                &mut machine,
                                hook.as_mut()
                                    .ok_or(RunExecutionError::LifecycleTransition)?,
                                &cancellation,
                                &operation,
                                &coordinator,
                                &session_establisher,
                                model_session_occurrence,
                            )
                            .await?;
                            model_session_occurrence = model_session_occurrence.saturating_add(1);
                        }
                    }
                }
                MachineStep::Complete(_) => {
                    if execution_foreground {
                        return self
                            .inner
                            .lifecycle
                            .query_execution(accepted.execution_id)
                            .map_err(RunExecutionError::Lifecycle);
                    }
                    return Ok(None);
                }
            }
        }
    }

    async fn apply_task_cancellation(
        &self,
        accepted: &StartExecutionAccepted,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        machine: &mut Machine,
        events: &mut ExecutionEventPipeline<'_>,
    ) -> Result<(), RunExecutionError> {
        if machine.outcome().is_some() {
            return Ok(());
        }
        let coordinated_reason = coordinator
            .snapshot()
            .state()
            .task_cancellation_reason(task_id)
            .map(Arc::from);
        let lifecycle_reason = accepted
            .handle
            .cancellation_signal()
            .ok()
            .filter(CancellationToken::is_cancelled)
            .map(|_| {
                self.inner
                    .lifecycle
                    .query_execution(accepted.execution_id)
                    .ok()
                    .flatten()
                    .and_then(|snapshot| snapshot.cancellation)
                    .map_or_else(
                        || Arc::from("cancellation"),
                        |reason| {
                            reason
                                .message
                                .unwrap_or_else(|| Arc::from(reason.category.wire_name()))
                        },
                    )
            });
        let Some(reason) = coordinated_reason.or(lifecycle_reason) else {
            return Ok(());
        };
        coordinator
            .cancel_task_tree(task_id, Arc::clone(&reason))
            .map_err(RunExecutionError::TaskState)?;
        if let Some(label) = machine.cancel(reason)
            && let Some(draft) = machine_lifecycle_event(&label, accepted.execution_id, task_id)
        {
            self.complete_and_enqueue_nondurable_event(
                coordinator,
                &accepted.handle,
                &accepted.event_delivery,
                events.complete_task_draft(draft),
            )
            .await?;
        }
        Ok(())
    }

    #[cfg(feature = "concurrent")]
    async fn cancel_and_drain_nondurable_descendants(
        &self,
        execution_id: ProtocolIdentity,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        outcome: &MachineOutcome,
    ) -> Result<(), RunExecutionError> {
        let reason: Arc<str> = match outcome {
            MachineOutcome::Failed(failure) => Arc::from(failure.code.wire_name()),
            MachineOutcome::Cancelled(reason) => Arc::clone(reason),
            MachineOutcome::Succeeded(_) => return Ok(()),
        };
        let mut affected = {
            let snapshot = coordinator.snapshot();
            let state = snapshot.state();
            let attached = state.shutdown_cohort().attached_tasks;
            let mut descendants = Vec::new();
            let mut frontier = vec![task_id];
            while let Some(parent_task_id) = frontier.pop() {
                for child_task_id in &attached {
                    if descendants.contains(child_task_id) {
                        continue;
                    }
                    if state
                        .task(*child_task_id)
                        .is_some_and(|child| child.parent_task_id() == parent_task_id)
                    {
                        descendants.push(*child_task_id);
                        frontier.push(*child_task_id);
                    }
                }
            }
            descendants
        };
        let direct_attached_children = {
            let snapshot = coordinator.snapshot();
            let state = snapshot.state();
            affected
                .iter()
                .copied()
                .filter(|child_task_id| {
                    state
                        .task(*child_task_id)
                        .is_some_and(|child| child.parent_task_id() == task_id)
                })
                .collect::<Vec<_>>()
        };
        for child_task_id in direct_attached_children {
            for newly_affected in coordinator
                .cancel_task_tree(child_task_id, Arc::clone(&reason))
                .map_err(RunExecutionError::TaskState)?
            {
                if !affected.contains(&newly_affected) {
                    affected.push(newly_affected);
                }
            }
        }
        if affected.is_empty() {
            return Ok(());
        }

        let selected = self
            .inner
            .lifecycle
            .task_supervisor()
            .owned_task_controls(execution_id, &affected);
        let waits = affected
            .iter()
            .copied()
            .map(|affected_task_id| coordinator.wait_for_task_settlement(affected_task_id))
            .collect::<Result<Vec<_>, _>>()
            .map_err(RunExecutionError::TaskState)?;
        let graceful_controls = Arc::clone(&selected);
        let graceful = deadline_race(
            self.inner.configuration.executor(),
            Box::pin(async move {
                for wait in waits {
                    wait.await;
                }
                for task in graceful_controls.iter() {
                    let _ = task.completion().await;
                }
            }),
            self.inner.configuration.post_cancellation_drain(),
            None,
        )
        .await;
        if matches!(graceful, DeadlineOutcome::Completed(())) {
            return Ok(());
        }

        request_abort_for_active_controls(&selected);
        let physical = deadline_race(
            self.inner.configuration.executor(),
            Box::pin(wait_for_abort_and_completion(&selected)),
            self.inner.configuration.post_cancellation_drain(),
            None,
        )
        .await;
        if !matches!(physical, DeadlineOutcome::Completed(Ok(()))) {
            return Err(RunExecutionError::ExecutorFailure);
        }
        let snapshot = coordinator.snapshot();
        if affected.iter().any(|affected_task_id| {
            snapshot
                .state()
                .task_record(*affected_task_id)
                .is_some_and(|task| {
                    matches!(
                        task.status(),
                        ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running
                    )
                })
        }) {
            return Err(RunExecutionError::ExecutorFailure);
        }
        Ok(())
    }

    #[cfg(feature = "concurrent")]
    async fn settle_nondurable_cancelled_child(
        &self,
        accepted: &StartExecutionAccepted,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        events: &mut ExecutionEventPipeline<'_>,
    ) -> Result<(), RunExecutionError> {
        let snapshot = coordinator.snapshot();
        let state = snapshot.state();
        let reason = state
            .task_cancellation_reason(task_id)
            .map(Arc::<str>::from)
            .ok_or(RunExecutionError::LifecycleTransition)?;
        match state.task(task_id).map(|task| task.status().kind()) {
            Some(gantry_core::portable::TaskStatusKind::Submitting) => coordinator
                .resolve_unsubmitted_cancellation(task_id)
                .map_err(RunExecutionError::TaskState)?,
            Some(gantry_core::portable::TaskStatusKind::Running) => coordinator
                .settle_task(task_id, MachineOutcome::Cancelled(Arc::clone(&reason)))
                .map_err(RunExecutionError::TaskState)?,
            Some(gantry_core::portable::TaskStatusKind::Cancelled) => {}
            _ => return Err(RunExecutionError::LifecycleTransition),
        }
        drop(snapshot);
        for label in [
            MachineLabel::Cancellation {
                reason: Arc::clone(&reason),
            },
            MachineLabel::TaskSettled(MachineOutcome::Cancelled(reason)),
        ]
        .into_iter()
        {
            let draft = machine_lifecycle_event(&label, accepted.execution_id, task_id)
                .ok_or(RunExecutionError::LifecycleTransition)?;
            self.complete_and_enqueue_nondurable_event(
                coordinator,
                &accepted.handle,
                &accepted.event_delivery,
                events.complete_task_draft_for(task_id, draft),
            )
            .await?;
        }
        Ok(())
    }

    #[cfg(feature = "concurrent")]
    async fn settle_nondurable_child_executor_failure(
        &self,
        accepted: &StartExecutionAccepted,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        workflow: &gantry_ir::CanonicalPath,
        site: &gantry_ir::StructuralPosition,
        events: &mut ExecutionEventPipeline<'_>,
    ) -> Result<(), RunExecutionError> {
        let outcome = MachineOutcome::Failed(MachineFailure {
            code: RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure),
            workflow: workflow.clone(),
            site: site.clone(),
            #[cfg(feature = "concurrent")]
            join_failure: None,
        });
        coordinator
            .settle_task(task_id, outcome.clone())
            .map_err(RunExecutionError::TaskState)?;
        let draft = machine_lifecycle_event(
            &MachineLabel::TaskSettled(outcome),
            accepted.execution_id,
            task_id,
        )
        .ok_or(RunExecutionError::LifecycleTransition)?;
        self.complete_and_enqueue_nondurable_event(
            coordinator,
            &accepted.handle,
            &accepted.event_delivery,
            events.complete_task_draft_for(task_id, draft),
        )
        .await?;
        Ok(())
    }

    async fn wait_for_nondurable_attached_tasks(
        &self,
        coordinator: &ExecutionCoordinator,
    ) -> Result<(), RunExecutionError> {
        loop {
            let attached = coordinator.shutdown_cohort().attached_tasks;
            if attached.is_empty() {
                return Ok(());
            }
            for task_id in attached {
                coordinator
                    .wait_for_task_settlement(task_id)
                    .map_err(RunExecutionError::TaskState)?
                    .await;
            }
        }
    }

    async fn complete_and_enqueue_nondurable_event<F>(
        &self,
        coordinator: &ExecutionCoordinator,
        handle: &ExecutionHandle,
        initial_plan: &SinkPlan,
        completion: F,
    ) -> Result<(), RunExecutionError>
    where
        F: Future<Output = Result<CompletedExecutionEventV1, ExecutionEventError>>,
    {
        let active_plan = coordinator.event_plan(initial_plan);
        if active_plan.registrations().is_empty() {
            completion.await.map_err(RunExecutionError::Event)?;
            return Ok(());
        }
        let completed = completion.await.map_err(RunExecutionError::Event)?;
        self.handoff_nondurable_event_delivery(coordinator, handle, completed, active_plan)?
            .await;
        Ok(())
    }

    fn handoff_nondurable_event_delivery(
        &self,
        coordinator: &ExecutionCoordinator,
        handle: &ExecutionHandle,
        completed: CompletedExecutionEventV1,
        plan: SinkPlan,
    ) -> Result<gantry_runtime::OwnedEventDeliveryHandoffWait, RunExecutionError> {
        let required = plan.required_only();
        let best_effort = plan.best_effort_only();
        let has_required = !required.registrations().is_empty();
        let has_best_effort = !best_effort.registrations().is_empty();
        let (required_delivery, best_effort_delivery) = coordinator
            .begin_event_delivery_plan(has_required, has_best_effort)
            .map_err(|_| RunExecutionError::Event(ExecutionEventError::TaskSequenceExhausted))?;
        let inner = Arc::clone(&self.inner);
        let delivery_coordinator = coordinator.clone();
        let required_predecessor = required_delivery
            .map(|delivery| coordinator.wait_for_required_event_delivery_predecessors(delivery));
        let best_effort_predecessor = best_effort_delivery
            .map(|delivery| coordinator.wait_for_best_effort_event_delivery_predecessors(delivery));
        let required_settled = Arc::new(AtomicBool::new(false));
        let best_effort_settled = Arc::new(AtomicBool::new(false));
        let operation_required_settled = Arc::clone(&required_settled);
        let operation_best_effort_settled = Arc::clone(&best_effort_settled);
        let abnormal_required_settled = Arc::clone(&required_settled);
        let abnormal_best_effort_settled = Arc::clone(&best_effort_settled);
        let operation_coordinator = coordinator.clone();
        let operation_handle = handle.clone();
        Ok(self.inner.lifecycle.spawn_owned_event_delivery_after(
            async move {
                if let Some(predecessor) = required_predecessor {
                    predecessor.await;
                }
                if let Some(predecessor) = best_effort_predecessor {
                    predecessor.await;
                }
            },
            async move {
                if let Some(delivery) = required_delivery {
                    match DeliveryKernel::new(
                        &inner.allocator,
                        inner.configuration.identity_source(),
                        inner.event_delivery_runtime.as_ref(),
                    )
                    .deliver(
                        completed.event.clone(),
                        &completed.protected_payloads,
                        &required,
                    )
                    .await
                    {
                        Ok(delivery_result) => {
                            if let ActivityBarrier::RequiredExhausted {
                                sink_id,
                                event_id,
                                attempt_id,
                            } = delivery_result.barrier
                            {
                                operation_coordinator.exclude_event_sink(&sink_id);
                                operation_coordinator.note_required_event_delivery_failure();
                                let failure = gantry_runtime::RequiredEventDeliveryFailureV1 {
                                    sink_id,
                                    event_id,
                                    attempt_id,
                                };
                                if let Some(terminal) = operation_coordinator.terminal_outcome() {
                                    let _ = operation_handle
                                        .record_post_terminal_required_delivery_failure(
                                            failure, terminal,
                                        );
                                } else {
                                    let _ =
                                        operation_handle.record_required_delivery_failure(failure);
                                    let _ = operation_coordinator.cancel_execution(Arc::from(
                                        "required-event-delivery-failure",
                                    ));
                                }
                            }
                        }
                        Err(_) => {
                            operation_coordinator.note_event_delivery_executor_failure();
                            let _ = operation_coordinator
                                .cancel_execution(Arc::from("event-delivery-executor-failure"));
                        }
                    }
                    operation_required_settled.store(true, Ordering::Release);
                    operation_coordinator.settle_required_event_delivery(delivery);
                }
                if let Some(delivery) = best_effort_delivery {
                    let _ = DeliveryKernel::new(
                        &inner.allocator,
                        inner.configuration.identity_source(),
                        inner.event_delivery_runtime.as_ref(),
                    )
                    .deliver(completed.event, &completed.protected_payloads, &best_effort)
                    .await;
                    operation_best_effort_settled.store(true, Ordering::Release);
                    operation_coordinator.settle_best_effort_event_delivery(delivery);
                }
            },
            move |result| {
                if let Some(delivery) = required_delivery
                    && !abnormal_required_settled.swap(true, Ordering::AcqRel)
                {
                    if !matches!(result, Ok(())) {
                        delivery_coordinator.note_event_delivery_executor_failure();
                        let _ = delivery_coordinator
                            .cancel_execution(Arc::from("event-delivery-executor-failure"));
                    }
                    delivery_coordinator.settle_required_event_delivery(delivery);
                }
                if let Some(delivery) = best_effort_delivery
                    && !abnormal_best_effort_settled.swap(true, Ordering::AcqRel)
                {
                    delivery_coordinator.settle_best_effort_event_delivery(delivery);
                }
            },
        ))
    }

    #[cfg(feature = "concurrent")]
    #[allow(clippy::too_many_arguments)]
    async fn fail_source_child_submission(
        &self,
        accepted: &StartExecutionAccepted,
        machine: &mut Machine,
        coordinator: &ExecutionCoordinator,
        parent_task_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        handle_id: gantry_runtime::DynamicTaskHandleIdentity,
        cancellation: &dyn CancellationToken,
        events: &mut ExecutionEventPipeline<'_>,
        suspension: &MachineSpawnSuspension,
    ) -> Result<(), RunExecutionError> {
        self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine, events)
            .await?;
        if cancellation.is_cancelled() || machine.outcome().is_some() {
            self.settle_nondurable_cancelled_child(accepted, coordinator, task_id, events)
                .await?;
            return Ok(());
        }
        let outcome = MachineOutcome::Failed(MachineFailure {
            code: RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure),
            workflow: suspension.workflow.clone(),
            site: suspension.site.clone(),
            #[cfg(feature = "concurrent")]
            join_failure: None,
        });
        machine
            .complete_spawn(suspension, handle_id)
            .map_err(|_| RunExecutionError::LifecycleTransition)?;
        let disposition = coordinator
            .resolve_submission(
                task_id,
                Err(HostError {
                    code: Arc::from("task-submission-failure"),
                    protected_diagnostic: None,
                }),
            )
            .map_err(RunExecutionError::TaskState)?;
        if disposition == gantry_core::portable::TaskStatusKind::Cancelled {
            return Ok(());
        }
        let draft = machine_lifecycle_event(
            &MachineLabel::TaskSettled(outcome),
            accepted.execution_id,
            task_id,
        )
        .ok_or(RunExecutionError::LifecycleTransition)?;
        self.complete_and_enqueue_nondurable_event(
            coordinator,
            &accepted.handle,
            &accepted.event_delivery,
            events.complete_task_draft_for(task_id, draft),
        )
        .await?;
        Ok(())
    }

    #[cfg(feature = "concurrent")]
    #[allow(clippy::too_many_arguments)]
    async fn submit_source_child(
        &self,
        accepted: &StartExecutionAccepted,
        machine: &mut Machine,
        coordinator: &ExecutionCoordinator,
        parent_task_id: ProtocolIdentity,
        program: &Arc<gantry_ir::MachineProgram>,
        execution_budget: &ExecutionBudget,
        session_establisher: &SessionEstablisher,
        cancellation: &dyn CancellationToken,
        events: &mut ExecutionEventPipeline<'_>,
        _execution_foreground: bool,
        suspension: MachineSpawnSuspension,
    ) -> Result<(), RunExecutionError> {
        self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine, events)
            .await?;
        if cancellation.is_cancelled() || machine.outcome().is_some() {
            return Ok(());
        }
        let task_limit_reached = |coordinator: &ExecutionCoordinator| {
            let state = coordinator.snapshot();
            state.state().created_task_count() >= state.state().maximum_task_count()
        };
        if task_limit_reached(coordinator) {
            machine
                .fail_spawn(
                    &suspension,
                    RuntimeCode::Deterministic(DeterministicEvaluationCode::TaskCountLimit),
                )
                .map_err(|_| RunExecutionError::LifecycleTransition)?;
            return Ok(());
        }
        let parent_session_id = suspension
            .parent_session
            .ok_or(RunExecutionError::MissingLogicalSession)?;
        let parent_session = coordinator
            .session(parent_session_id)
            .ok_or(RunExecutionError::MissingLogicalSession)?;
        if session_establisher
            .establish(accepted.execution_id, &parent_session)
            .await
            .is_err()
        {
            let _ = machine.fail_execution(
                RuntimeErrorCategory::LogicalSessionSetup,
                gantry_runtime::ExecutionFailureProjection::Full,
            );
            return Ok(());
        }
        self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine, events)
            .await?;
        if cancellation.is_cancelled() || machine.outcome().is_some() {
            return Ok(());
        }
        if task_limit_reached(coordinator) {
            machine
                .fail_spawn(
                    &suspension,
                    RuntimeCode::Deterministic(DeterministicEvaluationCode::TaskCountLimit),
                )
                .map_err(|_| RunExecutionError::LifecycleTransition)?;
            return Ok(());
        }

        let captures = suspension
            .captures
            .iter()
            .map(|capture| capture.task_capture().clone())
            .collect::<Vec<_>>();
        let created = match coordinator.create_child(
            TaskCreationRequestV1 {
                parent_task_id,
                handle_name: Arc::from(suspension.handle.name()),
                workflow: suspension.workflow.clone(),
                spawn_site: suspension.site.clone(),
                spawn_occurrence: suspension.occurrence,
                result_type: suspension.handle.result_type().clone(),
                captures: captures.clone(),
                inherited_agent: suspension.inherited_agent.clone(),
                parent_session_id,
            },
            self.inner.configuration.required().value_limits,
        ) {
            Ok(created) => created,
            Err(TaskStateError::TaskCountLimit) => {
                machine
                    .fail_spawn(
                        &suspension,
                        RuntimeCode::Deterministic(DeterministicEvaluationCode::TaskCountLimit),
                    )
                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                return Ok(());
            }
            Err(error) => return Err(RunExecutionError::TaskState(error)),
        };

        let spawn_event = concurrent_spawn_event(accepted.execution_id, &created.transition, 0)
            .map_err(|_| RunExecutionError::LifecycleTransition)?;
        self.complete_and_enqueue_nondurable_event(
            coordinator,
            &accepted.handle,
            &accepted.event_delivery,
            events.complete_task_draft(spawn_event),
        )
        .await?;

        self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine, events)
            .await?;
        if cancellation.is_cancelled() || machine.outcome().is_some() {
            // This already-created child never acquired executor ownership, so
            // cancellation settles both its semantics and physical driver coordinate.
            self.settle_nondurable_cancelled_child(accepted, coordinator, created.task_id, events)
                .await?;
            return Ok(());
        }
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve(AdmissionClass::SourceChildTask) {
            Ok(reservation) if !cancellation.is_cancelled() && machine.outcome().is_none() => {
                reservation
            }
            Ok(reservation) => {
                drop(reservation);
                self.apply_task_cancellation(
                    accepted,
                    coordinator,
                    parent_task_id,
                    machine,
                    events,
                )
                .await?;
                self.settle_nondurable_cancelled_child(
                    accepted,
                    coordinator,
                    created.task_id,
                    events,
                )
                .await?;
                return Ok(());
            }
            Err(_) => {
                self.apply_task_cancellation(
                    accepted,
                    coordinator,
                    parent_task_id,
                    machine,
                    events,
                )
                .await?;
                if cancellation.is_cancelled() || machine.outcome().is_some() {
                    self.settle_nondurable_cancelled_child(
                        accepted,
                        coordinator,
                        created.task_id,
                        events,
                    )
                    .await?;
                    return Ok(());
                }
                self.fail_source_child_submission(
                    accepted,
                    machine,
                    coordinator,
                    parent_task_id,
                    created.task_id,
                    created.handle_id,
                    cancellation,
                    events,
                    &suspension,
                )
                .await?;
                return Ok(());
            }
        };

        let snapshot = coordinator.snapshot();
        let child_record = snapshot
            .state()
            .task(created.task_id)
            .ok_or(RunExecutionError::TaskState(TaskStateError::UnknownTask))?;
        let child_session = coordinator
            .session(created.base_session_id)
            .ok_or(RunExecutionError::MissingLogicalSession)?;
        let root_session = coordinator
            .session(child_session.root)
            .ok_or(RunExecutionError::MissingLogicalSession)?;
        let root_provenance = match root_session.mode {
            SessionCreationModeV1::EmbedderRoot => RootSessionProvenanceV1::EmbedderSupplied,
            SessionCreationModeV1::GantryRoot => RootSessionProvenanceV1::GantryCreated,
            SessionCreationModeV1::New | SessionCreationModeV1::Fork => {
                return Err(RunExecutionError::LifecycleTransition);
            }
        };
        let child_machine = match Machine::new_concurrent_task_body_with_context(
            Arc::clone(program),
            &suspension.body,
            &captures,
            accepted.execution_id,
            created.task_id,
            Arc::from(child_record.task_path()),
            self.inner.configuration.machine_limits(),
            execution_budget.clone(),
            suspension.inherited_agent.clone(),
            Some(created.base_session_id),
        ) {
            Ok(machine) => machine,
            Err(_) => {
                drop(reservation);
                self.fail_source_child_submission(
                    accepted,
                    machine,
                    coordinator,
                    parent_task_id,
                    created.task_id,
                    created.handle_id,
                    cancellation,
                    events,
                    &suspension,
                )
                .await?;
                return Ok(());
            }
        };
        let create_request = match (TaskContextV1 {
            execution_id: accepted.execution_id,
            task_id: created.task_id,
            inherited_agent: suspension.inherited_agent.clone(),
            session: TaskSessionContextV1::Forked {
                base_session_id: created.base_session_id,
                parent_session_id,
                root_session_id: child_session.root,
                root_provenance,
            },
        })
        .into_host_request()
        {
            Ok(request) => request,
            Err(_) => {
                drop(reservation);
                self.fail_source_child_submission(
                    accepted,
                    machine,
                    coordinator,
                    parent_task_id,
                    created.task_id,
                    created.handle_id,
                    cancellation,
                    events,
                    &suspension,
                )
                .await?;
                return Ok(());
            }
        };
        let prepared = PreparedTaskDriver {
            machine: child_machine,
            coordinator: coordinator.clone(),
            task_id: created.task_id,
            workflow: suspension.workflow.clone(),
            create_request,
            base_session: Some(created.base_session_id),
            program: Arc::clone(program),
            execution_budget: execution_budget.clone(),
        };
        let driver = TaskDriver::from_child(Arc::clone(&self.inner), accepted.clone(), prepared);
        let abnormal = driver.abnormal_completion_handler();
        let completion = driver.physical_completion_handler();
        let registration = supervisor.prepare_owned_deferred_with_completion(
            SupervisedTaskDomain::SourceChild,
            accepted.execution_id,
            created.task_id,
            Some(abnormal),
            Some(completion),
        );
        let signal = registration.signal();
        let gate = Arc::new(RootStartGate::default());
        let task = driver.into_gated_owned_task(signal.clone(), Arc::clone(&gate));

        #[cfg(feature = "test-support")]
        if let Some(cancellation) =
            lock_shutdown(&self.inner.nondurable_cancel_before_child_submit).take()
        {
            cancellation.cancel();
        }
        self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine, events)
            .await?;
        if cancellation.is_cancelled() || machine.outcome().is_some() {
            gate.cancel();
            drop(task);
            drop(reservation);
            self.settle_nondurable_cancelled_child(accepted, coordinator, created.task_id, events)
                .await?;
            return Ok(());
        }
        #[cfg(feature = "test-support")]
        if let Some(hook) =
            lock_shutdown(&self.inner.nondurable_before_child_executor_submit).take()
        {
            hook();
        }
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => {
                self.apply_task_cancellation(
                    accepted,
                    coordinator,
                    parent_task_id,
                    machine,
                    events,
                )
                .await?;
                if cancellation.is_cancelled() || machine.outcome().is_some() {
                    let disposition = coordinator
                        .resolve_submission(created.task_id, Ok(()))
                        .map_err(RunExecutionError::TaskState)?;
                    if disposition != gantry_core::portable::TaskStatusKind::Cancelled {
                        return Err(RunExecutionError::LifecycleTransition);
                    }
                    self.settle_nondurable_cancelled_child(
                        accepted,
                        coordinator,
                        created.task_id,
                        events,
                    )
                    .await?;
                    self.rollback_submitted_source_child(task, &signal, &gate)
                        .await
                        .map_err(|_| RunExecutionError::ExecutorFailure)?;
                    return Ok(());
                }
                // The child gate stays closed until the task-created event, submission
                // handle, and submission state are published in that order. These two
                // in-memory transitions cannot be atomic; the closed gate prevents child
                // progress across their bounded interval.
                let disposition = machine
                    .complete_spawn(&suspension, created.handle_id)
                    .map_err(|_| TaskStateError::InvalidTransition)
                    .and_then(|_| coordinator.resolve_submission(created.task_id, Ok(())));
                let Ok(disposition) = disposition else {
                    gate.cancel();
                    let fallback = MachineOutcome::Failed(MachineFailure {
                        code: RuntimeCode::InternalInvariant,
                        workflow: suspension.workflow,
                        site: suspension.site,
                        #[cfg(feature = "concurrent")]
                        join_failure: None,
                    });
                    let _ = coordinator.settle_task(created.task_id, fallback);
                    let _ = signal.settle();
                    let _ = signal.arm_completion_observation();
                    let _ = task.request_abort();
                    task.relinquish();
                    return Err(RunExecutionError::LifecycleTransition);
                };
                if disposition == gantry_core::portable::TaskStatusKind::Cancelled {
                    self.settle_nondurable_cancelled_child(
                        accepted,
                        coordinator,
                        created.task_id,
                        events,
                    )
                    .await?;
                    self.rollback_submitted_source_child(task, &signal, &gate)
                        .await
                        .map_err(|_| RunExecutionError::ExecutorFailure)?;
                    return Ok(());
                }

                #[cfg(feature = "test-support")]
                if let Some(cancellation) =
                    lock_shutdown(&self.inner.nondurable_cancel_after_child_resolution).take()
                {
                    cancellation.cancel();
                }
                if cancellation.is_cancelled() || machine.outcome().is_some() {
                    if self
                        .rollback_submitted_source_child(task, &signal, &gate)
                        .await
                        .is_err()
                    {
                        self.settle_nondurable_child_executor_failure(
                            accepted,
                            coordinator,
                            created.task_id,
                            &suspension.workflow,
                            &suspension.site,
                            events,
                        )
                        .await?;
                        return Err(RunExecutionError::ExecutorFailure);
                    }
                    self.apply_task_cancellation(
                        accepted,
                        coordinator,
                        parent_task_id,
                        machine,
                        events,
                    )
                    .await?;
                    self.settle_nondurable_cancelled_child(
                        accepted,
                        coordinator,
                        created.task_id,
                        events,
                    )
                    .await?;
                    return Ok(());
                }
                let _ = signal.arm_completion_observation();
                task.relinquish();
                gate.release();
            }
            Err(_) => {
                self.apply_task_cancellation(
                    accepted,
                    coordinator,
                    parent_task_id,
                    machine,
                    events,
                )
                .await?;
                if cancellation.is_cancelled() || machine.outcome().is_some() {
                    self.settle_nondurable_cancelled_child(
                        accepted,
                        coordinator,
                        created.task_id,
                        events,
                    )
                    .await?;
                    return Ok(());
                }
                self.fail_source_child_submission(
                    accepted,
                    machine,
                    coordinator,
                    parent_task_id,
                    created.task_id,
                    created.handle_id,
                    cancellation,
                    events,
                    &suspension,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Returns one linearizable point-in-time snapshot for an accepted execution identity.
    ///
    /// The snapshot may advance immediately after return; use the independent
    /// foreground or terminal waits when a completion coordinate is required.
    pub fn query_execution(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Result<Option<ExecutionSnapshot>, LifecycleError> {
        self.inner.lifecycle.query_execution(execution_id)
    }

    /// Returns concurrent task state for focused nondurable conformance assertions.
    #[cfg(all(feature = "concurrent", feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn test_nondurable_task_state(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Option<ConcurrentTaskStateV1> {
        self.inner
            .nondurable_executions
            .coordinator(execution_id)
            .map(|coordinator| coordinator.snapshot().state().clone())
    }

    /// Installs a one-shot callback at the source-child executor submission cut.
    #[cfg(all(feature = "concurrent", feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_before_nondurable_child_executor_submit(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *lock_shutdown(&self.inner.nondurable_before_child_executor_submit) = Some(hook);
    }

    /// Installs a deterministic cancellation at the last pre-submission checkpoint.
    #[cfg(all(feature = "concurrent", feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_cancel_nondurable_child_before_submit(&self, cancellation: CancellationSignal) {
        *lock_shutdown(&self.inner.nondurable_cancel_before_child_submit) = Some(cancellation);
    }

    /// Installs a deterministic cancellation after submission resolution but before gate release.
    #[cfg(all(feature = "concurrent", feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_cancel_nondurable_child_after_resolution(&self, cancellation: CancellationSignal) {
        *lock_shutdown(&self.inner.nondurable_cancel_after_child_resolution) = Some(cancellation);
    }

    /// Installs a deterministic durable cancellation at the last pre-submission checkpoint.
    #[cfg(all(feature = "concurrent", feature = "durable", feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_cancel_durable_child_before_submit(&self, reason: CancellationReason) {
        *lock_shutdown(&self.inner.durable_cancel_before_child_submit) = Some(reason);
    }

    /// Installs a deterministic durable cancellation immediately after child submission.
    #[cfg(all(feature = "concurrent", feature = "durable", feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_cancel_durable_child_after_submit(&self, reason: CancellationReason) {
        *lock_shutdown(&self.inner.durable_cancel_after_child_submit) = Some(reason);
    }

    /// Installs a deterministic durable cancellation after child session establishment.
    #[cfg(all(feature = "concurrent", feature = "durable", feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_cancel_durable_child_after_session_establishment(
        &self,
        reason: CancellationReason,
    ) {
        *lock_shutdown(&self.inner.durable_cancel_after_child_session_establishment) = Some(reason);
    }

    /// Returns how often a child continued after the test cancellation cut was committed.
    #[cfg(all(feature = "concurrent", feature = "durable", feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_durable_cancelled_child_continuations(&self) -> usize {
        self.inner
            .durable_cancelled_child_continuations
            .load(Ordering::Acquire)
    }

    /// Returns the active physical-task registry for focused ownership assertions.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_task_supervisor_snapshot(&self) -> gantry_runtime::TaskSupervisorSnapshot {
        self.inner.lifecycle.task_supervisor().snapshot()
    }

    /// Aborts physical drivers owned by one execution for deterministic handoff tests.
    #[cfg(all(feature = "concurrent", feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn test_abort_nondurable_execution_tasks(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Arc<[SupervisedTask]> {
        self.inner
            .lifecycle
            .task_supervisor()
            .request_abort_owned_execution(execution_id)
    }

    #[cfg(feature = "concurrent")]
    async fn rollback_submitted_source_child(
        &self,
        task: SupervisedTask,
        signal: &SupervisionSignal,
        gate: &RootStartGate,
    ) -> Result<(), SubmittedChildRollbackFailure> {
        gate.cancel();
        let _ = signal.settle();
        let _ = signal.arm_completion_observation();
        if !task.request_abort() {
            let completion = task.snapshot().completion;
            task.relinquish();
            return match completion {
                Some(OwnedTaskCompletion::Completed(_) | OwnedTaskCompletion::Stopped) => Ok(()),
                Some(OwnedTaskCompletion::Failed(_) | OwnedTaskCompletion::Panicked { .. })
                | None => Err(SubmittedChildRollbackFailure),
            };
        }
        let completion = deadline_race(
            self.inner.configuration.executor(),
            Box::pin(task.completion()),
            self.inner.configuration.post_cancellation_drain(),
            None,
        )
        .await;
        let abort = task.snapshot().abort_result;
        task.relinquish();
        if matches!(abort, Some(OwnedTaskAbort::Failed(_))) {
            return Err(SubmittedChildRollbackFailure);
        }
        match completion {
            DeadlineOutcome::Completed(
                OwnedTaskCompletion::Completed(_) | OwnedTaskCompletion::Stopped,
            ) => Ok(()),
            DeadlineOutcome::Completed(
                OwnedTaskCompletion::Failed(_) | OwnedTaskCompletion::Panicked { .. },
            )
            | DeadlineOutcome::TimedOut
            | DeadlineOutcome::Failed(_)
            | DeadlineOutcome::Cancelled => Err(SubmittedChildRollbackFailure),
        }
    }

    /// Returns the in-process durable observation for focused failure-order assertions.
    #[cfg(all(feature = "durable", feature = "test-support"))]
    #[doc(hidden)]
    pub async fn test_durable_observation(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Option<crate::DurableExecutionObservation> {
        self.durable_execution(execution_id)
            .await
            .map(|owner| owner.observation())
    }

    /// Waits independently for the foreground coordinate of one in-process handle.
    ///
    /// Foreground completion includes the root and required attached-descendant
    /// cleanup, but does not wait for execution-owned detached tasks. Dropping
    /// this future stops only this wait and does not cancel the execution.
    pub async fn await_foreground(
        &self,
        handle: &ExecutionHandle,
    ) -> Result<Option<ExecutionSnapshot>, LifecycleError> {
        Ok(self
            .inner
            .lifecycle
            .await_foreground(handle.execution_id())?
            .await)
    }

    /// Waits independently for the terminal coordinate of one in-process handle.
    ///
    /// Terminal completion additionally accounts for detached work and final
    /// execution obligations. Dropping this future stops only this wait and
    /// does not cancel the execution.
    pub async fn await_terminal(
        &self,
        handle: &ExecutionHandle,
    ) -> Result<Option<ExecutionSnapshot>, LifecycleError> {
        Ok(self
            .inner
            .lifecycle
            .await_terminal(handle.execution_id())?
            .await)
    }

    /// Records the first effective cancellation reason and waits for terminal settlement.
    ///
    /// Cancellation is scoped to the named execution, preserves the first
    /// effective reason, and does not affect unrelated executions. Durable
    /// cancellation commits before signalling task drivers. Dropping this
    /// caller stops only observation of the caller-independent cancellation
    /// and descendant-drain work.
    pub async fn cancel_execution(
        &self,
        execution_id: ProtocolIdentity,
        reason: CancellationReason,
    ) -> Result<CancellationRecord, CancelExecutionError> {
        #[cfg(feature = "durable")]
        if let Some(owner) = self.durable_execution(execution_id).await {
            return match self
                .cancel_durable_execution(&owner, execution_id, reason)
                .await
            {
                crate::DurableCancelExecutionResult::Accepted {
                    effective_reason, ..
                } => Ok(CancellationRecord::Accepted {
                    reason: effective_reason,
                    signal: owner
                        .execution_handle()
                        .cancellation_signal()
                        .map_err(CancelExecutionError::Transition)?,
                }),
                crate::DurableCancelExecutionResult::AlreadyTerminal(_) => owner
                    .execution_handle()
                    .snapshot()
                    .map(|snapshot| CancellationRecord::AlreadyTerminal(Box::new(snapshot)))
                    .map_err(CancelExecutionError::Transition),
                crate::DurableCancelExecutionResult::NotFound { .. } => {
                    Ok(CancellationRecord::NotFound)
                }
                crate::DurableCancelExecutionResult::Failed { failure, .. } => {
                    Err(CancelExecutionError::Durable(failure))
                }
            };
        }
        let admission = self
            .inner
            .lifecycle
            .admit(AdmissionKind::ExistingExecution(execution_id))
            .map_err(CancelExecutionError::Lifecycle)?;
        let Some(owner) = self.inner.nondurable_executions.owner(execution_id).await else {
            drop(admission);
            return Ok(CancellationRecord::NotFound);
        };
        owner.cancellation.request(reason);
        if owner.cancellation.claim() {
            self.start_nondurable_cancellation(Arc::clone(&owner));
        }
        drop(admission);
        std::future::poll_fn(|context| owner.cancellation.poll(context)).await
    }

    fn start_nondurable_cancellation(&self, owner: Arc<NondurableExecutionOwner>) {
        if self.inner.shutdown_started.load(Ordering::Acquire) {
            owner.cancellation.release_claim();
            self.start_owned_shutdown();
            return;
        }
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve_control_plane() {
            Ok(reservation) => reservation,
            Err(error) => {
                if self.inner.shutdown_started.load(Ordering::Acquire) {
                    owner.cancellation.release_claim();
                    self.start_owned_shutdown();
                } else {
                    owner
                        .cancellation
                        .publish(Err(CancelExecutionError::Admission(error)));
                }
                return;
            }
        };
        let cancellation = Arc::clone(&owner.cancellation);
        let completion_inner = Arc::clone(&self.inner);
        let completion: PhysicalCompletionHandler = Arc::new(move |_| {
            cancellation.mark_physically_completed();
            if completion_inner.shutdown_started.load(Ordering::Acquire) {
                let interpreter = Interpreter {
                    inner: Arc::clone(&completion_inner),
                    external_owner: false,
                };
                interpreter.start_owned_shutdown();
            }
        });
        let abnormal_cancellation = Arc::clone(&owner.cancellation);
        let abnormal: AbnormalCompletionHandler = Arc::new(move |completion| {
            abnormal_cancellation.publish(Err(CancelExecutionError::Physical(completion)));
        });
        let registration = supervisor.prepare_with_completion(
            SupervisedTaskDomain::ControlPlane,
            Some(abnormal),
            Some(completion),
        );
        let signal = registration.signal();
        let task_inner = Arc::clone(&self.inner);
        let task_cancellation = Arc::clone(&owner.cancellation);
        let task_owner = Arc::clone(&owner);
        let task: OwnedTaskFuture = Box::pin(async move {
            let interpreter = Interpreter {
                inner: task_inner,
                external_owner: false,
            };
            let result = interpreter.drive_nondurable_cancellation(&task_owner).await;
            task_cancellation.publish(result);
            let _ = signal.settle();
            OwnedTaskResult::new()
        });
        owner.cancellation.mark_control_active();
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => task.relinquish(),
            Err(error) => {
                owner.cancellation.mark_physically_completed();
                owner
                    .cancellation
                    .publish(Err(CancelExecutionError::Executor(error)));
                if self.inner.shutdown_started.load(Ordering::Acquire) {
                    self.start_owned_shutdown();
                }
            }
        }
    }

    async fn drive_nondurable_cancellation(
        &self,
        owner: &NondurableExecutionOwner,
    ) -> Result<CancellationRecord, CancelExecutionError> {
        let reason = owner
            .cancellation
            .requested_reason()
            .ok_or(CancelExecutionError::Invariant)?;
        let reason_text = reason
            .message
            .clone()
            .unwrap_or_else(|| Arc::from(reason.category.wire_name()));
        owner
            .coordinator
            .cancel_execution(reason_text)
            .map_err(CancelExecutionError::TaskState)?;
        let record = owner
            .handle
            .publish_committed_cancellation(reason)
            .map_err(CancelExecutionError::Transition)?;
        if matches!(record, CancellationRecord::AlreadyTerminal(_)) {
            return Ok(record);
        }

        let semantic_tasks = owner.coordinator.execution_cancellation_cohort();
        let semantic_waits = semantic_tasks
            .iter()
            .copied()
            .map(|task_id| owner.coordinator.wait_for_task_settlement(task_id))
            .collect::<Result<Vec<_>, _>>()
            .map_err(CancelExecutionError::TaskState)?;
        let semantic_settled = matches!(
            deadline_race(
                self.inner.configuration.executor(),
                Box::pin(async move {
                    for wait in semantic_waits {
                        wait.await;
                    }
                }),
                self.inner.configuration.post_cancellation_drain(),
                None,
            )
            .await,
            DeadlineOutcome::Completed(())
        );

        let selected = self
            .inner
            .lifecycle
            .task_supervisor()
            .owned_task_controls(owner.handle.execution_id(), &semantic_tasks);
        let completed_gracefully = if semantic_settled {
            let graceful_controls = Arc::clone(&selected);
            matches!(
                deadline_race(
                    self.inner.configuration.executor(),
                    Box::pin(async move {
                        for task in graceful_controls.iter() {
                            let _ = task.completion().await;
                        }
                    }),
                    self.inner.configuration.post_cancellation_drain(),
                    None,
                )
                .await,
                DeadlineOutcome::Completed(())
            )
        } else {
            false
        };
        if !completed_gracefully {
            request_abort_for_active_controls(&selected);
        }
        let aborted = selected;
        owner.cancellation.retain_aborts(Arc::clone(&aborted));
        if !aborted.is_empty() && !completed_gracefully {
            let physical = deadline_race(
                self.inner.configuration.executor(),
                Box::pin(wait_for_nondurable_abort_and_completion(&aborted)),
                self.inner.configuration.post_cancellation_drain(),
                None,
            )
            .await;
            match physical {
                DeadlineOutcome::Completed(Ok(())) => {}
                DeadlineOutcome::Completed(Err(error)) | DeadlineOutcome::Failed(error) => {
                    let snapshot = owner.coordinator.snapshot();
                    let root_task_id = snapshot.state().root_task_id();
                    drop(snapshot);
                    let outcome = MachineOutcome::Failed(MachineFailure {
                        code: RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure),
                        workflow: owner.workflow.clone(),
                        site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
                            .map_err(|_| CancelExecutionError::Invariant)?,
                        #[cfg(feature = "concurrent")]
                        join_failure: None,
                    });
                    owner
                        .coordinator
                        .settle_after_abort_failure(root_task_id, outcome.clone())
                        .map_err(CancelExecutionError::TaskState)?;
                    self.complete_nondurable_execution_if_ready(
                        &owner.coordinator,
                        &owner.handle,
                        outcome,
                    )
                    .map_err(|_| CancelExecutionError::Invariant)?;
                    return Err(CancelExecutionError::Executor(error));
                }
                DeadlineOutcome::TimedOut | DeadlineOutcome::Cancelled => {
                    let _ = owner.handle.publish_run_failed_nondurably();
                    return Err(CancelExecutionError::CleanupTimedOut);
                }
            }
        }

        let quiescence = deadline_race(
            self.inner.configuration.executor(),
            Box::pin(owner.coordinator.wait_for_shutdown_quiescence()),
            self.inner.configuration.post_cancellation_drain(),
            None,
        )
        .await;
        if !matches!(quiescence, DeadlineOutcome::Completed(())) {
            let _ = owner.handle.publish_run_failed_nondurably();
            return match quiescence {
                DeadlineOutcome::Failed(error) => Err(CancelExecutionError::Executor(error)),
                DeadlineOutcome::Completed(()) => unreachable!(),
                DeadlineOutcome::TimedOut | DeadlineOutcome::Cancelled => {
                    Err(CancelExecutionError::CleanupTimedOut)
                }
            };
        }
        let terminal = self
            .inner
            .lifecycle
            .await_terminal(owner.handle.execution_id())
            .map_err(CancelExecutionError::Lifecycle)?;
        match deadline_race(
            self.inner.configuration.executor(),
            Box::pin(terminal),
            self.inner.configuration.post_cancellation_drain(),
            None,
        )
        .await
        {
            DeadlineOutcome::Completed(_) => Ok(record),
            DeadlineOutcome::Failed(error) => Err(CancelExecutionError::Executor(error)),
            DeadlineOutcome::TimedOut | DeadlineOutcome::Cancelled => {
                let _ = owner.handle.publish_run_failed_nondurably();
                Err(CancelExecutionError::CleanupTimedOut)
            }
        }
    }

    #[cfg(feature = "durable")]
    async fn cancel_durable_execution(
        &self,
        owner: &crate::DurableOwnedExecution,
        execution_id: ProtocolIdentity,
        reason: CancellationReason,
    ) -> crate::DurableCancelExecutionResult {
        let result = owner.cancel_execution(execution_id, reason).await;
        match result {
            crate::DurableCancelExecutionResult::Accepted {
                effective_reason, ..
            } => match owner
                .drain_event_obligations(
                    &self.inner.allocator,
                    self.inner.configuration.identity_source(),
                    self.inner.event_delivery_runtime.as_ref(),
                )
                .await
            {
                Ok(terminal) => crate::DurableCancelExecutionResult::Accepted {
                    effective_reason,
                    terminal: Box::new(terminal),
                },
                Err(failure) => crate::DurableCancelExecutionResult::Failed {
                    effective_reason: Some(effective_reason),
                    failure,
                    observation: Box::new(owner.observation()),
                },
            },
            crate::DurableCancelExecutionResult::AlreadyTerminal(_) => match owner
                .drain_event_obligations(
                    &self.inner.allocator,
                    self.inner.configuration.identity_source(),
                    self.inner.event_delivery_runtime.as_ref(),
                )
                .await
            {
                Ok(terminal) => {
                    crate::DurableCancelExecutionResult::AlreadyTerminal(Box::new(terminal))
                }
                Err(failure) => crate::DurableCancelExecutionResult::Failed {
                    effective_reason: owner.observation().cancellation,
                    failure,
                    observation: Box::new(owner.observation()),
                },
            },
            result => result,
        }
    }

    #[cfg(feature = "durable")]
    fn mark_durable_execution(&self, execution_id: ProtocolIdentity) {
        self.inner.durable_executions.mark(execution_id);
    }

    #[cfg(feature = "durable")]
    fn register_durable_execution(&self, owner: Arc<crate::DurableOwnedExecution>) {
        self.inner.durable_executions.publish(owner);
    }

    #[cfg(feature = "durable")]
    fn abandon_durable_execution(&self, execution_id: ProtocolIdentity) {
        self.inner.durable_executions.abandon(execution_id);
    }

    #[cfg(feature = "durable")]
    async fn durable_execution(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Option<Arc<crate::DurableOwnedExecution>> {
        self.inner.durable_executions.owner(execution_id).await
    }

    /// Starts or joins the caller-independent shutdown coordinator.
    ///
    /// Once this future is first polled, dropping it stops only this caller's
    /// observation. The unique coordinator remains supervised until physical
    /// completion, and every caller observes the same immutable result. It
    /// rejects new work, cancels and drains owned execution cohorts, accounts
    /// for submitted physical tasks and finite delivery/blocking ownership, and
    /// uses reserved control-plane capacity. Await this orderly path before
    /// dropping the embedder-owned executor runtime.
    pub async fn shutdown(&self) -> Result<Arc<ShutdownReport>, ShutdownError> {
        if self
            .inner
            .shutdown_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.start_owned_shutdown();
        }
        std::future::poll_fn(|context| self.inner.shutdown.poll(context)).await
    }

    fn start_owned_shutdown(&self) {
        let Some(retained_admission) = self.inner.shutdown.claim_launch() else {
            return;
        };
        let mut admission = match retained_admission {
            Some(admission) => admission,
            None => match self.inner.lifecycle.begin_shutdown(None, None) {
                Ok(admission) => admission,
                Err(error) => {
                    self.inner
                        .shutdown
                        .publish(Err(ShutdownError::Lifecycle(error)));
                    return;
                }
            },
        };
        if self
            .inner
            .nondurable_executions
            .cancellation_control_is_active()
        {
            self.inner.shutdown.defer_launch(admission);
            return;
        }
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve_control_plane() {
            Ok(reservation) => reservation,
            Err(error) => {
                if self
                    .inner
                    .nondurable_executions
                    .cancellation_control_is_active()
                {
                    self.inner.shutdown.defer_launch(admission);
                    return;
                }
                self.inner.lifecycle.fail_owned_shutdown();
                self.inner
                    .shutdown
                    .publish(Err(ShutdownError::Admission(error)));
                return;
            }
        };
        let durations = admission.durations;
        let completion_state = Arc::clone(&self.inner.shutdown);
        let completion_lifecycle = self.inner.lifecycle.clone();
        let completion: PhysicalCompletionHandler = Arc::new(move |completion| {
            if !matches!(completion, OwnedTaskCompletion::Completed(_)) {
                completion_lifecycle.fail_owned_shutdown();
            }
            completion_state.publish_physical(completion);
        });
        let registration = supervisor.prepare_with_completion(
            SupervisedTaskDomain::Shutdown,
            None,
            Some(completion),
        );
        let signal = registration.signal();
        let shutdown_supervisor = supervisor.clone();
        let shutdown_owner = Arc::clone(&self.inner);
        let task: OwnedTaskFuture = if let Some(coordinator) = admission.coordinator.take() {
            let executions_at_start = coordinator.initial_executions();
            let tasks_at_start = usize_to_u64(executions_at_start.len());
            Box::pin(async move {
                let mut orderly = true;
                let executor = shutdown_owner.configuration.executor();
                let mut retained_cancellations = Vec::new();
                coordinator.wait_for_admission_handoffs().await;
                let handoff_cohort = coordinator.cohort_executions();
                let grace = shutdown_grace_race(
                    executor,
                    coordinator.wait_for_quiescence(),
                    &shutdown_owner.nondurable_executions,
                    &handoff_cohort,
                    durations.graceful,
                )
                .await;
                orderly &= !matches!(grace, DeadlineOutcome::Failed(_));
                let mut aborts = Arc::from([]);
                if !matches!(grace, DeadlineOutcome::Completed(())) {
                    let mut cancellation_executions = coordinator.pending_executions().to_vec();
                    cancellation_executions.extend(
                        shutdown_owner
                            .nondurable_executions
                            .requested_executions(&handoff_cohort),
                    );
                    cancellation_executions.sort_unstable();
                    cancellation_executions.dedup();
                    retained_cancellations = cancellation_executions
                        .iter()
                        .copied()
                        .map(|execution_id| {
                            let cancellation_owner = Arc::clone(&shutdown_owner);
                            let committed = CancellationSignal::default();
                            let committed_by_task = committed.clone();
                            #[cfg(feature = "durable")]
                            let durable = cancellation_owner
                                .durable_executions
                                .contains(execution_id);
                            #[cfg(not(feature = "durable"))]
                            let durable = false;
                            let completion = Box::pin(async move {
                                #[cfg(feature = "durable")]
                                if durable {
                                    let owner = cancellation_owner
                                        .durable_executions
                                        .owner(execution_id)
                                        .await;
                                    if let Some(owner) = owner {
                                        let cancellation_signal = owner
                                            .execution_handle()
                                            .cancellation_signal()
                                            .ok();
                                        let reason = CancellationReason::new(
                                            CancellationReasonCategory::Shutdown,
                                            None,
                                            None,
                                            0,
                                        )
                                        .unwrap_or_else(|_| {
                                            unreachable!(
                                                "empty shutdown reason is always bounded"
                                            )
                                        });
                                        let interpreter = Interpreter {
                                            inner: cancellation_owner,
                                            external_owner: false,
                                        };
                                        let mut cancellation = Box::pin(
                                            interpreter.cancel_durable_execution(
                                                &owner,
                                                execution_id,
                                                reason,
                                            ),
                                        );
                                        let result = std::future::poll_fn(|context| {
                                            let result = cancellation.as_mut().poll(context);
                                            if cancellation_signal
                                                .as_ref()
                                                .is_some_and(CancellationToken::is_cancelled)
                                                || result.is_ready()
                                            {
                                                committed_by_task.cancel();
                                            }
                                            result
                                        })
                                        .await;
                                        return matches!(
                                            result,
                                            crate::DurableCancelExecutionResult::Accepted {
                                                ..
                                            } | crate::DurableCancelExecutionResult::AlreadyTerminal(
                                                _
                                            )
                                        );
                                    }
                                }
                                if let Some(owner) = cancellation_owner
                                    .nondurable_executions
                                    .owner(execution_id)
                                    .await
                                {
                                    let cancellation_signal = owner
                                        .handle
                                        .cancellation_signal()
                                        .ok();
                                    let reason = CancellationReason::new(
                                        CancellationReasonCategory::Shutdown,
                                        None,
                                        None,
                                        0,
                                    )
                                    .unwrap_or_else(|_| {
                                        unreachable!("empty shutdown reason is always bounded")
                                    });
                                    owner.cancellation.request(reason);
                                    let result = if owner.cancellation.claim() {
                                        let interpreter = Interpreter {
                                            inner: Arc::clone(&cancellation_owner),
                                            external_owner: false,
                                        };
                                        let result = interpreter
                                            .drive_nondurable_cancellation(&owner)
                                            .await;
                                        owner.cancellation.publish(result.clone());
                                        result
                                    } else {
                                        std::future::poll_fn(|context| {
                                            owner.cancellation.poll(context)
                                        })
                                        .await
                                    };
                                    if cancellation_signal
                                        .as_ref()
                                        .is_some_and(CancellationToken::is_cancelled)
                                        || result.is_ok()
                                    {
                                        committed_by_task.cancel();
                                    }
                                    return matches!(
                                        result,
                                        Ok(CancellationRecord::Accepted { .. }
                                            | CancellationRecord::Existing { .. }
                                            | CancellationRecord::AlreadyTerminal(_))
                                    );
                                }
                                let reason = CancellationReason::new(
                                    CancellationReasonCategory::Shutdown,
                                    None,
                                    None,
                                    0,
                                )
                                .unwrap_or_else(|_| {
                                    unreachable!("empty shutdown reason is always bounded")
                                });
                                let result = cancellation_owner
                                    .lifecycle
                                    .cancel_execution(execution_id, reason)
                                    .is_ok();
                                committed_by_task.cancel();
                                result
                            }) as HostFuture<'static, bool>;
                            ShutdownCancellation {
                                committed,
                                completion,
                                outcome: None,
                                commit_observation_required: true,
                            }
                        })
                        .collect::<Vec<_>>();
                    let commits = deadline_race(
                        executor,
                        Box::pin(wait_for_shutdown_cancellation_commits(
                            &mut retained_cancellations,
                        )),
                        durations.drain,
                        None,
                    )
                    .await;
                    if matches!(commits, DeadlineOutcome::Completed(())) {
                        let drain = deadline_race(
                            executor,
                            Box::pin(wait_for_shutdown_cancellations(
                                &mut retained_cancellations,
                                coordinator.wait_for_quiescence(),
                            )),
                            durations.drain,
                            None,
                        )
                        .await;
                        if let DeadlineOutcome::Completed(cancellations_orderly) = drain {
                            orderly &= cancellations_orderly;
                        } else {
                            orderly &= !matches!(drain, DeadlineOutcome::Failed(_));
                            aborts = shutdown_supervisor.request_abort_shutdown_work();
                            let completion = deadline_race(
                                executor,
                                Box::pin(coordinator.wait_for_quiescence()),
                                durations.drain,
                                None,
                            )
                            .await;
                            orderly &= matches!(completion, DeadlineOutcome::Completed(()));
                        }
                    } else {
                        orderly = false;
                        aborts = shutdown_supervisor.request_abort_shutdown_work();
                        let completion = deadline_race(
                            executor,
                            Box::pin(coordinator.wait_for_quiescence()),
                            durations.drain,
                            None,
                        )
                        .await;
                        orderly &= matches!(completion, DeadlineOutcome::Completed(()));
                    }
                }
                let mut confirmed_abort_ids = aborts
                    .iter()
                    .filter(|task| task.snapshot().abort_result == Some(OwnedTaskAbort::Stopped))
                    .map(SupervisedTask::id)
                    .collect::<BTreeSet<_>>();
                confirmed_abort_ids.extend(
                    shutdown_owner
                        .nondurable_executions
                        .confirmed_stopped_abort_ids(&handoff_cohort),
                );
                let aborted = usize_to_u64(confirmed_abort_ids.len());
                let mut blocking_shutdown =
                    catch_integration(&shutdown_owner.blocking_work_poison, || {
                        shutdown_owner.configuration.blocking_work().shutdown()
                    })
                    .ok()
                    .map(|shutdown| {
                        contain_integration_future(
                            shutdown,
                            shutdown_owner.blocking_work_poison.clone(),
                        )
                    });
                let mut retain_blocking_shutdown = false;
                let blocking_settled = if let Some(shutdown) = blocking_shutdown.as_mut() {
                    match observe_shutdown_deadline(executor, shutdown.as_mut(), durations.drain)
                        .await
                    {
                        DeadlineOutcome::Completed(result) => {
                            result.is_ok_and(|result| result.is_ok())
                        }
                        DeadlineOutcome::Cancelled
                        | DeadlineOutcome::TimedOut
                        | DeadlineOutcome::Failed(_) => {
                            retain_blocking_shutdown = true;
                            false
                        }
                    }
                } else {
                    false
                };
                if !blocking_settled {
                    orderly = false;
                }
                let cohort = coordinator.cohort_executions();
                #[cfg(feature = "durable")]
                let mut journal_owner_releases = Vec::new();
                #[cfg(not(feature = "durable"))]
                let journal_owner_releases = Vec::new();
                #[cfg(feature = "durable")]
                let mut retained_owner_releases = Vec::new();
                #[cfg(feature = "durable")]
                for owner in shutdown_owner.durable_executions.all_owned() {
                    let execution_id = owner.execution_id();
                    let mut release =
                        Box::pin(async move { owner.release_owner_for_shutdown().await });
                    let status = match observe_shutdown_deadline(
                        executor,
                        release.as_mut(),
                        durations.drain,
                    )
                    .await
                    {
                        DeadlineOutcome::Completed(observation) => match observation.owner {
                            Some(crate::DurableJournalOwnerState::Released) => {
                                ShutdownJournalOwnerReleaseStatus::Released
                            }
                            Some(crate::DurableJournalOwnerState::ReleaseFailed(error)) => {
                                ShutdownJournalOwnerReleaseStatus::ReleaseFailed(error)
                            }
                            Some(crate::DurableJournalOwnerState::Held) | None => {
                                ShutdownJournalOwnerReleaseStatus::HeldNotSafe
                            }
                        },
                        DeadlineOutcome::Cancelled => unreachable!(
                            "shutdown owner-release observation has no cancellation signal"
                        ),
                        DeadlineOutcome::TimedOut => {
                            retained_owner_releases.push(release);
                            ShutdownJournalOwnerReleaseStatus::TimedOut
                        }
                        DeadlineOutcome::Failed(error) => {
                            retained_owner_releases.push(release);
                            ShutdownJournalOwnerReleaseStatus::ExecutorFailed(error)
                        }
                    };
                    let released = status == ShutdownJournalOwnerReleaseStatus::Released;
                    orderly &= released;
                    journal_owner_releases.push(ShutdownJournalOwnerRelease {
                        execution_id,
                        status,
                    });
                }
                let final_event = settle_final_shutdown_event(
                    &shutdown_owner,
                    durations,
                    &executions_at_start,
                    &cohort,
                    tasks_at_start,
                    aborted,
                )
                .await;
                orderly &= final_event.required_sinks_settled;
                let result = coordinator
                    .complete(
                        orderly,
                        final_event.settlement,
                        Arc::from(journal_owner_releases),
                    )
                    .map_err(ShutdownError::Completion);
                #[cfg(feature = "durable")]
                shutdown_owner.durable_executions.fence_root_submission();
                shutdown_owner.shutdown.publish(result);
                let _ = signal.settle();
                #[cfg(feature = "durable")]
                for release in retained_owner_releases {
                    let _ = release.await;
                }
                wait_for_retained_shutdown_cancellations(&mut retained_cancellations).await;
                if retain_blocking_shutdown && let Some(shutdown) = blocking_shutdown {
                    let _ = shutdown.await;
                }
                OwnedTaskResult::new()
            })
        } else {
            Box::pin(async move {
                let report = admission.wait.await;
                shutdown_owner.shutdown.stage(Ok(report));
                signal.settle();
                OwnedTaskResult::new()
            })
        };
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => {
                self.inner.shutdown.mark_submitted();
                task.relinquish();
            }
            Err(error) => {
                self.inner.lifecycle.fail_owned_shutdown();
                self.inner
                    .shutdown
                    .publish(Err(ShutdownError::Executor(error)));
            }
        }
    }

    async fn drive_action_operation(
        &self,
        accepted: &StartExecutionAccepted,
        analysis: &gantry_analysis::TypedPackage,
        machine: &mut Machine,
        hook: &mut TaskHook<'_>,
        cancellation: &dyn CancellationToken,
        occurrence: &gantry_runtime::OperationOccurrence,
    ) -> Result<(), RunExecutionError> {
        let metadata = occurrence
            .metadata
            .as_ref()
            .ok_or(RunExecutionError::MissingOperationMetadata)?;
        let action = metadata
            .action
            .as_ref()
            .ok_or(RunExecutionError::MissingOperationMetadata)?;
        if action.parameters.len() != occurrence.inputs.len() {
            return Err(RunExecutionError::MissingOperationMetadata);
        }
        let expected_schema = analysis
            .schemas()
            .and_then(|schemas| {
                schemas
                    .entries()
                    .iter()
                    .find(|(ty, _)| ty == &metadata.result_type)
                    .map(|(_, schema)| Arc::clone(schema))
            })
            .ok_or(RunExecutionError::MissingOperationSchema)?;
        let mapping_revision = accepted
            .mapping_revisions
            .action
            .clone()
            .ok_or(RunExecutionError::MissingActionMappingRevision)?;
        let captured = CapturedOperationRequestV1::Action {
            header: OperationRequestHeaderV1 {
                execution_id: accepted.execution_id,
                task_id: occurrence.task_id,
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self
                    .inner
                    .configuration
                    .required()
                    .maximum_hook_output_bytes,
                value_limits: self.inner.configuration.required().value_limits,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: ActionOperationRequestV1 {
                path: action.path.clone(),
                signature: action.signature.clone(),
                recovery: action.recovery,
                mapping_revision,
                arguments: action
                    .parameters
                    .iter()
                    .zip(occurrence.inputs.iter())
                    .map(|(parameter, value)| TypedActionArgumentV1 {
                        name: Arc::from(parameter.name()),
                        ty: parameter.ty().clone(),
                        value: value.canonical_json(),
                    })
                    .collect(),
            },
        };
        let mut operation =
            OperationLifecycle::new(captured).map_err(RunExecutionError::OperationLifecycle)?;
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            self.inner.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| RunExecutionError::RetryPolicy)?;
        operation
            .prepare(
                &self.inner.allocator,
                self.inner.configuration.identity_source(),
                0,
                0,
                &[],
            )
            .map_err(RunExecutionError::OperationLifecycle)?;
        loop {
            if let Err(error) = operation.dispatch(hook, cancellation).await {
                if error == OperationLifecycleError::Cancelled {
                    return Ok(());
                }
                let category = if hook.is_ready() {
                    RuntimeErrorCategory::HookFailure
                } else {
                    RuntimeErrorCategory::HookCreation
                };
                machine
                    .fail_operation(occurrence.identity, category)
                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                return match error {
                    OperationLifecycleError::Hook(_) => Ok(()),
                    other => Err(RunExecutionError::OperationLifecycle(other)),
                };
            }
            match operation
                .process_outcome(policy, self.inner.configuration.executor(), cancellation)
                .map_err(RunExecutionError::OperationLifecycle)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let value = decode_logical_value(
                        output.canonical_json().bytes(),
                        &metadata.result_type,
                        self.inner.configuration.required().value_limits,
                        analysis.declared_value_shapes(),
                    )?;
                    if metadata.attempted {
                        operation.accept_attempt(machine, value)
                    } else {
                        operation.accept(machine, value)
                    }
                    .map_err(RunExecutionError::OperationLifecycle)?;
                    return Ok(());
                }
                ProcessedHookOutcomeV1::Retry(_) => {
                    if operation
                        .prepare_after_retry_wait(
                            self.inner.configuration.executor(),
                            &accepted
                                .handle
                                .cancellation_signal()
                                .map_err(|_| RunExecutionError::LifecycleTransition)?,
                            &self.inner.allocator,
                            self.inner.configuration.identity_source(),
                        )
                        .await
                        .map_err(RunExecutionError::OperationLifecycle)?
                        .is_none()
                    {
                        Self::settle_retry_terminal(machine, occurrence, &operation)?;
                        return Ok(());
                    }
                }
                ProcessedHookOutcomeV1::Failed(failure) => {
                    if metadata.attempted
                        && matches!(
                            operation.lifecycle_failure(),
                            Some(OperationLifecycleFailureV1::Operation(_))
                        )
                    {
                        operation
                            .accept_attempt_failure(machine)
                            .map_err(RunExecutionError::OperationLifecycle)?;
                    } else {
                        machine
                            .fail_operation(occurrence.identity, failure.runtime_category())
                            .map_err(|_| RunExecutionError::LifecycleTransition)?;
                    }
                    return Ok(());
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn drive_model_operation(
        &self,
        accepted: &StartExecutionAccepted,
        analysis: &gantry_analysis::TypedPackage,
        machine: &mut Machine,
        hook: &mut TaskHook<'_>,
        cancellation: &dyn CancellationToken,
        occurrence: &gantry_runtime::OperationOccurrence,
        coordinator: &ExecutionCoordinator,
        establisher: &SessionEstablisher,
        session_occurrence: u64,
    ) -> Result<(), RunExecutionError> {
        let metadata = occurrence
            .metadata
            .as_ref()
            .ok_or(RunExecutionError::MissingOperationMetadata)?;
        let interpolation_count = metadata.interpolation_types.len();
        if metadata.named_input_names.len() != metadata.named_input_types.len()
            || occurrence.inputs.len()
                != interpolation_count.saturating_add(metadata.named_input_types.len())
        {
            return Err(RunExecutionError::MissingOperationMetadata);
        }
        let expected_schema = analysis
            .schemas()
            .and_then(|schemas| {
                schemas
                    .entries()
                    .iter()
                    .find(|(ty, _)| ty == &metadata.result_type)
                    .map(|(_, schema)| Arc::clone(schema))
            })
            .ok_or(RunExecutionError::MissingOperationSchema)?;
        let selected_agent = occurrence
            .active_agent
            .clone()
            .ok_or(RunExecutionError::MissingActiveAgent)?;
        let mapping_revision = accepted
            .mapping_revisions
            .agent
            .clone()
            .ok_or(RunExecutionError::MissingAgentMappingRevision)?;
        let parent_session_id = occurrence
            .active_session
            .ok_or(RunExecutionError::MissingLogicalSession)?;
        let task_id = occurrence.task_id;
        let active_session_id = if let Some(mode) = metadata.session_mode.as_deref() {
            let mode = match mode {
                "fork" => SessionCreationModeV1::Fork,
                "new" => SessionCreationModeV1::New,
                _ => return Err(RunExecutionError::MissingOperationMetadata),
            };
            coordinator
                .create_session(
                    parent_session_id,
                    task_id,
                    occurrence.site.clone(),
                    session_occurrence,
                    mode,
                    SessionEstablishmentV1::OperationRequest,
                )
                .map_err(RunExecutionError::Session)?
                .id
        } else {
            parent_session_id
        };
        let session = coordinator
            .session(active_session_id)
            .ok_or(RunExecutionError::MissingLogicalSession)?;
        let interpolation_inputs = metadata
            .interpolation_types
            .iter()
            .zip(occurrence.inputs.iter().take(interpolation_count))
            .enumerate()
            .map(|(position, (ty, value))| {
                Ok(InterpolationInputV1 {
                    position: u64::try_from(position)
                        .map_err(|_| RunExecutionError::MissingOperationMetadata)?,
                    ty: ty.clone(),
                    value: value.canonical_json(),
                })
            })
            .collect::<Result<Vec<_>, RunExecutionError>>()?;
        let named_inputs = metadata
            .named_input_names
            .iter()
            .zip(&metadata.named_input_types)
            .zip(occurrence.inputs.iter().skip(interpolation_count))
            .map(|((name, ty), value)| NamedInputV1 {
                name: Arc::clone(name),
                ty: ty.clone(),
                value: value.canonical_json(),
            })
            .collect::<Vec<_>>();
        let rendered_prompt = match render_prompt(
            &metadata.template_segments,
            occurrence.inputs.iter().take(interpolation_count),
            self.inner
                .configuration
                .required()
                .value_limits
                .maximum_string_scalars(),
        ) {
            Ok(prompt) => prompt,
            Err(RenderPromptError::Limit) => {
                machine
                    .fail_operation_with_code(
                        occurrence.identity,
                        RuntimeCode::Deterministic(DeterministicEvaluationCode::StringSizeLimit),
                    )
                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                return Ok(());
            }
            Err(RenderPromptError::Shape) => {
                return Err(RunExecutionError::MissingOperationMetadata);
            }
        };
        let session_use = if let Some(mode) = metadata.session_mode.as_ref() {
            ModelSessionUseV1::Create {
                mode: Arc::clone(mode),
                session_id: session.id,
                parent_session_id,
                root_session_id: session.root,
                provenance: Arc::from("operation-request"),
            }
        } else {
            ModelSessionUseV1::Inline
        };
        let captured = CapturedOperationRequestV1::Model {
            header: OperationRequestHeaderV1 {
                execution_id: accepted.execution_id,
                task_id,
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self
                    .inner
                    .configuration
                    .required()
                    .maximum_hook_output_bytes,
                value_limits: self.inner.configuration.required().value_limits,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: Box::new(ModelOperationRequestV1 {
                selected_agent: Arc::clone(&selected_agent),
                mapping_revision,
                template_segments: metadata.template_segments.clone(),
                rendered_prompt: Arc::clone(&rendered_prompt),
                interpolation_inputs: interpolation_inputs.clone(),
                named_inputs: named_inputs.clone(),
                transcript: session.transcript.clone(),
                active_session_id: session.id,
                parent_session_id: session.parent,
                root_session_id: session.root,
                session_use,
            }),
        };
        let mut operation =
            OperationLifecycle::new(captured).map_err(RunExecutionError::OperationLifecycle)?;
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            self.inner.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| RunExecutionError::RetryPolicy)?;
        operation
            .prepare(
                &self.inner.allocator,
                self.inner.configuration.identity_source(),
                0,
                0,
                &[],
            )
            .map_err(RunExecutionError::OperationLifecycle)?;
        loop {
            if let Err(error) = operation
                .dispatch_model(
                    hook,
                    cancellation,
                    establisher,
                    accepted.execution_id,
                    &session,
                )
                .await
            {
                let category = match error {
                    OperationLifecycleError::Cancelled => return Ok(()),
                    OperationLifecycleError::Session(_) => {
                        RuntimeErrorCategory::LogicalSessionSetup
                    }
                    OperationLifecycleError::Hook(_) if hook.is_ready() => {
                        RuntimeErrorCategory::HookFailure
                    }
                    OperationLifecycleError::Hook(_) => RuntimeErrorCategory::HookCreation,
                    other => return Err(RunExecutionError::OperationLifecycle(other)),
                };
                machine
                    .fail_operation(occurrence.identity, category)
                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                return Ok(());
            }
            match operation
                .process_outcome(policy, self.inner.configuration.executor(), cancellation)
                .map_err(RunExecutionError::OperationLifecycle)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let value = decode_logical_value(
                        output.canonical_json().bytes(),
                        &metadata.result_type,
                        self.inner.configuration.required().value_limits,
                        analysis.declared_value_shapes(),
                    )?;
                    let turn = TranscriptTurnV1 {
                        operation_kind: metadata.kind,
                        template_representation: metadata.template_segments.clone(),
                        rendered_prompt: Arc::clone(&rendered_prompt),
                        interpolation_inputs: interpolation_inputs.clone(),
                        using_inputs: named_inputs.clone(),
                        selected_agent: Arc::clone(&selected_agent),
                        accepted_result: AcceptedTranscriptResultV1 {
                            kind: transcript_result_kind(&metadata.result_type),
                            ty: metadata.result_type.clone(),
                            value: value.canonical_json(),
                        },
                    };
                    let accepted_result = coordinator
                        .with_session_mut(active_session_id, |session| {
                            if metadata.attempted {
                                operation.accept_model_attempt(
                                    machine,
                                    session,
                                    &turn,
                                    self.inner.configuration.required().value_limits,
                                    value,
                                )
                            } else {
                                operation.accept_model(
                                    machine,
                                    session,
                                    &turn,
                                    self.inner.configuration.required().value_limits,
                                    value,
                                )
                            }
                        })
                        .map_err(RunExecutionError::Session)?;
                    match accepted_result {
                        Ok(_) => return Ok(()),
                        Err(OperationLifecycleError::Transcript(
                            gantry_runtime::TranscriptError::Limit,
                        )) => {
                            machine
                                .fail_operation(
                                    occurrence.identity,
                                    RuntimeErrorCategory::LogicalSessionTranscriptLimit,
                                )
                                .map_err(|_| RunExecutionError::LifecycleTransition)?;
                            return Ok(());
                        }
                        Err(error) => return Err(RunExecutionError::OperationLifecycle(error)),
                    }
                }
                ProcessedHookOutcomeV1::Retry(_) => {
                    if operation
                        .prepare_after_retry_wait(
                            self.inner.configuration.executor(),
                            &accepted
                                .handle
                                .cancellation_signal()
                                .map_err(|_| RunExecutionError::LifecycleTransition)?,
                            &self.inner.allocator,
                            self.inner.configuration.identity_source(),
                        )
                        .await
                        .map_err(RunExecutionError::OperationLifecycle)?
                        .is_none()
                    {
                        Self::settle_retry_terminal(machine, occurrence, &operation)?;
                        return Ok(());
                    }
                }
                ProcessedHookOutcomeV1::Failed(failure) => {
                    if metadata.attempted
                        && matches!(
                            operation.lifecycle_failure(),
                            Some(OperationLifecycleFailureV1::Operation(_))
                        )
                    {
                        operation
                            .accept_attempt_failure(machine)
                            .map_err(RunExecutionError::OperationLifecycle)?;
                    } else {
                        machine
                            .fail_operation(occurrence.identity, failure.runtime_category())
                            .map_err(|_| RunExecutionError::LifecycleTransition)?;
                    }
                    return Ok(());
                }
            }
        }
    }

    fn settle_retry_terminal(
        machine: &mut Machine,
        occurrence: &gantry_runtime::OperationOccurrence,
        operation: &OperationLifecycle,
    ) -> Result<(), RunExecutionError> {
        match operation.lifecycle_failure() {
            Some(OperationLifecycleFailureV1::Operation(
                gantry_runtime::OperationFailureV1::TaskCancellation,
            )) => Ok(()),
            Some(OperationLifecycleFailureV1::Operation(failure)) => {
                machine
                    .fail_operation(occurrence.identity, failure.runtime_category())
                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                Ok(())
            }
            _ => Err(RunExecutionError::LifecycleTransition),
        }
    }

    fn fix_failed_execution(
        &self,
        accepted: &StartExecutionAccepted,
        failure: MachineFailure,
    ) -> Result<(), RunExecutionError> {
        let outcome = MachineOutcome::Failed(failure);
        self.inner
            .lifecycle
            .complete_foreground(&accepted.handle, outcome.clone())
            .map_err(|_| RunExecutionError::LifecycleTransition)?;
        self.inner
            .lifecycle
            .complete_terminal(&accepted.handle, outcome)
            .map_err(|_| RunExecutionError::LifecycleTransition)
    }

    fn settle_unhandled_driver_failure(
        &self,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        handle: &ExecutionHandle,
        workflow: gantry_ir::CanonicalPath,
        error: &RunExecutionError,
    ) -> Result<(), RunExecutionError> {
        let fallback = MachineOutcome::Failed(MachineFailure {
            code: if matches!(error, RunExecutionError::ExecutorFailure) {
                RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure)
            } else {
                RuntimeCode::InternalInvariant
            },
            workflow,
            site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
                .map_err(|_| RunExecutionError::LifecycleTransition)?,
            #[cfg(feature = "concurrent")]
            join_failure: None,
        });
        self.settle_driver_failure(coordinator, task_id, handle, fallback)
    }

    #[cfg(feature = "concurrent")]
    fn settle_child_driver_failure(
        &self,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        fallback: MachineOutcome,
    ) -> Result<(), RunExecutionError> {
        coordinator
            .settle_after_driver_failure(task_id, fallback)
            .map_err(RunExecutionError::TaskState)?;
        Ok(())
    }

    fn settle_driver_failure(
        &self,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        handle: &ExecutionHandle,
        fallback: MachineOutcome,
    ) -> Result<(), RunExecutionError> {
        coordinator
            .settle_after_driver_failure(task_id, fallback)
            .map_err(RunExecutionError::TaskState)?;
        let outcome = coordinator
            .snapshot()
            .state()
            .root_settled_outcome()
            .cloned()
            .ok_or(RunExecutionError::LifecycleTransition)?;
        self.complete_nondurable_execution_if_ready(coordinator, handle, outcome)
    }

    fn complete_nondurable_execution_if_ready(
        &self,
        coordinator: &ExecutionCoordinator,
        handle: &ExecutionHandle,
        outcome: MachineOutcome,
    ) -> Result<(), RunExecutionError> {
        let coordinated = coordinator.snapshot();
        if coordinated.state().foreground_outcome().is_none() {
            let published = match coordinator.complete_foreground() {
                Ok(published) => published,
                Err(TaskStateError::AttachedTasksPending) => return Ok(()),
                Err(error) => return Err(RunExecutionError::TaskState(error)),
            };
            if published != outcome {
                return Err(RunExecutionError::LifecycleTransition);
            }
        } else if coordinated.state().foreground_outcome() != Some(&outcome) {
            return Err(RunExecutionError::LifecycleTransition);
        }

        let execution = self
            .inner
            .lifecycle
            .query_execution(handle.execution_id())
            .map_err(RunExecutionError::Lifecycle)?
            .ok_or(RunExecutionError::ExecutionNotFound)?;
        if execution.foreground.is_none() {
            self.inner
                .lifecycle
                .complete_foreground(handle, outcome.clone())
                .map_err(|_| RunExecutionError::LifecycleTransition)?;
        } else if execution.foreground.as_ref() != Some(&outcome) {
            return Err(RunExecutionError::LifecycleTransition);
        }
        let terminal =
            if let Some(terminal) = coordinator.snapshot().state().terminal_outcome().cloned() {
                terminal
            } else {
                match coordinator.complete_terminal() {
                    Ok(terminal) => terminal,
                    Err(TaskStateError::DetachedTasksPending) => return Ok(()),
                    Err(error) => return Err(RunExecutionError::TaskState(error)),
                }
            };
        let execution = self
            .inner
            .lifecycle
            .query_execution(handle.execution_id())
            .map_err(RunExecutionError::Lifecycle)?
            .ok_or(RunExecutionError::ExecutionNotFound)?;
        if execution.terminal.is_none() {
            self.inner
                .lifecycle
                .complete_terminal(handle, terminal)
                .map_err(|_| RunExecutionError::LifecycleTransition)?;
        }
        Ok(())
    }
}

/// One interpreter-owned `Send + 'static` asynchronous driver for a Gantry task.
struct TaskDriver {
    coordinator: ExecutionCoordinator,
    failure_context: TaskDriverFailureContext,
    future: Pin<Box<dyn Future<Output = Result<(), RunExecutionError>> + Send + 'static>>,
}

#[derive(Clone)]
struct TaskDriverFailureContext {
    inner: Arc<InterpreterInner>,
    coordinator: ExecutionCoordinator,
    task_id: ProtocolIdentity,
    handle: ExecutionHandle,
    workflow: gantry_ir::CanonicalPath,
    execution_foreground: bool,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    durable_graph: Option<Arc<SharedDurableMachineGraph>>,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    durable_owner: Option<Arc<crate::DurableOwnedExecution>>,
}

impl TaskDriverFailureContext {
    fn settle(&self, completion: &OwnedTaskCompletion) {
        let code = match completion {
            OwnedTaskCompletion::Panicked {
                origin: gantry_host::contracts::OwnedTaskPanicOrigin::Integration,
                ..
            } => RuntimeCode::IntegrationPanic,
            OwnedTaskCompletion::Panicked {
                origin: gantry_host::contracts::OwnedTaskPanicOrigin::GantryInvariant,
                ..
            } => RuntimeCode::InternalInvariant,
            OwnedTaskCompletion::Stopped | OwnedTaskCompletion::Failed(_) => {
                RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure)
            }
            OwnedTaskCompletion::Completed(_) => return,
        };
        let interpreter = Interpreter {
            inner: Arc::clone(&self.inner),
            external_owner: false,
        };
        let fallback = MachineOutcome::Failed(MachineFailure {
            code,
            workflow: self.workflow.clone(),
            site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
                .unwrap_or_else(|_| unreachable!("constant position is valid")),
            #[cfg(feature = "concurrent")]
            join_failure: None,
        });
        #[cfg(all(feature = "concurrent", feature = "durable"))]
        if let (Some(graph), Some(owner)) = (&self.durable_graph, &self.durable_owner) {
            if matches!(
                completion,
                OwnedTaskCompletion::Panicked {
                    origin: gantry_host::contracts::OwnedTaskPanicOrigin::GantryInvariant,
                    ..
                }
            ) {
                graph.require_failure_finalization(DurableRunFailure::Internal);
            } else {
                graph.request_abnormal_child_settlement(self.task_id, fallback);
            }
            let _ = interpreter.start_durable_graph_finalizer(
                Arc::clone(graph),
                Arc::clone(owner),
                self.coordinator.clone(),
                Arc::clone(&graph.program),
                graph.operations.clone(),
            );
            return;
        }
        if self.execution_foreground {
            let _ = interpreter.settle_driver_failure(
                &self.coordinator,
                self.task_id,
                &self.handle,
                fallback.clone(),
            );
        }
        #[cfg(feature = "concurrent")]
        if !self.execution_foreground {
            let _ = self
                .coordinator
                .settle_after_driver_failure(self.task_id, fallback);
        }
    }

    fn physical_completion(&self) {
        let _ = self
            .coordinator
            .mark_driver_physically_settled(self.task_id);
        #[cfg(all(feature = "concurrent", feature = "durable"))]
        if self.durable_graph.is_some() {
            return;
        }
        let snapshot = self.coordinator.snapshot();
        let state = snapshot.state();
        let root_task_id = state.root_task_id();
        let Some(root) = state.task_record(root_task_id) else {
            return;
        };
        if root.driver_ownership() != gantry_runtime::TaskDriverOwnershipV1::PhysicallySettled {
            return;
        }
        let Some(outcome) = state.root_settled_outcome().cloned() else {
            return;
        };
        drop(snapshot);
        let interpreter = Interpreter {
            inner: Arc::clone(&self.inner),
            external_owner: false,
        };
        let _ = interpreter.complete_nondurable_execution_if_ready(
            &self.coordinator,
            &self.handle,
            outcome,
        );
    }
}

impl TaskDriver {
    fn from_prepared(
        inner: Arc<InterpreterInner>,
        accepted: StartExecutionAccepted,
        prepared: PreparedRootDriver,
    ) -> Self {
        let task_id = prepared.task_id;
        let coordinator = prepared.coordinator.clone();
        let failure_coordinator = coordinator.clone();
        let handle = accepted.handle.clone();
        let workflow = prepared.workflow.clone();
        let failure_context = TaskDriverFailureContext {
            inner: Arc::clone(&inner),
            coordinator: coordinator.clone(),
            task_id,
            handle: handle.clone(),
            workflow: workflow.clone(),
            execution_foreground: true,
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            durable_graph: None,
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            durable_owner: None,
        };
        let future = Box::pin(async move {
            let interpreter = Interpreter {
                inner,
                external_owner: false,
            };
            let result = interpreter.drive_execution(accepted, prepared).await;
            if let Err(error) = result {
                interpreter.settle_unhandled_driver_failure(
                    &failure_coordinator,
                    task_id,
                    &handle,
                    workflow,
                    &error,
                )?;
                Err(error)
            } else {
                Ok(())
            }
        });
        Self {
            coordinator,
            failure_context,
            future,
        }
    }

    #[cfg(feature = "concurrent")]
    fn from_child(
        inner: Arc<InterpreterInner>,
        accepted: StartExecutionAccepted,
        prepared: PreparedTaskDriver,
    ) -> Self {
        let task_id = prepared.task_id;
        let coordinator = prepared.coordinator.clone();
        let failure_coordinator = coordinator.clone();
        let handle = accepted.handle.clone();
        let workflow = prepared.workflow.clone();
        let failure_context = TaskDriverFailureContext {
            inner: Arc::clone(&inner),
            coordinator: coordinator.clone(),
            task_id,
            handle,
            workflow: workflow.clone(),
            execution_foreground: false,
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            durable_graph: None,
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            durable_owner: None,
        };
        let future = Box::pin(async move {
            let interpreter = Interpreter {
                inner,
                external_owner: false,
            };
            match interpreter.drive_task(accepted, prepared, false).await {
                Ok(_) => Ok(()),
                Err(error) => {
                    let fallback = MachineOutcome::Failed(MachineFailure {
                        code: RuntimeCode::InternalInvariant,
                        workflow,
                        site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
                            .map_err(|_| RunExecutionError::LifecycleTransition)?,
                        #[cfg(feature = "concurrent")]
                        join_failure: None,
                    });
                    interpreter.settle_child_driver_failure(
                        &failure_coordinator,
                        task_id,
                        fallback,
                    )?;
                    Err(error)
                }
            }
        });
        Self {
            coordinator,
            failure_context,
            future,
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    fn from_durable_graph_child(
        inner: Arc<InterpreterInner>,
        coordinator: ExecutionCoordinator,
        task_id: ProtocolIdentity,
        workflow: gantry_ir::CanonicalPath,
        graph: Arc<SharedDurableMachineGraph>,
        owner: Arc<crate::DurableOwnedExecution>,
        future: Pin<Box<dyn Future<Output = Result<(), RunExecutionError>> + Send + 'static>>,
    ) -> Self {
        let failure_context = TaskDriverFailureContext {
            inner,
            coordinator: coordinator.clone(),
            task_id,
            handle: owner.execution_handle(),
            workflow,
            execution_foreground: false,
            durable_graph: Some(graph),
            durable_owner: Some(owner),
        };
        Self {
            coordinator,
            failure_context,
            future,
        }
    }

    /// Returns the shared semantic coordinator used by this driver.
    #[must_use]
    fn coordinator(&self) -> ExecutionCoordinator {
        self.coordinator.clone()
    }

    /// Returns the semantic fallback used when physical completion wins unexpectedly.
    #[must_use]
    fn abnormal_completion_handler(&self) -> AbnormalCompletionHandler {
        let context = self.failure_context.clone();
        Arc::new(move |completion| context.settle(&completion))
    }

    /// Returns the callback that releases process-local driver ownership exactly once.
    #[must_use]
    fn physical_completion_handler(&self) -> PhysicalCompletionHandler {
        let context = self.failure_context.clone();
        Arc::new(move |_| context.physical_completion())
    }

    fn into_gated_owned_task(
        self,
        signal: SupervisionSignal,
        gate: Arc<RootStartGate>,
    ) -> OwnedTaskFuture {
        Box::pin(async move {
            if gate.wait().await {
                let _ = self.await;
            }
            let _ = signal.settle();
            OwnedTaskResult::new()
        })
    }
}

impl Future for TaskDriver {
    type Output = Result<(), RunExecutionError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(context)
    }
}

#[cfg(feature = "concurrent")]
struct SubmittedChildRollbackFailure;

#[cfg(feature = "durable")]
async fn rollback_submitted_resume(
    task: SupervisedTask,
    gate: Arc<RootStartGate>,
    executor: &dyn ExecutorAdapter,
    timeout: DurationMicros,
) {
    gate.cancel();
    let _ = task.request_abort();
    let _ = deadline_race(executor, Box::pin(task.completion()), timeout, None).await;
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
async fn rollback_submitted_recovered_graph(
    tasks: Vec<(SupervisedTask, SupervisionSignal)>,
    gate: Arc<RootStartGate>,
    executor: &dyn ExecutorAdapter,
    timeout: DurationMicros,
) {
    gate.cancel();
    for (_, signal) in &tasks {
        let _ = signal.arm_completion_observation();
    }
    for (task, _) in &tasks {
        let _ = task.request_abort();
    }
    let _ = deadline_race(
        executor,
        Box::pin(async {
            for (task, _) in &tasks {
                let _ = task.completion().await;
            }
        }),
        timeout,
        None,
    )
    .await;
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
fn recovered_concurrent_task_drivers(
    admission: &gantry_runtime::RecoveredConcurrentDriverAdmissionV1,
    program: Arc<gantry_ir::MachineProgram>,
    machine_limits: gantry_runtime::MachineLimits,
) -> Result<Vec<RecoveredDurableTaskDriver>, &'static str> {
    let snapshot = admission.coordinator().snapshot();
    let root_task_id = snapshot.state().root_task_id();
    let root_session = snapshot
        .sessions()
        .iter()
        .find(|session| session.parent.is_none())
        .ok_or("missing-root-session")?;
    let root_provenance = match root_session.mode {
        SessionCreationModeV1::EmbedderRoot => RootSessionProvenanceV1::EmbedderSupplied,
        SessionCreationModeV1::GantryRoot => RootSessionProvenanceV1::GantryCreated,
        SessionCreationModeV1::New | SessionCreationModeV1::Fork => {
            return Err("invalid-root-session");
        }
    };
    admission
        .unfinished_task_ids()
        .iter()
        .map(|task_id| {
            let workflow = if *task_id == root_task_id {
                None
            } else {
                Some(
                    snapshot
                        .state()
                        .task(*task_id)
                        .ok_or("missing-recovered-task-record")?
                        .workflow()
                        .clone(),
                )
            };
            let (inherited_agent, session) = if *task_id == root_task_id {
                (
                    admission.foreground().active_agent().map(Arc::from),
                    TaskSessionContextV1::Root {
                        root_session_id: root_session.id,
                        provenance: root_provenance,
                    },
                )
            } else {
                let task = snapshot
                    .state()
                    .task(*task_id)
                    .ok_or("missing-recovered-task-record")?;
                let base_session = snapshot
                    .sessions()
                    .iter()
                    .find(|session| session.id == task.base_session_id())
                    .ok_or("missing-recovered-task-session")?;
                (
                    task.inherited_agent().map(Arc::from),
                    TaskSessionContextV1::Forked {
                        base_session_id: task.base_session_id(),
                        parent_session_id: task.parent_session_id(),
                        root_session_id: base_session.root,
                        root_provenance,
                    },
                )
            };
            let create_request = TaskContextV1 {
                execution_id: snapshot.state().execution_id(),
                task_id: *task_id,
                inherited_agent,
                session,
            }
            .into_host_request()
            .map_err(|_| "invalid-recovered-hook-context")?;
            let model_session_occurrence = snapshot
                .sessions()
                .iter()
                .filter(|session| session.creator_task == Some(*task_id))
                .filter_map(|session| session.creation_occurrence)
                .try_fold(0_u64, |next, occurrence| {
                    occurrence
                        .checked_add(1)
                        .map(|candidate| next.max(candidate))
                })
                .ok_or("recovered-session-occurrence-exhausted")?;
            let submission = if *task_id == root_task_id {
                None
            } else {
                let task = snapshot
                    .state()
                    .task(*task_id)
                    .ok_or("missing-recovered-task-record")?;
                match task.status() {
                    ConcurrentTaskStatusV1::Running => {
                        if !admission.children().contains_key(task_id) {
                            return Err("missing-recovered-task-machine");
                        }
                        None
                    }
                    ConcurrentTaskStatusV1::Submitting => {
                        if admission.children().contains_key(task_id) {
                            return Err("unexpected-recovered-task-machine");
                        }
                        let parent = if task.parent_task_id() == root_task_id {
                            admission.foreground()
                        } else {
                            admission
                                .children()
                                .get(&task.parent_task_id())
                                .ok_or("missing-recovered-parent-machine")?
                        };
                        let suspension = parent
                            .pending_spawn()
                            .cloned()
                            .ok_or("missing-recovered-parent-spawn")?;
                        let machine = Machine::new_concurrent_task_body_with_context(
                            Arc::clone(&program),
                            &suspension.body,
                            &suspension
                                .captures
                                .iter()
                                .map(|capture| capture.task_capture().clone())
                                .collect::<Vec<_>>(),
                            snapshot.state().execution_id(),
                            *task_id,
                            Arc::from(task.task_path()),
                            machine_limits,
                            admission.foreground().execution_budget(),
                            task.inherited_agent().map(Arc::from),
                            Some(task.base_session_id()),
                        )
                        .map_err(|_| "invalid-recovered-task-machine")?;
                        Some(RecoveredDurableTaskSubmission {
                            parent_task_id: task.parent_task_id(),
                            created: gantry_runtime::TaskCreationV1 {
                                task_id: *task_id,
                                handle_id: task.handle_id(),
                                base_session_id: task.base_session_id(),
                                transition: gantry_runtime::TaskCreatedV1 {
                                    task_id: *task_id,
                                    parent_task_id: task.parent_task_id(),
                                    workflow: task.workflow().clone(),
                                    spawn_site: task.spawn_site().clone(),
                                    spawn_occurrence: task.spawn_occurrence(),
                                    result_type: task.result_type().clone(),
                                    attachment: gantry_core::portable::TaskHandleState::Attached,
                                },
                            },
                            suspension,
                            machine,
                        })
                    }
                    ConcurrentTaskStatusV1::Succeeded(_)
                    | ConcurrentTaskStatusV1::Failed(_)
                    | ConcurrentTaskStatusV1::Cancelled(_) => {
                        return Err("settled-recovered-driver");
                    }
                }
            };
            Ok(RecoveredDurableTaskDriver {
                task_id: *task_id,
                workflow,
                create_request,
                model_session_occurrence,
                submission,
            })
        })
        .collect()
}

#[cfg(feature = "durable")]
fn recovered_task_event_sequences(
    events: &RecoveredDurableEventsV1,
) -> Result<BTreeMap<ProtocolIdentity, u64>, &'static str> {
    let mut sequences: BTreeMap<ProtocolIdentity, u64> = BTreeMap::new();
    for event in events.events().values() {
        let envelope = event.occurrence().event();
        let (Some(task_id), Some(sequence)) = (envelope.task_id(), envelope.per_task_sequence())
        else {
            continue;
        };
        let next = sequence
            .checked_add(1)
            .ok_or("recovered-event-sequence-exhausted")?;
        sequences
            .entry(task_id)
            .and_modify(|current| *current = (*current).max(next))
            .or_insert(next);
    }
    Ok(sequences)
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
fn recovered_events_have_pending_delivery(events: &RecoveredDurableEventsV1) -> bool {
    events.events().values().any(|event| {
        event.deliveries().values().any(|delivery| {
            !matches!(
                delivery,
                DurableDeliveryRecoveryV1::Success { .. }
                    | DurableDeliveryRecoveryV1::Terminal { .. }
            )
        })
    })
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
fn reserve_recovered_concurrent_identities(
    allocator: &FreshIdentityAllocator,
    recovered: &gantry_runtime::RecoveredConcurrentDurableStateV1,
    resume_activity_id: ProtocolIdentity,
) -> Result<bool, &'static str> {
    let mut identities = BTreeSet::new();
    identities.insert(recovered.execution().foreground().execution_id());
    identities.insert(recovered.execution().foreground().task_id());
    identities.extend(
        recovered
            .execution()
            .sessions()
            .sessions()
            .map(|session| session.id),
    );
    for recovery in recovered.operation_recoveries().values() {
        let dispatch_id = OperationLifecycle::retained_dispatch_id(recovery)
            .map_err(|_| "invalid-recovered-operation-state")?;
        identities.extend(dispatch_id);
    }
    let mut activity_collision = false;
    for event in recovered.events().events().values() {
        let envelope = event.occurrence().event();
        activity_collision |= envelope.activity_id() == resume_activity_id;
        identities.insert(envelope.event_id());
        identities.insert(envelope.activity_id());
        identities.extend(envelope.task_id());
        identities.extend(envelope.operation_id());
        identities.extend(envelope.causal_ids().iter().copied());
        for delivery in event.deliveries().values() {
            let attempt_id = match delivery {
                DurableDeliveryRecoveryV1::Indeterminate {
                    previous_attempt_id,
                    ..
                } => Some(*previous_attempt_id),
                DurableDeliveryRecoveryV1::Success { attempt_id }
                | DurableDeliveryRecoveryV1::Terminal { attempt_id } => Some(*attempt_id),
                DurableDeliveryRecoveryV1::Pending { .. }
                | DurableDeliveryRecoveryV1::RetryDelay { .. } => None,
            };
            identities.extend(attempt_id);
        }
    }
    for identity in identities {
        allocator
            .reserve(identity)
            .map_err(|_| "recovered-identity-registry-failure")?;
    }
    Ok(activity_collision)
}

#[cfg(feature = "durable")]
fn resume_failure(
    journal_id: gantry_host::journal::JournalId,
    category: ResumeStartFailureCategory,
    code: &'static str,
) -> DurableResumeExecutionResult {
    DurableResumeExecutionResult::Rejected(DurableResumeExecutionFailure {
        journal_id,
        category,
        code: Arc::from(code),
        candidate_package_activity: None,
        release_error: None,
    })
}

#[cfg(feature = "durable")]
fn decode_retained_schemas(
    bytes: &[u8],
    maximum_constructed_type_depth: u64,
) -> Result<BTreeMap<TypeDescriptor, Arc<[u8]>>, &'static str> {
    let length = u64::try_from(bytes.len()).map_err(|_| "invalid-retained-schemas")?;
    let document = StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes: length,
            maximum_nesting_depth: length.max(1),
            maximum_nodes: length.max(1),
            maximum_string_scalars: length.max(1),
            maximum_list_items: length.max(1),
        },
    )
    .map_err(|_| "invalid-retained-schemas")?;
    let canonical =
        CanonicalJson::from_document(&document).map_err(|_| "invalid-retained-schemas")?;
    if canonical.bytes() != bytes {
        return Err("invalid-retained-schemas");
    }
    let JsonNode::Object(entries) = document
        .node(document.root())
        .ok_or("invalid-retained-schemas")?
    else {
        return Err("invalid-retained-schemas");
    };
    entries
        .iter()
        .map(|(descriptor, schema)| {
            let descriptor = TypeDescriptor::from_canonical_string_with_depth_limit(
                descriptor,
                maximum_constructed_type_depth,
            )
            .map_err(|_| "invalid-retained-schemas")?;
            let schema = CanonicalJson::from_node(&document, *schema)
                .map_err(|_| "invalid-retained-schemas")?;
            Ok((descriptor, Arc::from(schema.bytes())))
        })
        .collect()
}

/// Failure while driving an already accepted nondurable execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunExecutionError {
    /// The accepted root is already owned by the interpreter's executor submission.
    ExecutionAlreadyOwned,
    /// Accepted package state unexpectedly omitted analysis.
    MissingAnalysis,
    /// Accepted package state unexpectedly omitted its entry inventory.
    MissingEntry,
    /// Accepted package state unexpectedly omitted executable typed IR.
    MissingExecutableProgram,
    /// Entry input could not be reconstructed as the normalized logical value.
    InvalidEntryValue,
    /// Analyzer-owned operation metadata was absent or internally inconsistent.
    MissingOperationMetadata,
    /// The analyzed package omitted the generated schema for an operation result.
    MissingOperationSchema,
    /// An action occurrence had no preflight-resolved action mapping revision.
    MissingActionMappingRevision,
    /// A model occurrence had no preflight-resolved agent mapping revision.
    MissingAgentMappingRevision,
    /// A model occurrence had no active agent selection.
    MissingActiveAgent,
    /// A model occurrence referenced no known logical session.
    MissingLogicalSession,
    /// Logical-session construction contradicted the runtime contract.
    Session(gantry_runtime::SessionError),
    /// Shared root or child task state rejected a driver transition.
    TaskState(TaskStateError),
    /// A versioned hook request could not be constructed.
    HookRequest(gantry_runtime::HookRequestError),
    /// The task-local hook owner rejected construction.
    TaskHook(TaskHookError),
    /// The shared operation lifecycle rejected a transition.
    OperationLifecycle(OperationLifecycleError),
    /// Effective retry policy contradicted analyzed action recovery metadata.
    RetryPolicy,
    /// The shared machine rejected the analyzed entry.
    MachineBuild(MachineBuildError),
    /// The configured executor failed one cooperative yield.
    ExecutorFailure,
    /// Nondurable execution-event completion or delivery failed.
    Event(ExecutionEventError),
    /// A lifecycle transition contradicted accepted execution state.
    LifecycleTransition,
    /// A lifecycle public operation failed.
    Lifecycle(LifecycleError),
    /// Accepted execution state disappeared before observation.
    ExecutionNotFound,
}

/// Failure while coordinating one public execution-cancellation operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancelExecutionError {
    /// Isolated control-plane capacity was unavailable before ownership transfer.
    Admission(AdmissionExhaustion),
    /// The public operation was rejected by the interpreter lifecycle.
    Lifecycle(LifecycleError),
    /// Coordinator task state rejected cancellation publication.
    TaskState(TaskStateError),
    /// A committed semantic transition could not be reflected in lifecycle state.
    Transition(gantry_runtime::ExecutionTransitionError),
    /// The executor rejected control ownership or reported an immutable abort failure.
    Executor(HostError),
    /// Bounded cancellation cleanup ended before physical settlement.
    CleanupTimedOut,
    /// The supervised cancellation owner stopped abnormally.
    Physical(OwnedTaskCompletion),
    /// Retained cancellation state was internally incomplete.
    Invariant,
    /// Durable cancellation failed without fabricating terminal state.
    #[cfg(feature = "durable")]
    Durable(DurableRunFailure),
}

/// Failure while coordinating interpreter shutdown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShutdownError {
    /// The isolated control-plane capacity was unavailable.
    Admission(AdmissionExhaustion),
    /// Shutdown admission failed at the lifecycle boundary.
    Lifecycle(LifecycleError),
    /// The unique coordinator could not publish the report.
    Completion(ShutdownCompletionError),
    /// The executor rejected the owned shutdown coordinator.
    Executor(gantry_host::contracts::HostError),
    /// The shutdown task stopped, panicked, or failed before normal completion.
    Physical(OwnedTaskCompletion),
}

#[derive(Default)]
struct SharedShutdown {
    state: Mutex<SharedShutdownState>,
}

struct SharedShutdownState {
    launch: SharedShutdownLaunch,
    staged: Option<Result<Arc<ShutdownReport>, ShutdownError>>,
    published: Option<Result<Arc<ShutdownReport>, ShutdownError>>,
    waiters: Vec<Waker>,
}

enum SharedShutdownLaunch {
    New,
    Launching,
    Deferred(ShutdownAdmission),
    Submitted,
}

impl Default for SharedShutdownState {
    fn default() -> Self {
        Self {
            launch: SharedShutdownLaunch::New,
            staged: None,
            published: None,
            waiters: Vec::new(),
        }
    }
}

impl SharedShutdown {
    fn claim_launch(&self) -> Option<Option<ShutdownAdmission>> {
        let mut state = lock_shutdown(&self.state);
        match std::mem::replace(&mut state.launch, SharedShutdownLaunch::Launching) {
            SharedShutdownLaunch::New => Some(None),
            SharedShutdownLaunch::Deferred(admission) => Some(Some(admission)),
            launch @ (SharedShutdownLaunch::Launching | SharedShutdownLaunch::Submitted) => {
                state.launch = launch;
                None
            }
        }
    }

    fn defer_launch(&self, admission: ShutdownAdmission) {
        lock_shutdown(&self.state).launch = SharedShutdownLaunch::Deferred(admission);
    }

    fn mark_submitted(&self) {
        lock_shutdown(&self.state).launch = SharedShutdownLaunch::Submitted;
    }

    fn stage(&self, result: Result<Arc<ShutdownReport>, ShutdownError>) {
        let mut state = lock_shutdown(&self.state);
        if state.staged.is_none() && state.published.is_none() {
            state.staged = Some(result);
        }
    }

    fn publish_physical(&self, completion: OwnedTaskCompletion) {
        let result = {
            let mut state = lock_shutdown(&self.state);
            if state.published.is_some() {
                return;
            }
            match completion {
                OwnedTaskCompletion::Completed(_) => state.staged.take().unwrap_or_else(|| {
                    Err(ShutdownError::Executor(gantry_host::contracts::HostError {
                        code: Arc::from("executor-failure"),
                        protected_diagnostic: None,
                    }))
                }),
                other => Err(ShutdownError::Physical(other)),
            }
        };
        self.publish(result);
    }

    fn publish(&self, result: Result<Arc<ShutdownReport>, ShutdownError>) {
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            if state.published.is_some() {
                return;
            }
            state.published = Some(result);
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn poll(&self, context: &mut Context<'_>) -> Poll<Result<Arc<ShutdownReport>, ShutdownError>> {
        let mut state = lock_shutdown(&self.state);
        if let Some(result) = &state.published {
            return Poll::Ready(result.clone());
        }
        if !state
            .waiters
            .iter()
            .any(|waiter| waiter.will_wake(context.waker()))
        {
            state.waiters.push(context.waker().clone());
        }
        Poll::Pending
    }
}

fn lock_shutdown<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct ShutdownCancellation {
    committed: CancellationSignal,
    completion: HostFuture<'static, bool>,
    outcome: Option<bool>,
    commit_observation_required: bool,
}

async fn wait_for_shutdown_cancellation_commits(cancellations: &mut [ShutdownCancellation]) {
    std::future::poll_fn(|context| {
        let mut commits_complete = true;
        for cancellation in cancellations.iter_mut() {
            if cancellation.outcome.is_none()
                && let Poll::Ready(result) = cancellation.completion.as_mut().poll(context)
            {
                cancellation.outcome = Some(result);
            }
            if cancellation.commit_observation_required && !cancellation.committed.is_cancelled() {
                commits_complete = false;
            }
        }
        if commits_complete {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await
}

async fn wait_for_shutdown_cancellations(
    cancellations: &mut [ShutdownCancellation],
    progress: gantry_runtime::ShutdownProgress,
) -> bool {
    let mut progress = Box::pin(progress);
    std::future::poll_fn(move |context| {
        let mut cancellations_complete = true;
        let mut orderly = true;
        for cancellation in cancellations.iter_mut() {
            if cancellation.outcome.is_none() {
                match cancellation.completion.as_mut().poll(context) {
                    Poll::Ready(result) => cancellation.outcome = Some(result),
                    Poll::Pending => cancellations_complete = false,
                }
            }
            if let Some(result) = cancellation.outcome {
                orderly &= result;
            }
        }
        let quiescent = progress.as_mut().poll(context).is_ready();
        if cancellations_complete && quiescent {
            Poll::Ready(orderly)
        } else {
            Poll::Pending
        }
    })
    .await
}

async fn wait_for_retained_shutdown_cancellations(cancellations: &mut [ShutdownCancellation]) {
    std::future::poll_fn(move |context| {
        let mut complete = true;
        for cancellation in cancellations.iter_mut() {
            if cancellation.outcome.is_none() {
                match cancellation.completion.as_mut().poll(context) {
                    Poll::Ready(result) => cancellation.outcome = Some(result),
                    Poll::Pending => complete = false,
                }
            }
        }
        if complete {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await
}

async fn wait_for_nondurable_abort_and_completion(
    tasks: &[SupervisedTask],
) -> Result<(), HostError> {
    wait_for_abort_and_completion(tasks).await
}

fn request_abort_for_active_controls(tasks: &[SupervisedTask]) {
    for task in tasks {
        if task.snapshot().completion.is_none() {
            let _ = task.request_abort();
        }
    }
}

async fn wait_for_abort_and_completion(tasks: &[SupervisedTask]) -> Result<(), HostError> {
    std::future::poll_fn(|context| {
        let mut complete = true;
        let mut abort_failure = None;
        for task in tasks {
            let snapshot = task.snapshot();
            match snapshot.abort_result {
                Some(OwnedTaskAbort::Failed(error)) => {
                    abort_failure.get_or_insert(error);
                }
                Some(OwnedTaskAbort::Stopped | OwnedTaskAbort::AlreadySettled) => {}
                None if snapshot.abort_requested => complete = false,
                None => {}
            }
            let mut completion = Box::pin(task.completion());
            if completion.as_mut().poll(context).is_pending() {
                complete = false;
            }
        }
        if let Some(error) = abort_failure {
            Poll::Ready(Err(error))
        } else if complete {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await
}

async fn shutdown_grace_race(
    executor: &dyn ExecutorAdapter,
    progress: gantry_runtime::ShutdownProgress,
    nondurable: &NondurableExecutionRegistry,
    execution_ids: &[ProtocolIdentity],
    timeout: DurationMicros,
) -> DeadlineOutcome<()> {
    let mut progress = Box::pin(progress);
    let mut timer = executor.sleep(timeout);
    std::future::poll_fn(|context| {
        if nondurable
            .poll_cancellation_requested(execution_ids, context)
            .is_ready()
        {
            return Poll::Ready(DeadlineOutcome::Cancelled);
        }
        if progress.as_mut().poll(context).is_ready() {
            return Poll::Ready(DeadlineOutcome::Completed(()));
        }
        match timer.as_mut().poll(context) {
            Poll::Ready(Ok(())) => Poll::Ready(DeadlineOutcome::TimedOut),
            Poll::Ready(Err(error)) => Poll::Ready(DeadlineOutcome::Failed(error)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

async fn observe_shutdown_deadline<T: Send>(
    executor: &dyn ExecutorAdapter,
    mut completion: Pin<&mut (dyn Future<Output = T> + Send + '_)>,
    timeout: DurationMicros,
) -> DeadlineOutcome<T> {
    let mut timer = None;
    std::future::poll_fn(move |context| {
        if let Poll::Ready(value) = completion.as_mut().poll(context) {
            return Poll::Ready(DeadlineOutcome::Completed(value));
        }
        let timer = timer.get_or_insert_with(|| executor.sleep(timeout));
        match timer.as_mut().poll(context) {
            Poll::Ready(Ok(())) => Poll::Ready(DeadlineOutcome::TimedOut),
            Poll::Ready(Err(error)) => Poll::Ready(DeadlineOutcome::Failed(error)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

fn owned_event_delivery_factory(
    inner: Arc<InterpreterInner>,
) -> crate::start::OwnedEventDeliveryFactory {
    Arc::new(move |events, plan| {
        let inner = Arc::clone(&inner);
        Box::pin(async move {
            let package = AnalyzePackageCoordinator::new(
                &inner.allocator,
                inner.configuration.identity_source(),
                inner.clock.as_ref(),
                inner.configuration.blocking_work(),
            )
            .with_blocking_work_poison(inner.blocking_work_poison.clone())
            .with_delivery_runtime(inner.event_delivery_runtime.as_ref());
            package.deliver_completed_events(&events, Some(&plan)).await
        })
    })
}

async fn settle_final_shutdown_event(
    inner: &InterpreterInner,
    durations: gantry_runtime::ShutdownDurations,
    executions_at_start: &[ProtocolIdentity],
    cohort: &[ProtocolIdentity],
    tasks_at_start: u64,
    aborted: u64,
) -> FinalShutdownEventOutcome {
    let activity_id = match inner.allocator.allocate(
        inner.configuration.identity_source(),
        IdentityKind::Activity,
    ) {
        Ok(activity_id) => activity_id,
        Err(_) => {
            return FinalShutdownEventOutcome::failed(
                FinalShutdownEventFailure::IdentityGeneration,
            );
        }
    };
    let snapshots = cohort
        .iter()
        .filter_map(|execution_id| {
            inner
                .lifecycle
                .query_execution(*execution_id)
                .ok()
                .flatten()
        })
        .collect::<Vec<_>>();
    let cancelled = usize_to_u64(
        snapshots
            .iter()
            .filter(|snapshot| snapshot.cancellation.is_some())
            .count(),
    );
    let completed_naturally = usize_to_u64(
        snapshots
            .iter()
            .filter(|snapshot| snapshot.cancellation.is_none() && snapshot.terminal.is_some())
            .count(),
    );
    let draft = match shutdown_event(&ShutdownEventSummaryV1 {
        activity_id,
        graceful_us: durations.graceful.get(),
        drain_us: durations.drain.get(),
        executions_at_start: usize_to_u64(executions_at_start.len()),
        tasks_at_start,
        admitted_after_start: usize_to_u64(cohort.len().saturating_sub(executions_at_start.len())),
        completed_naturally,
        cancelled,
        aborted,
        required_state_commit_status: Arc::from("not-applicable"),
        shutdown_report_reference: Arc::from(format!("shutdown-report:{activity_id}")),
    }) {
        Ok(draft) => draft,
        Err(_) => {
            return FinalShutdownEventOutcome::failed(FinalShutdownEventFailure::Internal);
        }
    };
    let event = match EventCompleter::new(
        &inner.allocator,
        inner.configuration.identity_source(),
        inner.clock.as_ref(),
    )
    .complete(activity_id, draft.draft)
    .await
    {
        Ok(event) => event,
        Err(EventCompletionError::Identity(_)) => {
            return FinalShutdownEventOutcome::failed(
                FinalShutdownEventFailure::IdentityGeneration,
            );
        }
        Err(EventCompletionError::Clock(_)) => {
            return FinalShutdownEventOutcome::failed(FinalShutdownEventFailure::Executor);
        }
        Err(EventCompletionError::InvalidActivityIdentity | EventCompletionError::Contract(_)) => {
            return FinalShutdownEventOutcome::failed(FinalShutdownEventFailure::Internal);
        }
    };
    let delivery = DeliveryKernel::new(
        &inner.allocator,
        inner.configuration.identity_source(),
        inner.event_delivery_runtime.as_ref(),
    )
    .deliver(event, &draft.protected_payloads, &inner.event_delivery)
    .await;
    let delivery = match delivery {
        Ok(delivery) => delivery,
        Err(DeliveryError::Identity(_)) => {
            return FinalShutdownEventOutcome::failed(
                FinalShutdownEventFailure::IdentityGeneration,
            );
        }
        Err(DeliveryError::Runtime(_) | DeliveryError::Retry(_)) => {
            return FinalShutdownEventOutcome::failed(FinalShutdownEventFailure::Executor);
        }
        Err(
            DeliveryError::Projection(_)
            | DeliveryError::RetryOverflow
            | DeliveryError::MissingAttempt,
        ) => {
            return FinalShutdownEventOutcome::failed(FinalShutdownEventFailure::Internal);
        }
    };
    let all_settled = delivery
        .settlements
        .iter()
        .all(|settlement| settlement.status == SinkSettlementStatus::Success);
    let required_sinks_settled = delivery.settlements.iter().all(|settlement| {
        settlement.class != gantry_core::portable::SinkClass::Required
            || settlement.status == SinkSettlementStatus::Success
    });
    FinalShutdownEventOutcome {
        settlement: if all_settled {
            FinalShutdownEventSettlement::Settled
        } else {
            FinalShutdownEventSettlement::Exhausted
        },
        required_sinks_settled,
    }
}

struct FinalShutdownEventOutcome {
    settlement: FinalShutdownEventSettlement,
    required_sinks_settled: bool,
}

impl FinalShutdownEventOutcome {
    const fn failed(failure: FinalShutdownEventFailure) -> Self {
        Self {
            settlement: FinalShutdownEventSettlement::Failed(failure),
            required_sinks_settled: false,
        }
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn preparation_error_code(error: &RunExecutionError) -> &'static str {
    match error {
        RunExecutionError::MissingAnalysis => "missing-analysis",
        RunExecutionError::MissingEntry => "missing-entry",
        RunExecutionError::MissingExecutableProgram => "missing-executable-program",
        RunExecutionError::InvalidEntryValue => "invalid-entry-value",
        RunExecutionError::MachineBuild(MachineBuildError::UnsupportedEffect(_)) => {
            "unsupported-profile-effect"
        }
        RunExecutionError::MachineBuild(_) => "root-machine-construction",
        RunExecutionError::Session(_) => "root-session-state",
        RunExecutionError::TaskState(_) => "root-task-state",
        RunExecutionError::HookRequest(_) => "root-hook-request",
        _ => "root-preparation-invariant",
    }
}

fn prepared_start_failure(
    prepared: PreparedExecutionStart,
    category: StartFailureCategory,
    code: impl Into<Arc<str>>,
) -> StartExecutionFailure {
    StartExecutionFailure {
        category,
        code: code.into(),
        package_activity: Some(Box::new(prepared.package_activity)),
    }
}

fn root_start_failure(workflow: &gantry_ir::CanonicalPath, code: RuntimeCode) -> MachineOutcome {
    MachineOutcome::Failed(MachineFailure {
        code,
        workflow: workflow.clone(),
        site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
            .unwrap_or_else(|_| unreachable!("constant position is valid")),
        #[cfg(feature = "concurrent")]
        join_failure: None,
    })
}

fn settle_root_start_failure(
    lifecycle: &InterpreterLifecycle,
    accepted: &StartExecutionAccepted,
    coordinator: &ExecutionCoordinator,
    outcome: MachineOutcome,
    physically_settled: bool,
) -> Result<(), RunExecutionError> {
    if physically_settled {
        coordinator
            .fail_root_submission(outcome.clone())
            .map_err(RunExecutionError::TaskState)?;
    } else {
        coordinator
            .fail_root_registration(outcome.clone())
            .map_err(RunExecutionError::TaskState)?;
    }
    let foreground = coordinator
        .complete_foreground()
        .map_err(RunExecutionError::TaskState)?;
    if foreground != outcome {
        return Err(RunExecutionError::LifecycleTransition);
    }
    let terminal = coordinator
        .complete_terminal()
        .map_err(RunExecutionError::TaskState)?;
    lifecycle
        .complete_foreground(&accepted.handle, outcome.clone())
        .map_err(|_| RunExecutionError::LifecycleTransition)?;
    lifecycle
        .complete_terminal(&accepted.handle, terminal)
        .map_err(|_| RunExecutionError::LifecycleTransition)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RenderPromptError {
    Shape,
    Limit,
}

fn render_prompt<'a>(
    segments: &[Arc<str>],
    inputs: impl Iterator<Item = &'a LogicalValue>,
    maximum_string_scalars: u64,
) -> Result<Arc<str>, RenderPromptError> {
    let inputs = inputs.collect::<Vec<_>>();
    if segments.len() != inputs.len().saturating_add(1) {
        return Err(RenderPromptError::Shape);
    }
    let mut rendered = String::new();
    for (index, input) in inputs.iter().enumerate() {
        rendered.push_str(&segments[index]);
        if let Some(value) = input.as_string() {
            rendered.push_str(value);
        } else {
            rendered.push_str(
                std::str::from_utf8(input.canonical_json().bytes())
                    .map_err(|_| RenderPromptError::Shape)?,
            );
        }
    }
    rendered.push_str(segments.last().ok_or(RenderPromptError::Shape)?);
    let scalars = u64::try_from(rendered.chars().count()).unwrap_or(u64::MAX);
    if scalars > maximum_string_scalars {
        return Err(RenderPromptError::Limit);
    }
    Ok(Arc::from(rendered))
}

fn transcript_result_kind(ty: &TypeDescriptor) -> TranscriptResultKindV1 {
    match ty.kind() {
        TypeKind::Unit => TranscriptResultKindV1::Unit,
        TypeKind::Decision => TranscriptResultKindV1::Decision,
        _ => TranscriptResultKindV1::Value,
    }
}

pub(crate) fn decode_logical_value(
    bytes: &[u8],
    ty: &TypeDescriptor,
    limits: ValueLimits,
    shapes: Option<&DeclaredValueShapes>,
) -> Result<LogicalValue, RunExecutionError> {
    let length = u64::try_from(bytes.len()).map_err(|_| RunExecutionError::InvalidEntryValue)?;
    let document = StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes: length,
            maximum_nesting_depth: limits.maximum_nesting_depth(),
            maximum_nodes: limits.maximum_nodes(),
            maximum_string_scalars: limits.maximum_string_scalars(),
            maximum_list_items: limits.maximum_list_items(),
        },
    )
    .map_err(|_| RunExecutionError::InvalidEntryValue)?;
    decode_node(&document, document.root(), ty, limits, shapes)
}

fn decode_node(
    document: &StrictJsonDocument,
    id: JsonNodeId,
    ty: &TypeDescriptor,
    limits: ValueLimits,
    shapes: Option<&DeclaredValueShapes>,
) -> Result<LogicalValue, RunExecutionError> {
    let node = document
        .node(id)
        .ok_or(RunExecutionError::InvalidEntryValue)?;
    match (ty.kind(), node) {
        (TypeKind::Unit, JsonNode::Null) => Ok(LogicalValue::unit()),
        (TypeKind::Bool, JsonNode::Bool(value)) => Ok(LogicalValue::boolean(*value)),
        (TypeKind::Int, JsonNode::Number(value)) => value
            .to_gantry_int()
            .ok()
            .and_then(GantryInt::new)
            .map(LogicalValue::integer)
            .ok_or(RunExecutionError::InvalidEntryValue),
        (TypeKind::Float, JsonNode::Number(value)) => value
            .to_gantry_float()
            .ok()
            .and_then(GantryFloat::new)
            .map(LogicalValue::float)
            .ok_or(RunExecutionError::InvalidEntryValue),
        (TypeKind::String, JsonNode::String(value)) => {
            LogicalValue::string(value.to_string(), limits)
                .map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        (TypeKind::Declared, JsonNode::Object(members)) => {
            decode_declared_value(document, members, ty, limits, shapes)
        }
        (TypeKind::Decision, JsonNode::Object(members)) => {
            if members.len() != 2 {
                return Err(RunExecutionError::InvalidEntryValue);
            }
            let decision = object_member(document, members, "decision")
                .and_then(|id| document.node(id))
                .and_then(|node| match node {
                    JsonNode::Bool(value) => Some(*value),
                    _ => None,
                })
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            let rationale = object_member(document, members, "rationale")
                .and_then(|id| document.node(id))
                .and_then(|node| match node {
                    JsonNode::String(value) => Some(value.to_string()),
                    _ => None,
                })
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            LogicalValue::decision(decision, rationale, limits)
                .map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        (TypeKind::Option, JsonNode::Null) => Ok(LogicalValue::none()),
        (TypeKind::Option, _) => {
            let member = ty
                .immediate_members()
                .into_iter()
                .next()
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            LogicalValue::some(decode_node(document, id, &member, limits, shapes)?, limits)
                .map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        (TypeKind::Result, JsonNode::Object(members)) => {
            if members.len() != 2 {
                return Err(RunExecutionError::InvalidEntryValue);
            }
            let variant = object_string(document, members, "variant")?;
            let value = object_member(document, members, "value")
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            let result_members = ty.immediate_members();
            match variant {
                "Ok" => LogicalValue::ok(
                    decode_node(
                        document,
                        value,
                        result_members
                            .first()
                            .ok_or(RunExecutionError::InvalidEntryValue)?,
                        limits,
                        shapes,
                    )?,
                    limits,
                ),
                "Err" => LogicalValue::err(
                    decode_node(
                        document,
                        value,
                        result_members
                            .get(1)
                            .ok_or(RunExecutionError::InvalidEntryValue)?,
                        limits,
                        shapes,
                    )?,
                    limits,
                ),
                _ => return Err(RunExecutionError::InvalidEntryValue),
            }
            .map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        (TypeKind::List, JsonNode::Array(items)) => {
            let member = ty
                .immediate_members()
                .into_iter()
                .next()
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            let values = items
                .iter()
                .map(|item| decode_node(document, *item, &member, limits, shapes))
                .collect::<Result<Vec<_>, _>>()?;
            LogicalValue::list(values, limits).map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        (TypeKind::Tuple, JsonNode::Array(items)) => {
            let members = ty.immediate_members();
            if members.len() != items.len() {
                return Err(RunExecutionError::InvalidEntryValue);
            }
            let values = items
                .iter()
                .zip(&members)
                .map(|(item, member)| decode_node(document, *item, member, limits, shapes))
                .collect::<Result<Vec<_>, _>>()?;
            LogicalValue::tuple(values, limits).map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        (TypeKind::OperationError, JsonNode::Object(members)) => {
            decode_operation_error(document, members, limits)
        }
        _ => Err(RunExecutionError::InvalidEntryValue),
    }
}

fn decode_declared_value(
    document: &StrictJsonDocument,
    members: &[(Arc<str>, JsonNodeId)],
    ty: &TypeDescriptor,
    limits: ValueLimits,
    shapes: Option<&DeclaredValueShapes>,
) -> Result<LogicalValue, RunExecutionError> {
    let shape = shapes
        .and_then(|shapes| shapes.get(ty))
        .ok_or(RunExecutionError::InvalidEntryValue)?;
    match shape {
        DeclaredValueShape::Struct(fields) => {
            if members
                .iter()
                .any(|(name, _)| !fields.iter().any(|field| field.name == *name))
            {
                return Err(RunExecutionError::InvalidEntryValue);
            }
            let values = fields
                .iter()
                .map(|field| {
                    let value = if let Some(id) = object_member(document, members, &field.name) {
                        decode_node(document, id, &field.ty, limits, shapes)
                    } else if field.ty.kind() == TypeKind::Option {
                        field.default_json.as_ref().map_or_else(
                            || Ok(LogicalValue::none()),
                            |default| decode_logical_value(default, &field.ty, limits, shapes),
                        )
                    } else {
                        Err(RunExecutionError::InvalidEntryValue)
                    }?;
                    Ok((field.name.to_string(), value))
                })
                .collect::<Result<Vec<_>, RunExecutionError>>()?;
            LogicalValue::structure(ty.canonical_string(), values, limits)
                .map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        DeclaredValueShape::Enum(variants) => {
            let variant_name = object_string(document, members, "variant")?;
            let variant = variants
                .iter()
                .find(|variant| variant.name.as_ref() == variant_name)
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            let payload = match &variant.payload {
                Some(payload_ty) if members.len() == 2 => {
                    let id = object_member(document, members, "value")
                        .ok_or(RunExecutionError::InvalidEntryValue)?;
                    Some(decode_node(document, id, payload_ty, limits, shapes)?)
                }
                None if members.len() == 1 => None,
                _ => return Err(RunExecutionError::InvalidEntryValue),
            };
            LogicalValue::enumeration(
                ty.canonical_string(),
                variant.name.to_string(),
                payload,
                limits,
            )
            .map_err(|_| RunExecutionError::InvalidEntryValue)
        }
    }
}

fn decode_operation_error(
    document: &StrictJsonDocument,
    members: &[(Arc<str>, JsonNodeId)],
    limits: ValueLimits,
) -> Result<LogicalValue, RunExecutionError> {
    let variant = object_string(document, members, "variant")?;
    let string_payload = || {
        if members.len() != 2 {
            return Err(RunExecutionError::InvalidEntryValue);
        }
        let id = object_member(document, members, "value")
            .ok_or(RunExecutionError::InvalidEntryValue)?;
        match document.node(id) {
            Some(JsonNode::String(value)) => Ok(value.to_string()),
            _ => Err(RunExecutionError::InvalidEntryValue),
        }
    };
    let error = match variant {
        "Declined" => OperationErrorValue::Declined(string_payload()?),
        "InvalidOutput" if members.len() == 1 => OperationErrorValue::InvalidOutput,
        "ProviderFailure" => OperationErrorValue::ProviderFailure(string_payload()?),
        "Timeout" => OperationErrorValue::Timeout(string_payload()?),
        "PolicyDenied" => OperationErrorValue::PolicyDenied(string_payload()?),
        "Cancelled" => OperationErrorValue::Cancelled(string_payload()?),
        "UnknownOutcome" if members.len() == 2 => {
            let id = object_member(document, members, "value")
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            let Some(JsonNode::Array(values)) = document.node(id) else {
                return Err(RunExecutionError::InvalidEntryValue);
            };
            if values.len() != 2 {
                return Err(RunExecutionError::InvalidEntryValue);
            }
            let operation_id = json_string_node(document, values[0])?.to_owned();
            let message = json_string_node(document, values[1])?.to_owned();
            OperationErrorValue::UnknownOutcome {
                operation_id,
                message,
            }
        }
        _ => return Err(RunExecutionError::InvalidEntryValue),
    };
    LogicalValue::operation_error(error, limits).map_err(|_| RunExecutionError::InvalidEntryValue)
}

fn object_string<'a>(
    document: &'a StrictJsonDocument,
    members: &[(Arc<str>, JsonNodeId)],
    name: &str,
) -> Result<&'a str, RunExecutionError> {
    let id = object_member(document, members, name).ok_or(RunExecutionError::InvalidEntryValue)?;
    json_string_node(document, id)
}

fn json_string_node(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<&str, RunExecutionError> {
    match document.node(id) {
        Some(JsonNode::String(value)) => Ok(value),
        _ => Err(RunExecutionError::InvalidEntryValue),
    }
}

fn object_member(
    _document: &StrictJsonDocument,
    members: &[(Arc<str>, JsonNodeId)],
    name: &str,
) -> Option<JsonNodeId> {
    members
        .iter()
        .find(|(candidate, _)| candidate.as_ref() == name)
        .map(|(_, id)| *id)
}

/// Constructs the ordinary caller cancellation reason under one value limit.
pub fn caller_cancellation_reason(
    message: Option<Arc<str>>,
    maximum_string_scalars: u64,
) -> Result<CancellationReason, gantry_runtime::CancellationReasonError> {
    CancellationReason::new(
        CancellationReasonCategory::Caller,
        message,
        None,
        maximum_string_scalars,
    )
}

/// Derives the stable root-task identity for public hook composition.
pub fn root_task_identity(execution_id: ProtocolIdentity) -> ProtocolIdentity {
    gantry_runtime::root_task_identity(execution_id)
}

fn should_defer_execution_completion_event(
    label: &MachineLabel,
    execution_foreground: bool,
) -> bool {
    execution_foreground
        && matches!(
            label,
            MachineLabel::ForegroundCompletion(_) | MachineLabel::TerminalCompletion(_)
        )
}

#[cfg(all(test, feature = "evaluator", not(feature = "concurrent")))]
mod evaluator_only_tests {
    use super::should_defer_execution_completion_event;
    use gantry_core::value::LogicalValue;
    use gantry_runtime::{MachineLabel, MachineOutcome};

    #[test]
    fn terminal_event_is_deferred_to_the_single_evaluator_specific_arm() {
        let outcome = MachineOutcome::Succeeded(LogicalValue::unit());

        assert!(should_defer_execution_completion_event(
            &MachineLabel::TerminalCompletion(outcome.clone()),
            true,
        ));
        assert!(should_defer_execution_completion_event(
            &MachineLabel::ForegroundCompletion(outcome),
            true,
        ));
    }
}
